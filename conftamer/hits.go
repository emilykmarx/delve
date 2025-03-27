package conftamer

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/go-delve/delve/pkg/proc"
	"github.com/go-delve/delve/service/api"
	"github.com/go-delve/delve/service/rpc2"
	set "github.com/hashicorp/go-set"
)

/* Handlers for breakpoint/watchpoint hits.
 * Handlers can update state but should not start/stop the target. */

// Data structures used to create the configuration tamer

type Param struct {
	Module string
	File   string
	Param  string
}
type TaintingParam struct {
	Param Param
	Flow  TaintFlow
}

type BehaviorValue struct {
	Offset        uint64 // offset in message
	Send_endpoint string // IP:port
	Recv_endpoint string // IP:port
	Transport     string // transport protocol
	Send_module   string
	Recv_module   string
	// XXX protocol, request vs response
}

type TaintingBehavior struct {
	Behavior BehaviorValue
	Flow     TaintFlow
}

type TaintingVals struct {
	Params    set.Set[TaintingParam]
	Behaviors set.Set[TaintingBehavior]
}

type BehaviorMap map[BehaviorValue]TaintingVals

// Info about a breakpoint or watchpoint hit
type Hit struct {
	thread    *api.Thread
	hit_bp    *api.Breakpoint
	hit_instr *api.AsmInstruction
	// Frame to check taint in (first non-runtime frame)
	frame int
	// Length of stack
	stack_len int
}

// A command needed before setting a watchpoint,
// and the criteria for when that command is done
type Command struct {
	cmd string
	// Length of stack when we've reached the destination
	stack_len int
	// Line number when recorded
	lineno int
}

// Exprs/args we will set a wp on, once they're in scope.
// If add any fields, update String()
type PendingWp struct {
	watchexprs set.Set[string]
	// Arg index => Expression to append to callee's copy, if any
	watchargs map[int]string
	// TaintingVals for the memory region that taints these watchexprs/args,
	// i.e. the region that overlapped the wp we just hit,
	// indexed by offset in region.
	// Copy from mem_param_map, so we have them even if the hit wp goes OOS
	// (e.g. hit for return of function local - will set wp after function returns)
	tainting_vals []TaintingVals
	threadID      int

	// If this is a bp within an if[else] body,
	// the start/end lines of the body
	body_start int
	body_end   int

	/* Used if need to execute commands to reach in-scope location (vs setting a breakpoint) */

	// The sequence of commands needed
	cmds []Command
}

type TaintCheck struct {
	config Config
	client *rpc2.RPCClient

	// Watchpoints waiting to be set when we hit a breakpoint
	// Key: Bp addr
	bp_pending_wps map[uint64]PendingWp

	// Watchpoint waiting to be set after a command sequence completes
	cmd_pending_wp *PendingWp

	// Note for both mem_param_map and behavior_map, each entry is for a single byte
	// (memory address or message offset).
	// Everything in mem_param_map overlaps some watchpoint, but each watchpoint is a contiguous region

	// Memory address => config/behavior values that taint it
	// Don't need PC to disambiguate - if memory is reused,
	// old entry will have gone OOS and been removed
	mem_param_map map[uint64]TaintingVals

	// Behavior value => config/behavior values that taint it
	behavior_map BehaviorMap

	event_log *csv.Writer
}

const (
	// Name of buf param in syscall.write
	SyscallRecvBuf = "p"
)

// Handle syscall entry bp hit - server returns it to us if tainted
func (tc *TaintCheck) handleSyscallEntry(hit *Hit) {
	raw_info := hit.hit_bp.UserData
	jsonString, _ := json.Marshal(raw_info)
	info := proc.SyscallBreakpointInfo{}
	json.Unmarshal(jsonString, &info)
	socket := info.Local_endpoint != ""

	if info.SyscallName == "syscall.write" {
		// Send tainted network message => add to behavior map its tainted offsets,
		// i.e. region of send buf that overlaps watched region
		sent_msg := BehaviorValue{
			Offset:        0,
			Send_endpoint: info.Local_endpoint, Recv_endpoint: info.Remote_endpoint, Transport: info.Transport,
			Send_module: tc.config.Module,
		}
		event := Event{EventType: MessageSend, Address: info.Bufaddr, Size: info.Bufsz, Behavior: &sent_msg}
		WriteEvent(hit.thread, tc.event_log, event)

		for buf_addr := info.Bufaddr; buf_addr < info.Bufaddr+info.Bufsz; buf_addr++ {
			tainting_vals, ok := tc.mem_param_map[buf_addr]
			if !ok {
				continue
			}
			sent_msg.Offset = buf_addr - info.Bufaddr
			tc.behavior_map[sent_msg] = tainting_vals
			event := Event{EventType: BehaviorMapUpdate, Size: 1, Behavior: &sent_msg, TaintingVals: &tainting_vals}
			WriteEvent(hit.thread, tc.event_log, event)
		}
	} else if info.SyscallName == "syscall.read" && socket {
		// Receive network message => set watchpoint on entire read buffer, tainted by message
		recvd_msg := BehaviorValue{
			Offset:        0,
			Send_endpoint: info.Remote_endpoint, Recv_endpoint: info.Local_endpoint, Transport: info.Transport,
			Recv_module: tc.config.Module,
		}
		event := Event{EventType: MessageRecv, Address: info.Bufaddr, Size: info.Bufsz, Behavior: &recvd_msg}
		WriteEvent(hit.thread, tc.event_log, event)

		recvd_msg.Offset = info.Bufsz // Used in setWatchpoint
		tainting_msg := TaintingBehavior{
			Behavior: recvd_msg,
			Flow:     DataFlow,
		}
		// frame 3 = syscall.read
		tc.setWatchpoint(SyscallRecvBuf, []TaintingVals{MakeTaintingVals(nil, &tainting_msg)}, true, hit.thread, 3)
	} else if info.SyscallName == "syscall.read" {
		// Read config file => set watchpoint on entire read buffer
		// Each byte is tainted by param of corresponding offset in buffer (assuming params are separated by \n)
		tainting_param := TaintingParam{
			Param: Param{
				File:   info.Filename,
				Module: tc.config.Module,
			},
			Flow: DataFlow,
		}
		tainting_vals := MakeTaintingVals(&tainting_param, nil)
		event := Event{EventType: ConfigLoad, Address: info.Bufaddr, Size: info.Bufsz, TaintingVals: &tainting_vals}
		WriteEvent(hit.thread, tc.event_log, event)
		tc.setWatchpoint(SyscallRecvBuf, []TaintingVals{tainting_vals}, true, hit.thread, 3)
	} else {
		log.Printf("Syscall entry breakpoint hit for unexpected syscall %v\n", info.SyscallName)
	}
}

/* If hit was in runtime, either ignore (e.g. newstack), or
 * record first non-runtime frame as line to check taint in.
 * (Can't assume that line will additionally have a non-runtime hit, e.g. some memmoves.)
 * Return false to ignore.
 * TODO are there any runtime functions we want to treat normally? */
func (tc *TaintCheck) handleRuntimeHit(hit *Hit) (*api.Stackframe, bool) {
	stack, err := tc.client.Stacktrace(-1, 100, api.StacktraceSimple, &api.LoadConfig{})
	// TODO check for partially loaded (in any calls with LoadConfig), and hitting max depth
	if err != nil {
		log.Panicf("Error getting stacktrace: %v\n", err)
	}

	hit.stack_len = len(stack)

	if strings.HasPrefix(stack[0].Function.Name(), "runtime") {
		log.Println("Runtime watchpoint hit - partial stack (including first non-runtime frame, whose PC is one after call instr)")
		for i, frame := range stack {
			fn := frame.Function.Name()
			loc := fmt.Sprintf("%v \nLine %v:%v:0x%x",
				frame.File, frame.Line, fn, frame.PC)
			log.Println(loc)

			// TODO skip all hits from go runtime goroutines (sw wp commit may hv a test for sysmon?)
			// (but not hits in go runtime from program thread)
			// To detect if runtime goroutine: see `goroutines -with user` (https://github.com/go-delve/delve/blob/master/Documentation/cli/README.md#goroutine)
			if fn == "runtime.newstack" {
				return nil, false
			}
			if !strings.HasPrefix(fn, "runtime") {
				hit.frame = i
				return &frame, true
			}

		}
	}

	return nil, true
}

/* Get instruction corresponding to hit */
func (tc *TaintCheck) hittingInstr(non_runtime_frame *api.Stackframe, hit *Hit) {
	pc := hit.thread.PC
	if non_runtime_frame != nil {
		pc = non_runtime_frame.PC
	}
	fct_instr, err := tc.client.DisassemblePC(api.EvalScope{GoroutineID: -1, Frame: hit.frame}, pc, api.IntelFlavour) // dst, src
	if err != nil {
		log.Panicf("Error disassembling at PC 0x%x: %v\n", pc, err)
	}

	for i, instr := range fct_instr {
		if instr.Loc.PC == pc {
			if non_runtime_frame != nil {
				// For runtime hit, pc is one *after* the call instr that ended up in runtime => get previous instr
				hit.hit_instr = &fct_instr[i-1]
			} else {
				hit.hit_instr = &fct_instr[i]
			}
			return
		}
	}

	log.Panicf("Failed to find instruction at PC 0x%x: %v\n", pc, err)
}

/* Get source line corresponding to hit.
 * Return false to ignore this hit. */
func (tc *TaintCheck) hittingLine(hit *Hit) bool {
	non_runtime_frame, handle := tc.handleRuntimeHit(hit)
	// Ignore prints (may be within print, or when calling print) for convenience
	if tc.hitInPrint() || !handle {
		return false
	}

	tc.hittingInstr(non_runtime_frame, hit)

	src_line := sourceLine(tc.client, hit.hit_instr.Loc.File, hit.hit_instr.Loc.Line)
	if strings.Contains(strings.ToLower(src_line), ("print")) {
		// hitInPrint doesn't catch if src line is calling print
		return false
	}

	if src_line == "" {
		log.Panicf("No source line found for PC 0x%x\n", hit.hit_instr.Loc.PC)
	}

	return true
}

// Pick any control-flow taint out of taintingVals
func controlFlowTaint(tainting_vals TaintingVals) TaintingVals {
	ifstmt_taint := newTaintingVals()
	tainting_vals.Params.ForEach(func(tp TaintingParam) bool {
		if tp.Flow == ControlFlow {
			ifstmt_taint.Params.Insert(tp)
		}
		return true
	})
	tainting_vals.Behaviors.ForEach(func(tb TaintingBehavior) bool {
		if tb.Flow == ControlFlow {
			ifstmt_taint.Behaviors.Insert(tb)
		}
		return true
	})
	return ifstmt_taint
}

/* If set a breakpoint for where to set the watchpoint (e.g. function arg), record in bp_pending_wps.
 * Otherwise, populate cmd_pending_wp (if one exists, update it) with sequence of commands needed to set watchpoint.
 * e.g. lhs of :=, a reference (since we watch its target which is about to change), runtime hit. */
func (tc *TaintCheck) recordPendingWp(expr string, loc api.Location, argno *int,
	body_start int, body_end int, overlap_start uint64, overlap_end uint64, hit *Hit) {
	existing_info := PendingWp{}
	new_bp_addr := uint64(0)
	if loc.PCs != nil {
		// Passed location for breakpoint => set breakpoint
		new_bp_addr = loc.PCs[0]
		tc.setBp(new_bp_addr)
	} else if tc.cmd_pending_wp != nil {
		// Passed no location => update existing cmd pending wp (or create new one)
		existing_info = *tc.cmd_pending_wp
	}

	if hit != nil {
		// Called for watchpoint hit, instead of finishing next in ifstmt =>
		// get tainting vals from watch region
		existing_info.threadID = hit.thread.ID
		// Case 1: Hit watchpoint => copy tainting vals from overlapping region's m-c entries
		// (they may differ across the region)
		ifstmt_taint := newTaintingVals()
		if overlap_end == 0 {
			// append => handle same as config variable load (put all taint at offset 0)
			overlap_end = overlap_start + 1
		}
		new_params := map[uint64]string{}
		for watchaddr := overlap_start; watchaddr < overlap_end; watchaddr++ {
			tainting_vals, ok := tc.mem_param_map[watchaddr]
			if !ok {
				log.Panicf("No mem-param map entry for %#x\n", watchaddr)
			}

			// M-c entry has an empty param => presumably we just accessed
			// (some region of) config read buf for the first time. Populate m-c.
			if hasEmptyParam(tainting_vals) {
				if len(new_params) == 0 {
					new_params = tc.readParams(overlap_start, overlap_end, hit.frame)
				}
				// XXX ignore offsets that don't correspond to params (e.g. \n)
				tc.populateParam(watchaddr, new_params[watchaddr-overlap_start])
				tainting_vals = tc.mem_param_map[watchaddr]
			}

			if body_start == 0 {
				// Case 1a: Regular watchpoint => copy overlapping region's vals at each offset
				// (offset may already have existing ones, e.g. hit a watchpoint within a tainted branch body - union with those if so).
				existing_info.updateTaintingVals(tainting_vals, watchaddr-overlap_start)
			} else {
				// Case 1b: Watchpoint in if condition => gather vals from all bytes of overlapping region,
				// to be copied into each byte of expressions in branch body (don't know their size),
				// and set them to control flow
				tainting_vals.Params.ForEach(func(tp TaintingParam) bool {
					tp.Flow = ControlFlow
					ifstmt_taint.Params.Insert(tp)
					return true
				})
				tainting_vals.Behaviors.ForEach(func(tb TaintingBehavior) bool {
					tb.Flow = ControlFlow
					ifstmt_taint.Behaviors.Insert(tb)
					return true
				})
			}
		}

		if body_start != 0 {
			existing_info.updateTaintingVals(ifstmt_taint, 0) // put them all at offset 0 - setWatchpoint will pick them out
			existing_info.body_start = body_start
			existing_info.body_end = body_end
		}
	}

	if argno != nil {
		if len(existing_info.watchargs) == 0 {
			existing_info.watchargs = make(map[int]string)
		}
		existing_info.watchargs[*argno] = expr
	} else if expr != "" {
		if existing_info.watchexprs.Empty() {
			existing_info.watchexprs = *set.New[string](1)
		}
		existing_info.watchexprs.Insert(expr)
	}

	if new_bp_addr != 0 {
		tc.bp_pending_wps[new_bp_addr] = existing_info
	} else if hit != nil {
		cmds := []Command{Command{cmd: api.Next, stack_len: hit.stack_len, lineno: hit.hit_instr.Loc.Line}}
		if hit.frame > 0 {
			// runtime hit
			cmds = []Command{}
			stack_len := hit.stack_len - 1
			for i := 0; i < hit.frame; i++ {
				cmds = append(cmds, Command{cmd: api.StepOut, stack_len: stack_len})
				stack_len--
			}

			cmds = append(cmds, Command{cmd: api.Next, stack_len: stack_len + 1, lineno: hit.hit_instr.Loc.Line})
		}
		existing_info.cmds = cmds
		tc.cmd_pending_wp = &existing_info
	} else {
		// branch body - cmds are already in existing info from previous hit - exec will update line
		tc.cmd_pending_wp = &existing_info
	}
	fmt.Printf("ZZEM: exit recordPendingWp, for line %v: %v\n", loc.Line, existing_info)
}

func (tc *TaintCheck) onPendingWpBpHitDone(hit *Hit) {
	bp_addr := hit.hit_bp.Addrs[0]
	if _, err := tc.client.ClearBreakpoint(hit.hit_bp.ID); err != nil {
		log.Panicf("Failed to clear bp at 0x%x: %v\n", bp_addr, err)
	}
	delete(tc.bp_pending_wps, bp_addr)
}

// Move watchexpr to tainted page, and set any watchpoint(s) corresponding to watchexpr
// Update m-c map:
// If !syscall_read, add tainting_vals to resulting watched region(s), byte by byte
// Else, we're tainting the recv buf of a network message or config file =>
// Network message: record each byte of buf as tainted by corresponding offset of message
// (tainting_vals[0] is recvd msg)
// Config file: record each byte of buf as tainted by corresponding param
// (tainting_vals[0] is param).
func (tc *TaintCheck) setWatchpoint(watchexpr string, tainting_vals []TaintingVals, syscall_read bool, thread *api.Thread, frame int) {
	scope := api.EvalScope{GoroutineID: -1, Frame: frame}
	// We really want a read-only wp, but not supported
	watchpoints, err := tc.client.CreateWatchpoint(scope, watchexpr, api.WatchRead|api.WatchWrite, api.WatchSoftware, tc.config.Move_wps)
	if err != nil {
		log.Panicf("Failed to set watchpoint for %v: %v\n", watchexpr, err)
	} else if len(watchpoints) == 0 {
		log.Panicf("Debugger returned no watchpoints for %v\n", watchexpr)
	}
	if syscall_read && len(watchpoints) > 1 {
		log.Panicf("Debugger returned multiple watchpoints for syscall read %+v\n", tainting_vals)
	}

	// Add pre-move addresses to m-c - will update after next Continue()
	for _, watchpoint := range watchpoints {
		// For each created or existing watchpoint: update mem-config map, log
		// TODO test for adding new taint to existing addr

		fmt.Printf("ZZEM Set watchpoint on %v\n", watchpoint.WatchExpr)
		event := Event{EventType: WatchpointSet, Address: watchpoint.Addr, Size: watchSize(watchpoint), Expression: watchpoint.WatchExpr}
		WriteEvent(thread, tc.event_log, event)

		if !syscall_read {
			allbytes_taint := controlFlowTaint(tainting_vals[0])
			// Config variable or append (or one-byte expression, but works for that too)
			if len(tainting_vals) == 1 {
				config_taint := tainting_vals[0]
				allbytes_taint = union(allbytes_taint, config_taint)
			}
			watch_end := watchpoint.Addrs[0] + watchSize(watchpoint)
			for watchaddr := watchpoint.Addrs[0]; watchaddr < watch_end; watchaddr++ {
				offset := watchaddr - watchpoint.Addrs[0]
				new_taint := allbytes_taint

				// For each byte in new watch region:
				// Apply any data-flow taint from corresponding byte,
				// and any control-flow or config/append taint
				if uint64(len(tainting_vals)) > offset {
					new_taint = union(new_taint, tainting_vals[offset])
				}
				tc.updateTaintingVals(watchaddr, new_taint, thread)
			}
		}
	}

	if syscall_read {
		message := tainting_vals[0].Params.Empty()
		// Can't read the params yet - read hasn't happened
		buf_start := watchpoints[0].Addrs[0]
		buf_sz := watchSize(watchpoints[0])
		for offset := uint64(0); offset < buf_sz; offset++ {
			buf_addr := buf_start + offset
			if message {
				tainting_msg := tainting_vals[0].Behaviors.Slice()[0]
				tainting_msg.Behavior.Offset = offset
				tc.updateTaintingVals(buf_addr, MakeTaintingVals(nil, &tainting_msg), thread)
			} else {
				tc.updateTaintingVals(buf_addr, tainting_vals[0], thread)
			}
		}
	}
}

// Watchpoint hit => record any new pending watchpoints.
func (tc *TaintCheck) onWatchpointHit(hit *Hit) {
	if !tc.hittingLine(hit) {
		log.Printf("Not propagating taint for watchpoint hit at %#x\n", hit.thread.PC)
		return
	}
	event := Event{EventType: WatchpointHit, Address: hit.hit_bp.Addr, Size: watchSize(hit.hit_bp), Expression: hit.hit_bp.WatchExpr}
	WriteEvent(hit.thread, tc.event_log, event)
	fmt.Printf("ZZEM hit watchpoint %v\n", hit.hit_bp.WatchExpr)
	tc.propagateTaint(hit.hit_instr.Loc.File, hit.hit_instr.Loc.Line, hit, hit.frame)
}

// Set all watchpoints corresponding to pendingWp, remove them from pendingWp
func (tc *TaintCheck) setPendingWatchpoints(pendingWp *PendingWp, thread *api.Thread, frame int) {
	if pendingWp.watchexprs.Empty() && len(pendingWp.watchargs) == 0 {
		log.Panicf("No pending watches found\n")
	}
	pendingWp.watchexprs.ForEach(func(watchexpr string) bool {
		tc.setWatchpoint(watchexpr, pendingWp.tainting_vals, false, thread, frame)
		return true
	})
	scope := api.EvalScope{GoroutineID: -1, Frame: frame}
	for argno, overlap_expr := range pendingWp.watchargs {
		// if method, args include receiver as arg 0 (as we did when recording argno)
		args, err := tc.client.ListFunctionArgs(scope, api.LoadConfig{})
		if err != nil {
			log.Panicf("Failed to list function args for pending wp %+v: %v\n", pendingWp, err)
		}
		watchexpr := args[argno].Name + overlap_expr
		tc.setWatchpoint(watchexpr, pendingWp.tainting_vals, false, thread, frame)
	}
	pendingWp.watchexprs = *set.New[string](0)
	pendingWp.watchargs = make(map[int]string)
}

func (tc *TaintCheck) onPendingWpBpHit(hit *Hit) {
	if len(hit.hit_bp.Addrs) != 1 {
		log.Panicf("Wrong number of addrs at pending wp; bp %+v\n", hit.hit_bp)
	}

	bp_addr := hit.hit_bp.Addrs[0]
	info := tc.bp_pending_wps[bp_addr]
	fmt.Printf("ZZEM line %v: hit pending wp breakpoint\n", hit.hit_bp.Line)
	fmt.Printf("info: %+v\n", info)
	defer func() {
		tc.onPendingWpBpHitDone(hit)
	}()

	tc.setPendingWatchpoints(&info, hit.thread, hit.frame)
}

// Update mem-param map for any watchpoints that moved since last Continue
// (either due to stack adjust or allocator move)
func (tc *TaintCheck) updateMovedWps() {
	// TODO: add a test for stack adjust - happens in xenon, but not deterministically
	bps, list_err := tc.client.ListBreakpoints(true)
	if list_err != nil {
		log.Panicf("Error listing breakpoints: %v\n", list_err)
	}
	for _, bp := range bps {
		new_addr := bp.Addr
		for _, prev_addrs := range bp.PreviousAddrs {
			for _, prev_addr := range prev_addrs {
				if prev_addr > 0 {
					if tainting_vals, ok := tc.mem_param_map[prev_addr]; ok {
						delete(tc.mem_param_map, prev_addr)
						tc.mem_param_map[new_addr] = tainting_vals
					}
				}
				new_addr++
			}
		}
	}
}

func New(config *Config) (*TaintCheck, error) {
	client := rpc2.NewClient(config.Server_endpoint)

	event_log_file, err := os.Create(config.Event_log_filename)
	if err != nil {
		return nil, err
	}

	// TODO (minor) rename TaintCheck to e.g. ConfTamerModule
	tc := TaintCheck{
		config:         *config,
		client:         client,
		bp_pending_wps: make(map[uint64]PendingWp),
		mem_param_map:  make(map[uint64]TaintingVals),
		behavior_map:   make(BehaviorMap),
		event_log:      csv.NewWriter(event_log_file),
	}

	tc.event_log.Write([]string{"Type", "Memory Address", "Memory Size", "Expression", "Behavior", "Tainting Values",
		"Timestamp", "Breakpoint/Watchpoint Hit Location (File Line PC)", "Thread"})

	if config.Initial_watchexpr != "" {
		// For testing: pass in an expr to set a watchpoint on
		init_loc := tc.lineWithStmt(nil, config.Initial_bp_file, config.Initial_bp_line, 0)
		tainting_param := TaintingParam{Param: Param{Module: tc.config.Module, Param: config.Initial_watchexpr}, Flow: DataFlow}
		tc.bp_pending_wps[init_loc.PC] = PendingWp{
			watchexprs: *set.From([]string{config.Initial_watchexpr}),
			// Will be copied into each byte of config variable (don't know its size)
			tainting_vals: []TaintingVals{MakeTaintingVals(&tainting_param, nil)},
		}
		tc.setBp(init_loc.PC)
	}
	return &tc, nil
}
