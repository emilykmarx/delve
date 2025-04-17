package conftamer

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"log"
	"log/slog"
	"os"
	"reflect"
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
	// Scope to check taint in (first non-runtime frame)
	scope api.EvalScope
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

	/* Used if need to execute commands to reach in-scope location (vs setting a breakpoint) */

	// The sequence of commands needed
	cmds []Command
	// If executing a command sequence, the index in the sequence
	cmd_idx int
}

type TaintCheck struct {
	config Config
	client *rpc2.RPCClient

	// Watchpoints waiting to be set when we hit a breakpoint
	// Key: Bp addr
	bp_pending_wps map[uint64]PendingWp

	// Watchpoint waiting to be set after a command sequence completes
	cmd_pending_wp *PendingWp
	// If we're in a branch body, the start/end lines
	body_start int
	body_end   int

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

	logger *slog.Logger
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
	} else if info.SyscallName == "syscall.read" && socket && info.Local_endpoint != tc.config.Config_API_endpoint {
		// Receive network message (not for config API) => set watchpoint on entire read buffer, tainted by message
		recvd_msg := BehaviorValue{
			Offset:        0,
			Send_endpoint: info.Remote_endpoint, Recv_endpoint: info.Local_endpoint, Transport: info.Transport,
			Recv_module: tc.config.Module,
		}
		event := Event{EventType: MessageRecv, Address: info.Bufaddr, Size: info.Bufsz, Behavior: &recvd_msg}
		WriteEvent(hit.thread, tc.event_log, event)
		if !tc.config.Ignore_msg_recvs {
			recvd_msg.Offset = info.Bufsz // Used in setWatchpoint
			tainting_msg := TaintingBehavior{
				Behavior: recvd_msg,
				Flow:     DataFlow,
			}
			// frame 3 = syscall.read
			hit.scope.Frame = 3
			// PERF consider delaying this wp set - server will immediately un-mprotect for duration of read)
			tc.setWatchpoint(SyscallRecvBuf, []TaintingVals{MakeTaintingVals(nil, &tainting_msg)}, true, hit)
		}
	} else if info.SyscallName == "syscall.read" {
		// Load config from file or API => set watchpoint on entire read buffer, tainted by empty param
		// (Will populate param with contents of buffer on first access)
		if info.Local_endpoint == tc.config.Config_API_endpoint {
			info.Filename = "config API"
		}

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
		hit.scope.Frame = 3
		tc.setWatchpoint(SyscallRecvBuf, []TaintingVals{tainting_vals}, true, hit)
	} else {
		log.Printf("Syscall entry breakpoint hit for unexpected syscall %v\n", info.SyscallName)
	}
}

/* If hit was in runtime or internal, either ignore (e.g. newstack), or
 * record first non-runtime/internal frame as line to check taint in.
 * (Assumption is function was called implicitly by target code, so we should go to the first explicit frame.
 * Also, these functions are often optimized or written in asm.)
 * (Can't assume that line will additionally have a non-runtime hit, e.g. some memmoves.)
 * Return false to ignore.
 * TODO are there any runtime functions we want to treat normally (maybe some exported ones?) */
func (tc *TaintCheck) handleRuntimeHit(hit *Hit) (*api.Stackframe, bool) {
	stack := tc.stacktrace()

	hit.stack_len = len(stack)

	// Don't use parseFn, since some runtime functions get reflect.X linkname
	// TODO (minor) take path to go src as config item (for now assume any path containing /src/internal or /src/runtime is in go src)
	skip := strings.Contains(stack[0].File, "/src/internal") || strings.Contains(stack[0].File, "/src/runtime")
	if skip {
		log.Printf("Watchpoint hit in runtime or internal, stack len %v - "+
			"partial stack (including first non-runtime frame, whose PC is one after call instr)\n", len(stack))
		for i, frame := range stack {
			fn := frame.Function.Name()

			skip = strings.Contains(frame.File, "/src/internal") || strings.Contains(frame.File, "/src/runtime")
			loc := fmt.Sprintf("%v \nLine %v:%v:0x%x",
				frame.File, frame.Line, fn, frame.PC)
			log.Println(loc)

			// TODO can go runtime goroutines ever cause hits? (maybe sysmon in early sw wp commit, but may have been due to mprotecting dlv's pages instead)
			// To detect if runtime goroutine: see `goroutines -with user` (https://github.com/go-delve/delve/blob/master/Documentation/cli/README.md#goroutine)
			if fn == "runtime.newstack" {
				return nil, false
			}
			if !skip {
				hit.scope.Frame = i
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
	fct_instr, err := tc.client.DisassemblePC(hit.scope, pc, api.IntelFlavour) // dst, src
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
	// Ignore prints (may be within print, or when setting up to call print) for convenience
	if tc.hitInPrint() || !handle {
		return false
	}

	tc.hittingInstr(non_runtime_frame, hit)

	src_line := sourceLine(tc.client, hit.hit_instr.Loc.File, hit.hit_instr.Loc.Line)
	if ignoreSourceLine(src_line) {
		fmt.Printf("IGNORING PRINT: %v\n", src_line)
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

/* Populate existing_info with tainting vals from region's m-c entries
 * (they may differ across the region) */
func (tc *TaintCheck) getTaintingVals(existing_info *PendingWp, tainted_region *TaintedRegion, hit *Hit) {
	existing_info.threadID = hit.thread.ID
	ifstmt_taint := newTaintingVals()
	if tainted_region.overlap_end == 0 {
		// append => handle same as config variable load (put all taint at offset 0)
		tainted_region.overlap_end = tainted_region.overlap_start + 1
	}
	new_params := map[uint64]string{}
	for watchaddr := tainted_region.overlap_start; watchaddr < tainted_region.overlap_end; watchaddr++ {
		tainting_vals, ok := tc.mem_param_map[watchaddr]
		if !ok {
			log.Panicf("No mem-param map entry for %#x\n", watchaddr)
		}

		// M-c entry has an empty param => presumably we just accessed
		// (some region of) config read buf for the first time. Populate m-c.
		if hasEmptyParam(tainting_vals) {
			if len(new_params) == 0 {
				new_params = tc.readParams(tainted_region.overlap_start, tainted_region.overlap_end, hit.scope.Frame)
			}
			// XXX ignore offsets that don't correspond to params (e.g. \n)
			tc.populateParam(watchaddr, new_params[watchaddr-tainted_region.overlap_start])
			tainting_vals = tc.mem_param_map[watchaddr]
		}

		if tainted_region.body_start == 0 {
			// Case 1a: Regular watchpoint => copy tainted_region vals at each offset
			// (offset may already have existing ones, e.g. hit a watchpoint within a tainted branch body - union with those if so).
			existing_info.updateTaintingVals(tainting_vals, watchaddr-tainted_region.overlap_start)
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

	if tainted_region.body_start != 0 {
		existing_info.updateTaintingVals(ifstmt_taint, 0) // put them all at offset 0 - setWatchpoint will pick them out
	}
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
func (tc *TaintCheck) setWatchpoint(watchexpr string, tainting_vals []TaintingVals, syscall_read bool, hit *Hit) {
	// We really want a read-only wp, but not supported
	watchpoints, err := tc.client.CreateWatchpoint(hit.scope, watchexpr, api.WatchRead|api.WatchWrite, api.WatchSoftware, tc.config.Move_wps)
	if err != nil {
		errstr := fmt.Sprintf("Failed to set watchpoint for %v: %v\n", watchexpr, err)
		if strings.Contains(err.Error(), "type not supported") || strings.Contains(err.Error(), "nil slice") ||
			strings.Contains(err.Error(), "fake address") {
			// TODO fake address is likely fixable by setting bp at 2nd instr in function body instead of 1st
			// (unsure if has potential to cause missed access of arg in 1st instr)
			tc.Logf(slog.LevelWarn, hit, errstr)
		} else {
			log.Panicln(errstr)
		}
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
		WriteEvent(hit.thread, tc.event_log, event)

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
				tc.updateTaintingVals(watchaddr, new_taint, hit.thread)
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
				tc.updateTaintingVals(buf_addr, MakeTaintingVals(nil, &tainting_msg), hit.thread)
			} else {
				tc.updateTaintingVals(buf_addr, tainting_vals[0], hit.thread)
			}
		}
	}
}

/* Record a pending watchpoint for the newly tainted region.
 * Create or update from breakpoint- or command-pending watchpoints,
 * depending on set location. */
func (tc *TaintCheck) pendingWatchpoint(tainted_region *TaintedRegion, hit *Hit) {
	set_at_bp := tainted_region.set_location != nil
	// Get existing pending watchpoint for location (if any)
	pending_watchpoint := PendingWp{}
	if set_at_bp {
		// Breakpoint
		pending_watchpoint = tc.bp_pending_wps[tainted_region.set_location.PC]
	} else if tc.cmd_pending_wp != nil {
		// Existing cmd sequence, if any
		pending_watchpoint = *tc.cmd_pending_wp
		// Currently only supporting single cmd_pending_wp
		if pending_watchpoint.cmds != nil && !reflect.DeepEqual(tainted_region.cmds, pending_watchpoint.cmds) {
			// When advancing through branch body, this is ok (we keep updating the same one throughout branch body)
			fmt.Printf("existing cmd_pending_wp %+v has different command sequence than current %+v\n",
				pending_watchpoint.cmds, tainted_region.cmds)
		}
	}
	// Update commands and branch body info (can change, e.g. if handling a return inside tainted if)
	pending_watchpoint.cmds = tainted_region.cmds
	pending_watchpoint.cmd_idx = 0

	// Populate tainting values
	if hit.hit_bp != nil {
		// Watchpoint hit => copy from region overlapping with hit
		tc.getTaintingVals(&pending_watchpoint, tainted_region, hit)
	} else {
		// Fake "hit" from finishing next in branch body => tainting vals are already in cmd_pending_wp
		// (created for hit in condition).
		// If new watchpoint is also in cmd_pending, will use those - else, copy them to bp_pending
		if set_at_bp {
			pending_watchpoint.updateTaintingVals(tc.cmd_pending_wp.tainting_vals[0], 0) // all at offset 0
		}
	}

	// Insert argno/expr
	if tainted_region.overlap_arg != nil {
		if len(pending_watchpoint.watchargs) == 0 {
			pending_watchpoint.watchargs = make(map[int]string)
		}
		pending_watchpoint.watchargs[*tainted_region.overlap_arg] = *tainted_region.overlap_expr
	} else if tainted_region.overlap_expr != nil {
		if pending_watchpoint.watchexprs.Empty() {
			pending_watchpoint.watchexprs = *set.New[string](1)
		}
		pending_watchpoint.watchexprs.Insert(*tainted_region.overlap_expr)
	}
	fmt.Printf("pendingWatchpoint about to record: ")
	fmt.Printf("watchexprs: %+v, watchargs: %+v, cmds: %+v\n", pending_watchpoint.watchexprs, pending_watchpoint.watchargs, pending_watchpoint.cmds)

	// Record pending watchpoint (or set now, if possible)
	if tainted_region.set_now && len(tainted_region.cmds) == 0 {
		// non-runtime hit, can set now
		fmt.Printf("set pendingwp now\n")
		tc.setPendingWatchpoints(&pending_watchpoint, hit)
		// Cleanup if there was already a pending watchpoint at this location
		if set_at_bp {
			delete(tc.bp_pending_wps, tainted_region.set_location.PC)
		} else {
			// cmd-pending - cleaned up in Run()
		}
	} else {
		if set_at_bp {
			tc.setBp(tainted_region.set_location.PC)
			fmt.Printf("pendingWatchpoint set bp at %v:%v\n", tainted_region.set_location.File, tainted_region.set_location.Line)
			tc.bp_pending_wps[tainted_region.set_location.PC] = pending_watchpoint
		} else {
			tc.cmd_pending_wp = &pending_watchpoint
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
	fmt.Printf("ZZEM hit watchpoint on %v at %v:%v\n", hit.hit_bp.WatchExpr, hit.hit_instr.Loc.File, hit.hit_instr.Loc.Line)
	tainted_region := tc.propagateTaint(hit)
	if tainted_region != nil {
		tc.pendingWatchpoint(tainted_region, hit)
	}
	fmt.Printf("ZZEM propagated taint for watchpoint hit on %v\n", hit.hit_bp.WatchExpr)
}

// Set all watchpoints corresponding to pendingWp, remove them from pendingWp
func (tc *TaintCheck) setPendingWatchpoints(pendingWp *PendingWp, hit *Hit) {
	if pendingWp.watchexprs.Empty() && len(pendingWp.watchargs) == 0 {
		log.Panicf("No pending watches found\n")
	}
	pendingWp.watchexprs.ForEach(func(watchexpr string) bool {
		tc.setWatchpoint(watchexpr, pendingWp.tainting_vals, false, hit)
		return true
	})
	for argno, overlap_expr := range pendingWp.watchargs {
		// if method, args include receiver as arg 0 (as we did when recording argno)
		args, err := tc.client.ListFunctionArgs(hit.scope, api.LoadConfig{})
		if err != nil {
			log.Panicf("Failed to list function args for pending wp %+v: %v\n", pendingWp, err)
		}
		watchexpr := args[argno].Name + overlap_expr
		tc.setWatchpoint(watchexpr, pendingWp.tainting_vals, false, hit)
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
	fmt.Printf("ZZEM file %v line %v: hit pending wp breakpoint\n", hit.hit_bp.File, hit.hit_bp.Line)
	fmt.Printf("watchexprs: %+v, watchargs: %+v, cmds: %+v\n", info.watchexprs, info.watchargs, info.cmds)
	defer func() {
		tc.onPendingWpBpHitDone(hit)
	}()

	tc.setPendingWatchpoints(&info, hit)
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

	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds | log.Lshortfile)                    // for log.Printf
	tc.logger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{AddSource: true})) // default min level is info

	tc.event_log.Write([]string{"Type", "Memory Address", "Memory Size", "Expression", "Behavior", "Tainting Values",
		"Timestamp", "Breakpoint/Watchpoint Hit Location (File Line PC)", "Thread"})

	if config.Initial_watchexpr != "" {
		// For testing: pass in an expr to set a watchpoint on
		tainting_param := TaintingParam{Param: Param{Module: tc.config.Module, Param: config.Initial_watchexpr}, Flow: DataFlow}
		tainting_vals := []TaintingVals{MakeTaintingVals(&tainting_param, nil)}
		if config.Initial_bp_file != "" {
			// Config specifies initial location => set bp there
			init_loc := tc.lineWithStmt(config.Initial_bp_file, config.Initial_bp_line, 0)
			tc.bp_pending_wps[init_loc.PC] = PendingWp{
				watchexprs: *set.From([]string{config.Initial_watchexpr}),
				// Will be copied into each byte of config variable (don't know its size)
				tainting_vals: tainting_vals,
			}
			tc.setBp(init_loc.PC)
		} else {
			// No initial location => set it now (assumes server is already attached to the target - for self-CTscan)
			tc.setWatchpoint(config.Initial_watchexpr, tainting_vals, false, &Hit{
				scope: api.EvalScope{GoroutineID: config.Initial_goroutine, Frame: config.Initial_frame},
			})
		}
	}

	return &tc, nil
}
