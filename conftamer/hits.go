package conftamer

import (
	"encoding/csv"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/go-delve/delve/pkg/proc"
	"github.com/go-delve/delve/service/api"
	"github.com/go-delve/delve/service/rpc2"
	set "github.com/hashicorp/go-set"
)

// Data structures used to create the configuration tamer
// When adding fields to Param or BehaviorValue, update graph.go

type Param struct {
	Module string
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

// Things that should be reset for each hit
type Hit struct {
	hit_bp    *api.Breakpoint
	hit_instr *api.AsmInstruction
	// Frame to check taint in (first non-runtime frame)
	frame int
}

// Exprs/args we will set a wp on, once they're in scope.
// If add any fields, update String()
type PendingWp struct {
	watchexprs set.Set[string]
	// Arg index => Expression to append to callee's copy, if any
	watchargs map[int]string
	// Values that tainted these
	// On wp hit: Copy from mem_param_map[hitting addrs], so we have them even if orig wp goes OOS
	// (e.g. hit for return of function local - will set wp after function returns)
	tainting_vals TaintingVals

	// If this is a bp within an if[else] body,
	// the start/end lines of the body
	body_start int
	body_end   int
}

type TaintCheck struct {
	config   Config
	hit      Hit
	client   *rpc2.RPCClient
	thread   *api.Thread
	move_wps bool
	module   string

	// Key: Bp addr where exprs go in scope
	pending_wps map[uint64]PendingWp

	// Note for both mem_param_map and behavior_map, each entry is for a single byte
	// (memory address or message offset).
	// Everything in mem_param_map overlaps some watchpoint, but each watchpoint is a contiguous region

	// Memory address => config/behavior values that taint it
	// Don't need PC to disambiguate - if memory is reused,
	// old entry will have gone OOS and been removed
	mem_param_map map[uint64]TaintingVals

	// Behavior value => config/behavior values that taint it
	behavior_map BehaviorMap

	event_log             *csv.Writer
	behavior_map_filename string
}

// Handle syscall entry bp hit - server returns it to us for message receives and tainted sends
func (tc *TaintCheck) onSyscallEntryBpHit() {
	stack, err := tc.client.Stacktrace(-1, 100, api.StacktraceSimple, &api.LoadConfig{})
	// TODO check for partially loaded (in any calls with LoadConfig)
	if err != nil {
		log.Panicf("Error getting stacktrace: %v\n", err)
	}

	syscall_name := stack[3].Function.Name()
	local, remote, transport := tc.getSocketEndpoints()
	bufstart, bufsz := tc.syscallBuf()
	if syscall_name == "syscall.write" {
		// Send tainted message => add to behavior map its tainted offsets,
		// i.e. region of send buf that overlaps watched region
		sent_msg := BehaviorValue{
			Offset:        0,
			Send_endpoint: local, Recv_endpoint: remote, Transport: transport,
			Send_module: tc.module,
		}
		event := Event{EventType: MessageSend, Address: bufstart, Size: bufsz, Behavior: &sent_msg}
		WriteEvent(tc, tc.event_log, event)

		// TODO handle other syscalls that do network send and file open (e.g. mmap, munmap)
		for buf_addr := bufstart; buf_addr < bufstart+bufsz; buf_addr++ {
			tainting_vals, ok := tc.mem_param_map[buf_addr]
			if !ok {
				continue
			}
			sent_msg.Offset = buf_addr - bufstart
			tc.behavior_map[sent_msg] = tainting_vals
			event := Event{EventType: BehaviorMapUpdate, Size: 1, Behavior: &sent_msg, TaintingVals: &tainting_vals}
			WriteEvent(tc, tc.event_log, event)
		}
	} else if syscall_name == "syscall.read" {
		// Receive message => set watchpoint on entire receive buffer
		recvd_msg := BehaviorValue{
			Offset:        0,
			Send_endpoint: remote, Recv_endpoint: local, Transport: transport,
			Recv_module: tc.config.Module,
		}
		event := Event{EventType: MessageRecv, Address: bufstart, Size: bufsz, Behavior: &recvd_msg}
		WriteEvent(tc, tc.event_log, event)

		recvd_msg.Offset = bufsz // Used in setWatchpoint
		tainting_msg := TaintingBehavior{
			Behavior: recvd_msg,
			Flow:     DataFlow,
		}
		tc.hit.frame = 3 // syscall.read: buffer is `p` argument
		tc.setWatchpoint("p", TaintingVals{Behaviors: *set.From([]TaintingBehavior{tainting_msg})}, true)
	} else {
		log.Printf("Syscall entry breakpoint hit for unexpected syscall %v\n", syscall_name)
	}
}

/* If hit was in runtime, either ignore (e.g. newstack), or
 * record first non-runtime frame as line to check taint in.
 * (Can't assume that line will additionally have a non-runtime hit, e.g. some memmoves.)
 * Return false to ignore.
 * TODO first non-runtime frame isn't always what we want - e.g. syscall arg faults:
 * user code may call Syscall6 directly, or e.g. os.Open().
 * Analyze every non-runtime line? */
func (tc *TaintCheck) handleRuntimeHit() (*api.Stackframe, bool) {
	stack, err := tc.client.Stacktrace(-1, 100, api.StacktraceSimple, &api.LoadConfig{})
	// TODO check for partially loaded (in any calls with LoadConfig)
	if err != nil {
		log.Panicf("Error getting stacktrace: %v\n", err)
	}

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
				tc.hit.frame = i
				return &frame, true
			}

		}
	}

	return nil, true
}

/* Get instruction corresponding to hit */
func (tc *TaintCheck) hittingInstr(non_runtime_frame *api.Stackframe) {
	pc := tc.thread.PC
	if non_runtime_frame != nil {
		pc = non_runtime_frame.PC
	}
	fct_instr, err := tc.client.DisassemblePC(api.EvalScope{GoroutineID: -1, Frame: tc.hit.frame}, pc, api.IntelFlavour) // dst, src
	if err != nil {
		log.Panicf("Error disassembling at PC 0x%x: %v\n", pc, err)
	}

	for i, instr := range fct_instr {
		if instr.Loc.PC == pc {
			if non_runtime_frame != nil {
				// For runtime hit, pc is one *after* the call instr that ended up in runtime => get previous instr
				tc.hit.hit_instr = &fct_instr[i-1]
			} else {
				tc.hit.hit_instr = &fct_instr[i]
			}
			return
		}
	}

	log.Panicf("Failed to find instruction at PC 0x%x: %v\n", pc, err)
}

/* Get source line corresponding to hit.
 * Return false to ignore this hit. */
func (tc *TaintCheck) hittingLine() bool {
	non_runtime_frame, handle := tc.handleRuntimeHit()
	// Ignore prints (may be within print, or when calling print) for convenience
	if tc.hitInPrint() || !handle {
		return false
	}

	tc.hittingInstr(non_runtime_frame)

	src_line := sourceLine(tc.client, tc.hit.hit_instr.Loc.File, tc.hit.hit_instr.Loc.Line)
	if strings.Contains(strings.ToLower(src_line), ("print")) {
		// hitInPrint doesn't catch if src line is calling print
		return false
	}

	if src_line == "" {
		log.Panicf("No source line found for PC 0x%x\n", tc.hit.hit_instr.Loc.PC)
	}

	return true
}

// Set bp for when wp will be in scope, record state
func (tc *TaintCheck) recordPendingWp(expr string, loc api.Location, argno *int, body_start int, body_end int) {
	// 1. Set breakpoint where pending watchpoint will be in scope
	new_bp_addr := loc.PCs[0]
	tc.setBp(new_bp_addr)

	// 2. Copy tainting values from hit watchpoint's to pending watchpoint
	// (or from config var, for config breakpoint)
	existing_info := tc.pending_wps[new_bp_addr]

	if tc.hit.hit_bp != nil {
		if tc.hit.hit_bp.WatchType != 0 {
			// hit watchpoint => copy tainting vals from watchpoint's m-c entry
			hit_wp_addr := tc.hit.hit_bp.Addrs[0]
			// XXX (when handle partial tainting): handle wp where m-p map entries
			// differ across the watched region. For now, using entry of starting addr

			tainting_vals, ok := tc.mem_param_map[hit_wp_addr]
			if !ok {
				log.Panicf("No mem-param map entry for watchpoint %v\n", tc.hit.hit_bp.WatchExpr)
			}

			// TODO add test for append w/ realloc to an alrdy tainted thing (i.e. need to update wp addr)
			// Note that wp for tainted array can hit for append to empty slice (first call to packUint16) - need to investigate
			// Also think abt packUint16 in xenon: passes in a ptr midway thru an alrdy-tainted slice
			// Also confirm that passing and returning a "[]" is always a slice (i.e. won't create new array)

			// Union with any existing ones for the new bp addr - can happen if e.g.
			// hit a watchpoint within a branch body whose condition hit the same watchpoint
			existing_info.updateTaintingVals(tainting_vals)

			if body_start != 0 {
				// Entering if[else] body => copy branch condition's tainting values, but set them to control flow
				tainting_vals = existing_info.tainting_vals
				existing_info.tainting_vals.Params = *set.New[TaintingParam](0)
				existing_info.tainting_vals.Behaviors = *set.New[TaintingBehavior](0)
				tainting_vals.Params.ForEach(func(tainting_param TaintingParam) bool {
					tainting_param.Flow = ControlFlow
					existing_info.tainting_vals.Params.Insert(tainting_param)
					return true
				})
				tainting_vals.Behaviors.ForEach(func(tainting_behavior TaintingBehavior) bool {
					tainting_behavior.Flow = ControlFlow
					existing_info.tainting_vals.Behaviors.Insert(tainting_behavior)
					return true
				})

				existing_info.body_start = body_start
				existing_info.body_end = body_end
			}
		} else {
			// hit breakpoint, presumably in branch body =>
			// copy taintingVals and body start/end from pending wp for bp we just hit
			cur_bp_addr := tc.hit.hit_bp.Addrs[0]
			cur_info, existed := tc.pending_wps[cur_bp_addr]
			if !existed {
				log.Panicf("Expected to find pending_wp at addr %#x in branch body\n", cur_bp_addr)
			}
			existing_info.updateTaintingVals(cur_info.tainting_vals)
			existing_info.body_start = cur_info.body_start
			existing_info.body_end = cur_info.body_end
		}
	} else {
		// config variable
		tainting_param := []TaintingParam{{Param: Param{Module: tc.module, Param: expr}, Flow: DataFlow}}
		existing_info.tainting_vals = TaintingVals{Params: *set.From(tainting_param)}
	}

	if argno != nil {
		if len(existing_info.watchargs) == 0 {
			existing_info.watchargs = make(map[int]string)
		}
		existing_info.watchargs[*argno] = expr
	} else {
		if existing_info.watchexprs.Empty() {
			existing_info.watchexprs = *set.New[string](1)
		}
		existing_info.watchexprs.Insert(expr)
	}

	log.Printf("recordPendingWp, line %v: %v\n", loc.Line, existing_info)
	tc.pending_wps[new_bp_addr] = existing_info
}

func (tc *TaintCheck) onPendingWpBpHitDone(bp_addr uint64) {
	// Nothing left pending at this bp addr
	if _, err := tc.client.ClearBreakpoint(tc.hit.hit_bp.ID); err != nil {
		log.Panicf("Failed to clear bp at 0x%x: %v\n", bp_addr, err)
	}
	delete(tc.pending_wps, bp_addr)
}

// Move watchexpr to tainted page, and set any watchpoint(s) corresponding to watchexpr
// Update m-c map:
// If !message, add tainting_vals to each addr in resulting watched region(s)
// Else, we're tainting a message recv buf =>
// record each byte of message as tainting corresponding byte of buf (tainting_vals.offset is buffer size)
func (tc *TaintCheck) setWatchpoint(watchexpr string, tainting_vals TaintingVals, message bool) {
	scope := api.EvalScope{GoroutineID: -1, Frame: tc.hit.frame}
	// We really want a read-only wp, but not supported
	watchpoints, err := tc.client.CreateWatchpoint(scope, watchexpr, api.WatchRead|api.WatchWrite, api.WatchSoftware, tc.move_wps)
	if err != nil {
		log.Panicf("Failed to set watchpoint for %v: %v\n", watchexpr, err)
	} else if len(watchpoints) == 0 {
		log.Panicf("Debugger returned no watchpoints for %v\n", watchexpr)
	}
	if message && len(watchpoints) > 1 {
		log.Panicf("Debugger returned multiple watchpoints for msg buffer %+v\n", tainting_vals.Behaviors.Slice()[0])
	}

	// Add pre-move addresses to m-c - will update after next Continue()
	for _, watchpoint := range watchpoints {
		// For each created or existing watchpoint: update mem-config map, log
		// TODO test for adding new taint to existing addr

		event := Event{EventType: WatchpointSet, Address: watchpoint.Addr, Size: watchSize(watchpoint), Expression: watchpoint.WatchExpr}
		WriteEvent(tc, tc.event_log, event)

		if !message {
			tc.forEachWatchaddr(watchpoint, func(watchaddr uint64) bool {
				tc.updateTaintingVals(watchaddr, tainting_vals)
				return true // unused
			})
		}
	}

	if message {
		tainting_val := tainting_vals.Behaviors.Slice()[0]
		bufstart := watchpoints[0].Addr
		bufsz := tainting_val.Behavior.Offset
		for offset := uint64(0); offset < bufsz; offset++ {
			tainting_val.Behavior.Offset = offset
			tc.updateTaintingVals(bufstart+offset, TaintingVals{Behaviors: *set.From([]TaintingBehavior{tainting_val})})
		}
	}
}

// Watchpoint hit => record any new pending watchpoints
func (tc *TaintCheck) onWatchpointHit() {
	if !tc.hittingLine() {
		log.Printf("Not propagating taint for watchpoint hit at %#x\n", tc.thread.PC)
		return
	}
	event := Event{EventType: WatchpointHit, Address: tc.hit.hit_bp.Addr, Size: watchSize(tc.hit.hit_bp), Expression: tc.hit.hit_bp.WatchExpr}
	WriteEvent(tc, tc.event_log, event)
	tc.propagateTaint()
}

// Breakpoint for pending watchpoint hit => try to set the watchpoint
func (tc *TaintCheck) onPendingWpBpHit() {
	if len(tc.hit.hit_bp.Addrs) != 1 {
		log.Panicf("Wrong number of addrs at pending wp; bp %+v\n", tc.hit.hit_bp)
	}

	bp_addr := tc.hit.hit_bp.Addrs[0]
	info := tc.pending_wps[bp_addr]
	log.Printf("\n\n*** Hit pending wp breakpoint at %v:%v (0x%x)\n", tc.hit.hit_bp.File, tc.hit.hit_bp.Line, bp_addr)
	defer func() {
		tc.onPendingWpBpHitDone(bp_addr)
	}()

	if info.watchexprs.Empty() && len(info.watchargs) == 0 {
		log.Panicf("No pending watches found after hitting 0x%x\n", bp_addr)
	}

	line := tc.hit.hit_bp.Line
	if info.body_start <= line && line <= info.body_end {
		// Bp in a branch body =>
		// record pending wp for this line, as if we hit a watchpoint and isTainted was always true
		tc.propagateTaint()
		if info.watchexprs.Contains("") {
			// first line of if/else body => no watchpoint to set yet
			return
		}
	}

	// Just wanted to hit and remove the breakpoint, not set watchpoint
	if info.watchexprs.Contains("") {
		return
	}

	info.watchexprs.ForEach(func(watchexpr string) bool {
		tc.setWatchpoint(watchexpr, info.tainting_vals, false)
		return true
	})
	scope := api.EvalScope{GoroutineID: -1, Frame: tc.hit.frame}
	for argno, overlap_expr := range info.watchargs {
		// if method, args include receiver as arg 0 (as we did when recording argno)
		args, err := tc.client.ListFunctionArgs(scope, api.LoadConfig{})
		if err != nil {
			log.Panicf("Failed to list function args at 0x%x: %v\n", bp_addr, err)
		}
		watchexpr := args[argno].Name + overlap_expr
		tc.setWatchpoint(watchexpr, info.tainting_vals, false)
	}
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

// Run the target until exit
func (tc *TaintCheck) Run() {
	log.Printf("Starting CT-Scan\n\n")
	defer WriteBehaviorMap(tc.behavior_map_filename, tc.behavior_map)

	state := <-tc.client.Continue()

	for ; !state.Exited; state = <-tc.client.Continue() {
		if state.Err != nil {
			log.Panicf("Error in debugger state: %v\n", state.Err)
		}
		tc.updateMovedWps()

		for _, thread := range state.Threads {
			hit_bp := thread.Breakpoint
			if hit_bp != nil {
				tc.hit = Hit{hit_bp: hit_bp}
				tc.thread = thread
				// TODO see gdoc (Instr that would hit multiple*) - may need more logic here for multiple hits
				if hit_bp.Name == proc.SyscallEntryBreakpoint {
					tc.onSyscallEntryBpHit()
				} else if hit_bp.WatchExpr != "" {
					tc.onWatchpointHit()
				} else {
					// Assumes the hit bp is for a pending wp (but could instead be e.g. fatalpanic)
					tc.onPendingWpBpHit()
				}
			}
		}

		// TODO also need to remove any PreviousAddrs?
		for _, wp_oos := range state.WatchOutOfScope {
			loc := state.SelectedGoroutine.CurrentLoc
			fmt.Printf("Watchpoint on %v went out of scope - current goroutine at %v:%v (0x%x) \n",
				wp_oos.WatchExpr, loc.File, loc.Line, loc.PC)
			tc.forEachWatchaddr(wp_oos, func(watchaddr uint64) bool {
				delete(tc.mem_param_map, watchaddr)
				return true // unused
			})
		}
	}

	fmt.Printf("Target exited with status %v\n", state.ExitStatus)
	log.Println("Finished CT-Scan")
	tc.client.Detach(false) // Also kills server, despite function doc (even on unmodified dlv)
}

func New(config *Config) (*TaintCheck, error) {
	client := rpc2.NewClient(config.Server_endpoint)

	event_log_file, err := os.Create(config.Event_log_filename)
	if err != nil {
		return nil, err
	}

	// TODO (minor) rename TaintCheck to e.g. ConfTamerModule
	tc := TaintCheck{
		config:                *config,
		client:                client,
		module:                config.Module,
		move_wps:              config.Move_wps,
		pending_wps:           make(map[uint64]PendingWp),
		mem_param_map:         make(map[uint64]TaintingVals),
		behavior_map:          make(BehaviorMap),
		event_log:             csv.NewWriter(event_log_file),
		behavior_map_filename: config.Behavior_map_filename,
	}

	tc.event_log.Write([]string{"Type", "Memory Address", "Memory Size", "Expression", "Behavior", "Tainting Values",
		"Timestamp", "Breakpoint/Watchpoint Hit Location (File Line PC)", "Thread"})

	if config.Initial_watchexpr != "" {
		// This will be replaced by a config breakpoint
		init_loc := tc.lineWithStmt(nil, config.Initial_bp_file, config.Initial_bp_line, 0)
		log.Printf("Configuration variable: %v\n", config.Initial_watchexpr)
		tc.recordPendingWp(config.Initial_watchexpr, init_loc, nil, 0, 0)
	}
	return &tc, nil
}
