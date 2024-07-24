package main

import (
	"fmt"
	"log"
	"reflect"
	"strings"

	"github.com/go-delve/delve/service/api"
	"github.com/go-delve/delve/service/rpc2"
)

// Data structures used to create the configuration lens

type TaintingParam struct {
	param string
	flow  TaintFlow
}

type TaintingVals struct {
	params map[TaintingParam]struct{}
}

// PC disambiguates if memory is reused for a different variable
type DoneWp struct {
	bp_addr uint64
	wp_addr uint64
}

// Things that should be reset for each hit
type Hit struct {
	hit_bp    *api.Breakpoint
	hit_instr *api.AsmInstruction
	// Frame to check taint in (first non-runtime frame)
	frame int
}

type PendingWp struct {
	watchexprs map[string]struct{}
	watchargs  map[int]struct{}
	// Addr => size
	watchaddrs map[uint64]int64
	// Values that tainted these
	// (With current taint policy, I think will always be same for all).
	// On wp hit: Copy from mem_param_map[hit], so we have them even if orig wp goes OOS
	// and/or we start a new round before setting the pending wp
	tainting_vals TaintingVals
}

type TaintCheck struct {
	hit    Hit
	client *rpc2.RPCClient

	// "Pending" = waiting for var to be in scope, or for hw wp to free up
	// Key: Bp addr where exprs go in scope
	// Value: Before hit corresp bp in any round, expr info. After, watch addr
	pending_wps map[uint64]PendingWp

	// Have already been set in an earlier round
	// Tainting vals disambiguates if we find new ones in later round
	done_wps map[DoneWp]TaintingVals

	// Set in this round (separate from done_wps to allow re-setting wp in a round)
	round_done_wps map[DoneWp]TaintingVals

	// Memory address => config/behavior values that taint it
	// Unlike done_wps, don't need PC - if memory is reused,
	// old entry will have gone OOS and been removed
	mem_param_map map[uint64]TaintingVals
}

/* If hit was in runtime, either ignore (e.g. newstack), or
 * record first non-runtime frame as line to check taint in
 * (can't assume that line will additionally have a non-runtime hit (e.g. some memmoves).
 * TODO in e.g. Printf, tainted line may be up the stack - analyze every non-runtime line?
 * Return false to ignore. */
func (tc *TaintCheck) handleRuntimeHit() (*api.Stackframe, bool) {
	stack, err := tc.client.Stacktrace(-1, 100, api.StacktraceSimple, &api.LoadConfig{})
	// TODO check for partially loaded (in any calls with LoadConfig)
	if err != nil {
		log.Fatalf("Error getting stacktrace: %v\n", err)
	}

	if strings.HasPrefix(stack[0].Function.Name(), "runtime") {
		fmt.Println("Runtime hit - partial stack (with PC one after hitting instr):")
		for i, frame := range stack {
			loc := fmt.Sprintf("%v \nLine %v:%v:0x%x",
				frame.File, frame.Line, frame.Function.Name(),
				frame.PC)
			fmt.Println(loc)

			// TODO skip hits from sysmon thread (sw wp commit may hv a test?)
			// What is the case when runtime.main hits again?
			if frame.Function.Name() == "runtime.newstack" || frame.Function.Name() == "runtime.main" {
				return nil, false
			}
			if !strings.HasPrefix(frame.Function.Name(), "runtime") {
				tc.hit.frame = i
				return &frame, true
			}

		}
	}

	return nil, true
}

/* Return false to ignore this hit. */
func (tc *TaintCheck) prevInstr(non_runtime_frame *api.Stackframe) bool {
	state, err := tc.client.GetState()
	if err != nil {
		log.Fatalf("Error getting state: %v\n", err)
	}

	// Hitting instr may be same or diff line as cur instr => get prev instr's line
	pc := state.CurrentThread.PC
	if non_runtime_frame != nil {
		// runtime hit
		pc = non_runtime_frame.PC
	}
	fct_instr, err := tc.client.DisassemblePC(api.EvalScope{GoroutineID: -1, Frame: tc.hit.frame}, pc, api.IntelFlavour) // dst, src
	if err != nil {
		log.Fatalf("Error disassembling at PC 0x%x: %v\n", pc, err)
	}

	// Ignore prints for convenience
	if strings.HasSuffix(fct_instr[0].Loc.File, "fmt/print.go") {
		return false
	}

	// TODO this assumes hitting instr is always linearly previous,
	// but not true for branching instr that touch memory (e.g. cmov)
	// Only applies to non-runtime hit?
	for i, instr := range fct_instr {
		if instr.Loc.PC == pc {
			tc.hit.hit_instr = &fct_instr[i-1]
			return true
		}
	}

	log.Fatalf("Failed to find instruction at PC 0x%x: %v\n", pc, err)
	return false
}

/* Get instruction and source line corresponding to preceding PC, for selected goroutine.
 * Return false to ignore this hit. */
func (tc *TaintCheck) hittingLine() bool {
	/* TODO for now, assume goroutine that hit the bp is currently selected.
	 * Should instead switch to that goroutine (need to read doc carefully:
	 * https://github.com/go-delve/delve/blob/master/Documentation/api/ClientHowto.md#using-rpcservercommand)
	 * (remember to pass that scope to Disass) */

	non_runtime_frame, handle := tc.handleRuntimeHit()
	if !handle || !tc.prevInstr(non_runtime_frame) {
		return false
	}

	src_line := sourceLine(tc.client, tc.hit.hit_instr.Loc.File, tc.hit.hit_instr.Loc.Line)

	if src_line == "" {
		log.Fatalf("No source line found for PC 0x%x\n", tc.hit.hit_instr.Loc.PC)
	}
	if strings.HasPrefix(src_line, "fmt.Print") {
		// Don't propagate into Print, for test convenience
		return false
	}

	fmt.Printf("\n\n*** Hit watchpoint for 0x%x at %v:%v (0x%x)\n", tc.hit.hit_bp.Addrs[0],
		tc.hit.hit_instr.Loc.File, tc.hit.hit_instr.Loc.Line, tc.hit.hit_instr.Loc.PC)
	fmt.Println(tc.hit.hit_instr.Loc.Function.Name())
	fmt.Println(src_line)
	fmt.Println(tc.hit.hit_instr.Text)
	return true
}

// Set bp for when wp will be in scope, record state
func (tc *TaintCheck) recordPendingWp(expr string, loc api.Location, argno *int) {
	// 1. Set breakpoint where pending watchpoint will be in scope
	bp_addr := loc.PCs[0]
	tc.setBp(bp_addr)

	// 2. Copy tainting values from hit watchpoint's to pending watchpoint
	// (or from config var, for config breakpoint)
	existing_info, existed := tc.pending_wps[bp_addr]

	if tc.hit.hit_bp != nil {
		// nil if config variable
		hit_wp_addr := tc.hit.hit_bp.Addrs[0]
		tainting_vals, ok := tc.mem_param_map[hit_wp_addr]
		if !ok {
			log.Fatalf("No mem-param map entry for watchpoint 0x%x\n", hit_wp_addr)
		}
		// TODO add test for append w/ realloc
		// TODO does append of a tainted value hit wp? (Currently is hitting bc of string concat and/or slice already being tainted)
		if existed && !reflect.DeepEqual(tainting_vals, existing_info.tainting_vals) {
			log.Fatalf("Pending wp already had an entry with different tainting values\n")
		}
		existing_info.tainting_vals = tainting_vals
	} else {
		tainting_param := TaintingParam{param: expr, flow: DataFlow}
		tainting_val := TaintingVals{params: map[TaintingParam]struct{}{tainting_param: {}}}
		existing_info.tainting_vals = tainting_val
	}

	if expr != "" {
		if len(existing_info.watchexprs) == 0 {
			existing_info.watchexprs = make(map[string]struct{})
		}
		existing_info.watchexprs[expr] = struct{}{}
		fmt.Printf("recordPendingWp: line %v, watchexpr %v, info %+v, bp addr 0x%x\n", loc.Line, expr, existing_info, bp_addr)
	}

	if argno != nil {
		if len(existing_info.watchargs) == 0 {
			existing_info.watchargs = make(map[int]struct{})
		}
		existing_info.watchargs[*argno] = struct{}{}
		fmt.Printf("recordPendingWp: line %v, argno %v, info %+v, bp addr 0x%x\n", loc.Line, *argno, existing_info, bp_addr)
	}

	tc.pending_wps[bp_addr] = existing_info
}

func (tc *TaintCheck) onPendingWpBpHitDone(bp_addr uint64) {
	info, ok := tc.pending_wps[bp_addr]
	if len(info.watchexprs) == 0 && len(info.watchargs) == 0 && len(info.watchaddrs) == 0 {
		// Nothing left pending at this bp addr
		if _, err := tc.client.ClearBreakpoint(tc.hit.hit_bp.ID); err != nil {
			log.Fatalf("Failed to clear bp at 0x%x: %v\n", bp_addr, err)
		}
		delete(tc.pending_wps, bp_addr)
	}

	if ok {
		fmt.Printf("ZZEM exit onPendingWpBpHitDone; info %v\n", info)
	} else {
		fmt.Printf("ZZEM exit onPendingWpBpHitDone; no more info\n")
	}
}

// Eval watchexpr, return addr(s) to set watch on, delete expr from pending
func (tc *TaintCheck) evalWatchexpr(watchexpr *string, bp_addr uint64, watcharg *int) []api.Variable {
	watchvars := []api.Variable{}
	scope := api.EvalScope{GoroutineID: -1, Frame: tc.hit.frame}
	xv, err := tc.client.EvalWatchexpr(scope, *watchexpr)
	if err != nil {
		log.Fatalf("Failed to eval new watchexpr %v: err %v, xv %+v\n", watchexpr, err, xv)
	}
	if watcharg != nil {
		delete(tc.pending_wps[bp_addr].watchargs, *watcharg)
	} else {
		delete(tc.pending_wps[bp_addr].watchexprs, *watchexpr)
	}
	watchvars = append(watchvars, *xv)
	if xv.RealType == "string" {
		// Also watch the first character of a string - string concatenation doesn't read the address
		xv, err := tc.client.EvalWatchexpr(scope, *watchexpr+"[0]")
		if err != nil {
			log.Fatalf("Failed to eval first byte of string %v: err %v, xv %+v\n", watchexpr, err, xv)
		}
		watchvars = append(watchvars, *xv)
	}

	return watchvars
}

// This should handle being called multiple times for same bpaddr+watchaddr
func (tc *TaintCheck) trySetWatchpoint(watchexpr *string, bp_addr uint64, watchaddr *uint64, sz int64) {
	fmt.Printf("trySetWatchpoint\n")
	if watchexpr != nil {
		fmt.Printf("watchexpr: %v\n", *watchexpr)
	}
	if watchaddr != nil {
		fmt.Printf("watchaddr: %x\n", *watchaddr)
	}

	wp := DoneWp{bp_addr: bp_addr, wp_addr: *watchaddr}
	info := tc.pending_wps[bp_addr]

	// 1. Check for dups
	// Must do before CreateWatchpoint, since rr can't handle dups (#3777)
	// TODO add test for both these dup types
	if done_wp, ok := tc.done_wps[wp]; ok {
		if reflect.DeepEqual(done_wp, info.tainting_vals) {
			// Already traced this addr in a previous round and found same tainting vals => return
			fmt.Printf("Already traced 0x%x in previous round\n", *watchaddr)
			return
		}
	}
	if _, ok := tc.mem_param_map[*watchaddr]; ok {
		// Already currently tracing this addr => update mem-param map with any new tainting vals, return
		tc.updateTaintingVals(info, bp_addr, *watchaddr)
		fmt.Printf("Already tracing 0x%x in current round\n", *watchaddr)
		return
	}

	// 2. Check if have hardware watchpoints available, else store watchaddr and return
	if tc.nWps() == 4 {
		// Stays pending
		if watchexpr != nil {
			// Just evaluated => add new watchaddr
			if len(info.watchaddrs) == 0 {
				info.watchaddrs = make(map[uint64]int64)
			}
			info.watchaddrs[*watchaddr] = sz
			tc.pending_wps[bp_addr] = info
			// Log for test (alternative is to store watchexpr - would also allow us to pass it to delve,
			// which would be convenient but require more storage)
			fmt.Printf("Hardware-pending createWatchpoint: line %v, watchexpr %v, watchaddr 0x%x\n",
				tc.hit.hit_bp.Line, *watchexpr, *watchaddr)
		}
		return
	}

	// 3. Create watchpoint
	// We really want a read-only wp, but rr's read-only hw wp are actually read-write
	scope := api.EvalScope{GoroutineID: -1, Frame: tc.hit.frame}
	// TODO (minor): fix error propagation here: if rr returns E01 (in gdbserial), logs "expected operand" here
	created_wp, err := tc.client.CreateWatchpointNoEval(scope, *watchaddr, sz, api.WatchRead|api.WatchWrite)
	if err != nil {
		log.Fatalf("Failed to set watchpoint at 0x%x: %v\n", *watchaddr, err)
	}

	if watchexpr != nil {
		// Log for test
		// TODO (minor): Move logic in this file to its own package, so can import it for testing
		// Also put test logging in a log separate from stdout which can be turned off for non-testing purposes
		fmt.Printf("CreateWatchpoint: line %v, watchexpr %v, watchaddr 0x%x\n",
			tc.hit.hit_bp.Line, *watchexpr, *watchaddr)
	} else {
		fmt.Printf("CreateWatchpoint (was hardware-pending): line %v, watchaddr 0x%x\n",
			tc.hit.hit_bp.Line, *watchaddr)
	}
	delete(tc.pending_wps[bp_addr].watchaddrs, *watchaddr)
	tc.round_done_wps[wp] = info.tainting_vals

	// 5. Add to mem-param map
	tc.mem_param_map[created_wp.Addrs[0]] = info.tainting_vals
	// Log for testing
	fmt.Printf("\tMemory-parameter map: 0x%x => %+v\n", created_wp.Addrs[0], info.tainting_vals)
}

// Watchpoint hit => record any new pending watchpoints
func (tc *TaintCheck) onWatchpointHit() {
	if !tc.hittingLine() {
		fmt.Printf("Ignoring watchpoint hit\n")
		return
	}
	tc.propagateTaint()
}

// Breakpoint for pending watchpoint hit => try to set the watchpoint
func (tc *TaintCheck) onPendingWpBpHit() {
	if len(tc.hit.hit_bp.Addrs) != 1 {
		log.Fatalf("Wrong number of addrs at pending wp; addrs %v\n", tc.hit.hit_bp.Addrs)
	}
	bp_addr := tc.hit.hit_bp.Addrs[0]
	info := tc.pending_wps[bp_addr]
	if len(info.watchexprs) == 0 && len(info.watchargs) == 0 && len(info.watchaddrs) == 0 {
		log.Fatalf("No pending watches found after hitting 0x%x\n", bp_addr)
	}

	fmt.Printf("\n\n*** Hit pending wp breakpoint at %v:%v (0x%x)\n", tc.hit.hit_bp.File, tc.hit.hit_bp.Line, bp_addr)

	for watchaddr, sz := range info.watchaddrs {
		tc.trySetWatchpoint(nil, bp_addr, &watchaddr, sz)
	}
	for watchexpr := range info.watchexprs {
		watchvars := tc.evalWatchexpr(&watchexpr, bp_addr, nil)
		for _, watchvar := range watchvars {
			tc.trySetWatchpoint(&watchexpr, bp_addr, &watchvar.Addr, watchvar.Watchsz)
		}
	}
	scope := api.EvalScope{GoroutineID: -1, Frame: tc.hit.frame}
	for argno := range info.watchargs {
		args, err := tc.client.ListFunctionArgs(scope, api.LoadConfig{})
		if err != nil {
			log.Fatalf("Failed to list function args at 0x%x: %v\n", bp_addr, err)
		}
		watchexpr := args[argno].Name
		watchvars := tc.evalWatchexpr(&watchexpr, bp_addr, &argno)
		for _, watchvar := range watchvars {
			tc.trySetWatchpoint(&watchexpr, bp_addr, &watchvar.Addr, watchvar.Watchsz)
		}
	}

	// cleanup
	tc.onPendingWpBpHitDone(bp_addr)
}
