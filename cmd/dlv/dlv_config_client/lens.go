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

// Things that should be reset for each hit
type Hit struct {
	hit_bp    *api.Breakpoint
	hit_instr *api.AsmInstruction
	// Frame to check taint in (first non-runtime frame)
	frame int
}

// If add any fields, update String()
type PendingWp struct {
	watchexprs map[string]struct{}
	// Arg index => Expression to append to callee's copy, if any
	watchargs map[int]string
	// Values that tainted these
	// (With current taint policy, I think will always be same for all).
	// On wp hit: Copy from mem_param_map[hit], so we have them even if orig wp goes OOS
	// and/or we start a new round before setting the pending wp
	tainting_vals TaintingVals
}

type TaintCheck struct {
	hit    Hit
	client *rpc2.RPCClient
	thread *api.Thread

	// "Pending" = waiting for var to be in scope, or for hw wp to free up
	// Key: Bp addr where exprs go in scope
	// Value: Before hit corresp bp in any round, expr info. After, watch addr
	pending_wps map[uint64]PendingWp

	// Memory address => config/behavior values that taint it
	// Don't need PC to disambiguate - if memory is reused,
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
		fmt.Println("Runtime watchpoint hit - partial stack (including first non-runtime frame, whose PC is one after call instr)")
		for i, frame := range stack {
			fn := frame.Function.Name()
			loc := fmt.Sprintf("%v \nLine %v:%v:0x%x",
				frame.File, frame.Line, fn, frame.PC)
			fmt.Println(loc)

			// TODO skip all hits from go runtime threads (sw wp commit may hv a test for sysmon?)
			// (but not hits in go runtime from program thread)
			if fn == "runtime.newstack" {
				fmt.Println("newstack")
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
		log.Fatalf("Error disassembling at PC 0x%x: %v\n", pc, err)
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

	log.Fatalf("Failed to find instruction at PC 0x%x: %v\n", pc, err)
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

	if src_line == "" {
		log.Fatalf("No source line found for PC 0x%x\n", tc.hit.hit_instr.Loc.PC)
	}

	fmt.Printf("Location:\n %v:%v (0x%x)\n",
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
			if tainting_vals_ := tc.updateMovedWps(hit_wp_addr); tainting_vals_ == nil {
				log.Fatalf("No mem-param map entry for watchpoint 0x%x\n", hit_wp_addr)
			} else {
				tainting_vals = *tainting_vals_
			}
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

	if argno != nil {
		if len(existing_info.watchargs) == 0 {
			existing_info.watchargs = make(map[int]string)
		}
		existing_info.watchargs[*argno] = expr
		fmt.Printf("recordPendingWp: line %v, argno %v, info %+v, bp addr 0x%x\n", loc.Line, *argno, existing_info, bp_addr)
	} else {
		if len(existing_info.watchexprs) == 0 {
			existing_info.watchexprs = make(map[string]struct{})
		}
		existing_info.watchexprs[expr] = struct{}{}
		fmt.Printf("recordPendingWp: line %v, watchexpr %v, info %+v, bp addr 0x%x\n", loc.Line, expr, existing_info, bp_addr)
	}

	tc.pending_wps[bp_addr] = existing_info
}

func (tc *TaintCheck) onPendingWpBpHitDone(bp_addr uint64) {
	info := tc.pending_wps[bp_addr]
	if len(info.watchexprs) == 0 && len(info.watchargs) == 0 {
		// Nothing left pending at this bp addr
		if _, err := tc.client.ClearBreakpoint(tc.hit.hit_bp.ID); err != nil {
			log.Fatalf("Failed to clear bp at 0x%x: %v\n", bp_addr, err)
		}
		delete(tc.pending_wps, bp_addr)
	}

	fmt.Printf("Exit onPendingWpBpHitDone; info %v\n", info)
}

// Set watchpoint given a variable - TODO fix comment
func (tc *TaintCheck) setWatchpointXv(watchexpr string, xv *api.Variable, bp_addr uint64, create bool) {
	fmt.Printf("setWatchpoint on %v (%#x, sz %v)\n", xv.Name, xv.Addr, xv.Watchsz)

	info := tc.pending_wps[bp_addr]

	// 2. Check for dups
	// TODO check have a test for this
	if _, ok := tc.mem_param_map[xv.Addr]; ok {
		// Already currently tracing this addr => update mem-param map with any new tainting vals, return
		tc.updateTaintingVals(info, bp_addr, xv.Addr)
		// May have already been set when hit same wp at different bp in this round
		// (e.g. when try to set wp on first byte of a copied string - as with fqdn[0] in xenon)
		fmt.Printf("Already tracing 0x%x in current round\n", xv.Addr)
		return
	}

	// 3. Create watchpoint (if not dup)
	// We really want a read-only wp, but not supported
	if create {
		scope := api.EvalScope{GoroutineID: -1, Frame: tc.hit.frame}
		_, err := tc.client.CreateWatchpointNoEval(scope, watchexpr, xv.Addr, xv.Watchsz, api.WatchRead|api.WatchWrite, api.WatchSoftware)
		if err != nil {
			log.Fatalf("Failed to set watchpoint at 0x%x: %v\n", xv.Addr, err)
		}
	}

	// Log for testing
	// TODO (minor): Move logic in this file to its own package, so can import it for testing
	// Also put test logging in a log separate from stdout which can be turned off for non-testing purposes
	fmt.Printf("CreateWatchpoint lineno %d watchexpr %s watchaddr 0x%x\n",
		tc.hit.hit_bp.Line, watchexpr, xv.Addr)

	// 4. Add to mem-param map
	tc.mem_param_map[xv.Addr] = info.tainting_vals
	// Log for testing
	fmt.Printf("\tMemory-parameter map: 0x%x => %+v\n", xv.Addr, info.tainting_vals)
}

// Set any watchpoint(s) corresponding to watchexpr
func (tc *TaintCheck) setWatchpoint(watchexpr string, bp_addr uint64) {
	// Eval watchexpr to get address for dup check
	scope := api.EvalScope{GoroutineID: -1, Frame: tc.hit.frame}
	xv, err := tc.client.EvalWatchexpr(scope, watchexpr)
	if err.Error() == "slice of strings" {
		// LEFT OFF: awk how things are passed from debugger to client --
		// err isn't proc.SliceOfStrings bc doesn't have sliceXv, and
		// if err != nil, server passes nil xv
		//if slice, ok := err.(proc.SliceOfStrings); ok {
		fmt.Println("client: SOS")
		log.Printf("err: %+v\n", err)
		log.Printf("xv: %+v\n", xv)
		// Watch each string's characters
		for i := 0; i < int(slice.Slicexv.Len); i++ {
			string_elem := fmt.Sprintf("%v[%v]", watchexpr, i)
			string_xv, err := tc.client.EvalWatchexpr(scope, string_elem)
			if err != nil {
				log.Fatalf("Failed to eval new watchexpr %v: err %v, xv %+v\n", watchexpr, err, xv)
			}
			tc.setWatchpointXv(watchexpr, string_xv, bp_addr, false)
		}
		// Server handles creating wp on each string
		_, err := tc.client.CreateWatchpoint(scope, watchexpr, api.WatchRead|api.WatchWrite, api.WatchSoftware)
		if err != nil {
			log.Fatalf("Failed to set watchpoint at 0x%x: %v\n", xv.Addr, err)
		}
	} else if err != nil {
		log.Fatalf("Failed to eval new watchexpr %v: err %v, xv %+v\n", watchexpr, err, xv)
	} else {
		tc.setWatchpointXv(watchexpr, xv, bp_addr, true)
	}
}

// Watchpoint hit => record any new pending watchpoints
func (tc *TaintCheck) onWatchpointHit() {
	fmt.Printf("\n\n*** Hit watchpoint for 0x%x\n", tc.hit.hit_bp.Addrs[0])
	if !tc.hittingLine() {
		fmt.Printf("Ignoring watchpoint hit at %#x\n", tc.thread.PC)
		return
	}
	tc.propagateTaint()
}

// Breakpoint for pending watchpoint hit => try to set the watchpoint
func (tc *TaintCheck) onPendingWpBpHit() {
	if len(tc.hit.hit_bp.Addrs) != 1 {
		log.Fatalf("Wrong number of addrs at pending wp; bp %+v\n", tc.hit.hit_bp)
	}

	bp_addr := tc.hit.hit_bp.Addrs[0]
	info := tc.pending_wps[bp_addr]
	fmt.Printf("\n\n*** Hit pending wp breakpoint at %v:%v (0x%x)\n", tc.hit.hit_bp.File, tc.hit.hit_bp.Line, bp_addr)
	if len(info.watchexprs) == 0 && len(info.watchargs) == 0 {
		log.Fatalf("No pending watches found after hitting 0x%x\n", bp_addr)
	}

	// Just wanted to hit and remove the breakpoint, not set watchpoint
	if _, ok := info.watchexprs[""]; ok {
		delete(tc.pending_wps[bp_addr].watchexprs, "")
		tc.onPendingWpBpHitDone(bp_addr)
		return
	}

	for watchexpr := range info.watchexprs {
		delete(tc.pending_wps[bp_addr].watchexprs, watchexpr)
		tc.setWatchpoint(watchexpr, bp_addr)
	}
	scope := api.EvalScope{GoroutineID: -1, Frame: tc.hit.frame}
	for argno, overlap_expr := range info.watchargs {
		delete(tc.pending_wps[bp_addr].watchargs, argno)
		args, err := tc.client.ListFunctionArgs(scope, api.LoadConfig{})
		if err != nil {
			log.Fatalf("Failed to list function args at 0x%x: %v\n", bp_addr, err)
		}
		watchexpr := args[argno].Name + overlap_expr
		tc.setWatchpoint(watchexpr, bp_addr)
	}

	// cleanup
	tc.onPendingWpBpHitDone(bp_addr)
}
