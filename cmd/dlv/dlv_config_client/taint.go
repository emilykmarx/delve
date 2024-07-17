package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"log"
	"strings"

	"github.com/go-delve/delve/service/api"
	"github.com/go-delve/delve/service/rpc2"
)

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
	watchexprs []string
	watchargs  []int
	watchaddrs []uint64
}

type TaintCheck struct {
	hit    Hit
	client *rpc2.RPCClient

	// "Pending" = waiting for var to be in scope, or for hw wp to free up
	// Key: Bp addr where exprs go in scope
	// Value: Before hit corresp bp in any round, expr info. After, watch addr
	pending_wps map[uint64]PendingWp

	// Have already been set in an earlier round
	done_wps map[DoneWp]bool

	// Set in this round (separate from done_wps to allow re-setting wp in a round)
	round_done_wps map[DoneWp]bool
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

	// Ignore prints for convenience; cpu.doinit was from delve bug that maintained OOS wp on restart, could likely remove
	if strings.HasSuffix(fct_instr[0].Loc.File, "fmt/print.go") || strings.Contains(fct_instr[0].Loc.Function.Name(), "cpu.doinit") {
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
	hit_loc := fmt.Sprintf("%v \nLine %v:%v:0x%x \n%v \n%v",
		tc.hit.hit_instr.Loc.File, tc.hit.hit_instr.Loc.Line, tc.hit.hit_instr.Loc.Function.Name(),
		tc.hit.hit_instr.Loc.PC, tc.hit.hit_instr.Text, src_line)

	fmt.Printf("\nHit watchpoint for %v (0x%x), at:\n%v\n", tc.hit.hit_bp.WatchExpr, tc.hit.hit_bp.Addr, hit_loc)
	return true
}

// Get the ith lhs of an assignment on lineno
// TODO test "_"
func getLhs(i int, file string, lineno int) (lhs *ast.Expr) {
	fset := token.NewFileSet()
	root, err := parser.ParseFile(fset, file, nil, parser.SkipObjectResolution)
	if err != nil {
		log.Fatalf("Failed to parse source file %v: %v\n", file, err)
	}

	ast.Inspect(root, func(node ast.Node) bool {
		cur_line := -1
		if node != nil {
			cur_line = fset.Position(node.Pos()).Line
		}
		if cur_line != lineno {
			return true
		}

		switch typed_node := node.(type) {
		case *ast.AssignStmt:
			lhs = &typed_node.Lhs[i]

		case *ast.RangeStmt:
			lhs = &typed_node.Value

		}
		return true
	})

	return lhs
}

/* Expr involves memory that overlaps the watched region,
 * ignoring function args (except builtins).
 * Requires expr to be in scope. */
func (tc *TaintCheck) isTainted(expr ast.Expr) bool {
	loadcfg := api.LoadConfig{FollowPointers: true}
	is_tainted := false

	ast.Inspect(expr, func(node ast.Node) bool {
		if is_tainted {
			return false // we're done
		}
		if node == nil {
			return true
		}
		switch typed_node := node.(type) {
		case *ast.CallExpr:
			if tc.handleBuiltinFct(typed_node) {
				is_tainted = true
			}
			return false
		default:
			// TODO check for incomplete loads (see client API doc)
			xv, err := tc.client.EvalVariable(api.EvalScope{GoroutineID: -1, Frame: tc.hit.frame}, exprToString(node.(ast.Expr)), loadcfg)
			if err != nil || xv.Addr == 0 { // Addr == 0 for e.g. x + 1, but not e.g. x[1]
				// Try evaluating any children
			} else {
				for _, watch_addr := range tc.hit.hit_bp.Addrs {
					// TODO get these sizes (once support tainted composite types in delve) - bp UserData?
					// For now, overapproximate
					watch_size := uint64(8)
					xv_size := uint64(8)

					// TODO the first-byte wp should go out of scope with string (currently doesn't bc on heap)
					if xv.RealType == "string" && memOverlap(xv.Base, 1, watch_addr, watch_size) {
						// For strings, wp may hit for first byte only, not for pointer
						is_tainted = true
					}

					if memOverlap(xv.Addr, xv_size, watch_addr, watch_size) {
						is_tainted = true
					}
				}

				// Don't evaluate children
				// (at least for Index and Selector - haven't thought through others)
				return false
			}
		}
		return true
	})

	return is_tainted
}

// If calling line has an assign or range, return corresp lhs and the next line's location
// (TODO same caveats about linear assumption as for Assign)
func (tc *TaintCheck) callerLhs(i int) (*ast.Expr, api.Location) {
	stack, err := tc.client.Stacktrace(-1, 100, api.StacktraceSimple, &api.LoadConfig{})
	if err != nil {
		log.Fatalf("Error getting stacktrace: %v\n", err)
	}
	call_file := stack[1].File
	call_line := stack[1].Line
	fmt.Printf("callerLhs returning loc %v:%v\n", call_file, call_line)
	next_line := tc.lineWithStmt(nil, call_file, call_line+1)
	return getLhs(i, call_file, call_line), next_line
}

/* Assuming this line hits hit_bp, propagate taint to other exprs on line.
 * Accounts for aliased reads (i.e. those that don't match hit_bp.WatchExpr).
*  Return cleared wp if we ended up propagating. */
func (tc *TaintCheck) propagateTaint() {
	fset := token.NewFileSet()
	root, err := parser.ParseFile(fset, tc.hit.hit_instr.Loc.File, nil, parser.SkipObjectResolution)
	if err != nil {
		log.Fatalf("Failed to parse source file %v: %v\n", tc.hit.hit_instr.Loc.File, err)
	}

	// DFS of file's AST
	ast.Inspect(root, func(node ast.Node) bool {
		// PERF: How to properly only inspect one line?
		var pos token.Position
		if node != nil {
			pos = fset.Position(node.Pos())
		}
		if pos.Line != tc.hit.hit_instr.Loc.Line {
			return true
		}

		switch typed_node := node.(type) {

		case *ast.CallExpr:
			if handledBuiltins[exprToString(typed_node.Fun)] {
				return false // will be handled in assign/range
			}
			if exprToString(typed_node.Fun) == "runtime.KeepAlive" {
				return false
			}
			for i, arg := range typed_node.Args {
				if tc.isTainted(arg) {
					// First line of function body (params are "fake" at declaration line)
					fn := exprToString(typed_node.Fun)
					pending_loc := tc.lineWithStmt(&fn, "", -1)
					tc.recordPendingWp(nil, nil, pending_loc, &i)
				}
			}

		case *ast.ReturnStmt:
			// Watched location is read in return value =>
			// taint corresponding assign lhs/range value in caller, if any
			// TODO handle function composition (for builtins too - will need diff handling)
			for i, ret := range typed_node.Results {
				if tc.isTainted(ret) {
					caller_lhs, caller_loc := tc.callerLhs(i)
					if caller_lhs != nil {
						// Line after calling line
						// TODO now that recordPendingWp is idempotent, can elim loops in other cases too
						tc.recordPendingWp([]ast.Expr{*caller_lhs}, nil, caller_loc, nil)
					}
				}
			}

		// May not be next line linearly for := in flow control statement
		// but if not, var immediately went out of scope so we don't need a wp anyway
		// TODO except for if/else, maybe others
		// And Range: If next line is }, set on next iter
		case *ast.AssignStmt:
			hit_rhs := false
			for _, rhs := range typed_node.Rhs {
				// TODO properly handle multiple rhs (unsure of semantics)
				if tc.isTainted(rhs) {
					hit_rhs = true
				}
			}
			if hit_rhs {
				// Watched location is read on the rhs =>
				// taint lhs
				pending_loc := tc.lineWithStmt(nil, pos.Filename, pos.Line+1)
				tc.recordPendingWp(typed_node.Lhs, nil, pending_loc, nil)
			}
		case *ast.RangeStmt:
			// TODO handle Range properly (once support tainted composite types in delve):
			// If only part of the rhs is tainted, value expr should only be tainted on corresp iters
			if tc.isTainted(typed_node.X) && typed_node.Value != nil {
				// Watched location is read on the rhs =>
				// taint value expr
				pending_loc := tc.lineWithStmt(nil, pos.Filename, pos.Line+1)
				tc.recordPendingWp([]ast.Expr{typed_node.Value}, nil, pending_loc, nil)
			}
		} // end switch

		return true
	})
}

// Find the next line on or after this one with a statement, so we can set a bp.
// May want to consider doing this with PC when handle the non-linear stuff
func (tc *TaintCheck) lineWithStmt(fn *string, file string, lineno int) api.Location {
	var loc string
	if fn != nil {
		locs, _, err := tc.client.FindLocation(api.EvalScope{GoroutineID: -1, Frame: tc.hit.frame}, *fn, true, nil)
		if err != nil {
			log.Fatalf("Error finding location: %v\n", err)
		}
		file = locs[0].File
		lineno = locs[0].Line + 1
	}

	for { // TODO make loop safer
		loc = fmt.Sprintf("%v:%v", file, lineno)
		// TODO(minor): how to pass in substitutePath rules? (2nd ret is related)
		// Lines with instr only
		locs, _, err := tc.client.FindLocation(api.EvalScope{GoroutineID: -1, Frame: tc.hit.frame}, loc, true, nil)
		if len(locs) == 1 {
			return locs[0]
		}
		if err != nil && !strings.HasPrefix(err.Error(), "could not find statement") {
			log.Fatalf("Error finding location: %v\n", err)
		}
		if len(locs) > 1 || (len(locs) > 0 && len(locs[0].PCs) != 1) {
			// Unsure when this would happen - don't support for now
			log.Fatalf("Too many locations: %v\n", locs)
		}
		lineno += 1
	}
}

func (tc *TaintCheck) setBp(addr uint64) {
	bp := api.Breakpoint{Addrs: []uint64{addr}}
	if _, err := tc.client.CreateBreakpoint(&bp); err != nil {
		if !strings.HasPrefix(err.Error(), "Breakpoint exists at") {
			log.Fatalf("Failed to create breakpoint at %v: %v\n", addr, err)
		}
	}
}

// TODO remove expr_strs once unused
// Set bp for when wp will be in scope, record state
func (tc *TaintCheck) recordPendingWp(exprs []ast.Expr, expr_strs []string, loc api.Location, argno *int) {
	addr := loc.PCs[0]
	tc.setBp(addr)

	for _, expr := range exprs {
		expr_str := exprToString(expr)
		expr_strs = append(expr_strs, expr_str)
	}
	// TODO add test for append w/ realloc
	// TODO does append of a tainted value hit wp? (Currently is hitting bc of string concat and/or slice already being tainted)
	for _, expr_str := range expr_strs {
		existing_info := tc.pending_wps[addr]
		existing_info.watchexprs = append(existing_info.watchexprs, expr_str)
		tc.pending_wps[addr] = existing_info
		fmt.Printf("recordPendingWp: line %v, watchexpr %v, bp addr 0x%x\n", loc.Line, expr_str, addr)
	}
	if argno != nil {
		existing_info := tc.pending_wps[addr]
		existing_info.watchargs = append(existing_info.watchargs, *argno)
		tc.pending_wps[addr] = existing_info
		fmt.Printf("recordPendingWp: line %v, argno %v, bp addr 0x%x\n", loc.Line, *argno, addr)
	}
}

func (tc *TaintCheck) onBreakpointHitDone(bp_addr uint64) {
	info, ok := tc.pending_wps[bp_addr]
	if len(info.watchexprs) == 0 && len(info.watchargs) == 0 && len(info.watchaddrs) == 0 {
		// Nothing left pending at this bp addr
		if _, err := tc.client.ClearBreakpoint(tc.hit.hit_bp.ID); err != nil {
			log.Fatalf("Failed to clear bp at 0x%x: %v\n", bp_addr, err)
		}
		delete(tc.pending_wps, bp_addr)
	}

	if ok {
		fmt.Printf("ZZEM exit onBreakpointHitDone; info %v\n", info)
	} else {
		fmt.Printf("ZZEM exit onBreakpointHitDone; no more info\n")
	}
}

// This should handle being called multiple times for same bpaddr+watchaddr
func (tc *TaintCheck) trySetWatchpoint(watchexpr *string, bp_addr uint64, watchaddr *uint64, watcharg *int) {
	fmt.Printf("ZZEM enter trySetWatchpoint, bp_addr 0x%x\n", bp_addr)
	if watchexpr != nil {
		fmt.Printf("watchexpr %v\n", *watchexpr)
	}
	if watchaddr != nil {
		fmt.Printf("watchaddr 0x%x\n", *watchaddr)
	}

	fmt.Println("wps:")
	bps_prev, list_err := tc.client.ListBreakpoints(true)
	if list_err != nil {
		log.Fatalf("Error listing breakpoints: %v\n", list_err)
	}
	for _, bp := range bps_prev {
		if bp.WatchExpr != "" {
			fmt.Printf("0x%x\n", bp.Addr)
		}
	}

	scope := api.EvalScope{GoroutineID: -1, Frame: tc.hit.frame}
	if watchexpr != nil {
		loadcfg := api.LoadConfig{FollowPointers: true}
		xv, err := tc.client.EvalVariable(scope, *watchexpr, loadcfg)
		if err != nil || xv.Addr == 0 {
			log.Fatalf("Failed to eval new watchexpr %v: err %v, xv %+v\n", watchexpr, err, xv)
		}
		if watcharg != nil {
			tc.deleteWatchArg(*watcharg, bp_addr)
		} else {
			tc.deleteWatchExpr(*watchexpr, bp_addr)
		}
		watchaddr = &xv.Addr
	}

	wp := DoneWp{bp_addr: bp_addr, wp_addr: *watchaddr}
	if tc.done_wps[wp] {
		// Already traced this addr in a previous round
		fmt.Printf("Already traced in prev round\n") // TODO add test for this
		tc.deleteWatchAddr(*watchaddr, bp_addr)
		return
	}

	// We really want a read-only wp, but rr's read-only hw wp are actually read-write

	var created_wp *api.Breakpoint
	var wp_err error
	if watchexpr != nil {
		// TODO (minor): fix error propagation here: if rr returns E01 (in gdbserial), logs "expected operand" here
		created_wp, wp_err = tc.client.CreateWatchpoint(scope, *watchexpr, api.WatchRead|api.WatchWrite)
	} else {
		// TODO proper size
		created_wp, wp_err = tc.client.CreateWatchpointNoEval(scope, *watchaddr, 8, api.WatchRead|api.WatchWrite)
	}
	existed := false
	if wp_err != nil {
		if !strings.HasPrefix(wp_err.Error(), "Breakpoint exists at") {
			// Check # of wp after create, since it may have been a dup
			if tc.nWps() == 4 {
				// Stays pending
				fmt.Printf("Ran out of hw wp; staying pending\n")
				if watchexpr != nil {
					// Just evaluated => add new watchaddr
					info := tc.pending_wps[bp_addr]
					info.watchaddrs = append(info.watchaddrs, *watchaddr)
					tc.pending_wps[bp_addr] = info
					// Log for test (alternative is to store watchexpr - would also allow us to pass it to delve,
					// which would be convenient but require more storage)
					fmt.Printf("Hardware-pending createWatchpoint: line %v, watchexpr %v, watchaddr 0x%x\n",
						tc.hit.hit_bp.Line, *watchexpr, *watchaddr)
				}
				return
			} else {
				log.Fatalf("Failed to set watch for %v (0x%x): %v\n", watchexpr, *watchaddr, wp_err)
			}
		} else {
			existed = true
			fmt.Printf("ZZEM wp existed\n")
		}
	}

	if !existed {
		if watchexpr != nil {
			// Log for test
			// TODO (minor): Move logic in this file to its own package, so can import it for testing
			fmt.Printf("CreateWatchpoint: line %v, watchexpr %v\n", tc.hit.hit_bp.Line, *watchexpr)
		} else {
			fmt.Printf("CreateWatchpoint (was hardware-pending): line %v, watchaddr 0x%x\n",
				tc.hit.hit_bp.Line, *watchaddr)
		}
		fmt.Printf("ZZEM created wp at 0x%x\n", created_wp.Addrs[0])
	}
	tc.deleteWatchAddr(*watchaddr, bp_addr)
	tc.round_done_wps[wp] = true
}

// Watchpoint hit => record any new pending watchpoints
func (tc *TaintCheck) onWatchpointHit() {
	if !tc.hittingLine() {
		fmt.Printf("Ignoring\n")
		return
	}
	tc.propagateTaint()
}

// Breakpoint for pending watchpoint hit => try to set the watchpoint
func (tc *TaintCheck) onBreakpointHit() {
	if len(tc.hit.hit_bp.Addrs) != 1 {
		log.Fatalf("Wrong number of addrs at pending wp; addrs %v\n", tc.hit.hit_bp.Addrs)
	}
	bp_addr := tc.hit.hit_bp.Addrs[0]
	info := tc.pending_wps[bp_addr]
	if len(info.watchexprs) == 0 && len(info.watchargs) == 0 && len(info.watchaddrs) == 0 {
		log.Fatalf("No pending watches found after hitting 0x%x\n", bp_addr)
	}

	fmt.Printf("ZZEM onBreakpointHit, bp addr 0x%x\nInfo %v\n", bp_addr, info)

	for _, watchaddr := range info.watchaddrs {
		tc.trySetWatchpoint(nil, bp_addr, &watchaddr, nil)
	}
	for _, watchexpr := range info.watchexprs {
		tc.trySetWatchpoint(&watchexpr, bp_addr, nil, nil)
	}
	scope := api.EvalScope{GoroutineID: -1, Frame: tc.hit.frame}
	for _, argno := range info.watchargs {
		args, err := tc.client.ListFunctionArgs(scope, api.LoadConfig{})
		if err != nil {
			log.Fatalf("Failed to list function args at 0x%x: %v\n", bp_addr, err)
		}
		tc.trySetWatchpoint(&args[argno].Name, bp_addr, nil, &argno)
	}

	// cleanup
	tc.onBreakpointHitDone(bp_addr)
}
