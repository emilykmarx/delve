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

type watchpoint struct {
	bp_addr uint64
	wp_addr uint64
}

type Hit struct {
	// Scope: per hit
	hit_bp    *api.Breakpoint
	hit_instr *api.AsmInstruction
	// Frame to check taint in (first non-runtime frame)
	frame int
}

// TODO remove unused stuff, update comments on all fcts
type TaintCheck struct {
	hit    Hit
	client *rpc2.RPCClient

	// LEFT OFF: need to store addr w/ wp waiting for hw, to handle e.g. loop

	// "Pending" = waiting for var to be in scope, or for hw wp to free up
	// Addr to set at => watchexpr
	pending_watchexpr map[uint64][]string
	// Addr to set at => argno
	pending_watchargs map[uint64][]int

	// Have already been set in an earlier round
	done_wps map[watchpoint]bool

	// Set in this round (separate from done_wps to allow re-setting wp in a round)
	round_done_wps map[watchpoint]bool
}

/* If hit was in runtime, stepout to the first non-runtime function.
 * Check that line for taint as usual.
 * TODO in e.g. Printf, tainted line may be up the stack - analyze every non-runtime line?
 * Return false to ignore this hit. */
func (tc *TaintCheck) handleRuntimeHit() (*api.Stackframe, bool) {
	// Check for runtime function
	stack, err := tc.client.Stacktrace(-1, 100, api.StacktraceSimple, &api.LoadConfig{})
	// TODO check for partially loaded (in any calls with LoadConfig)
	if err != nil {
		log.Fatalf("Error getting stacktrace: %v\n", err)
	}

	/* This assumes runtime function was called implicitly (e.g. newstack/memmove),
	 * so doesn't create new vars and doesn't propagate taint via return.
	 * TODO eventually consider explicit runtime calls */
	if strings.HasPrefix(stack[0].Function.Name(), "runtime") {
		fmt.Println("Runtime hit - runtime portion of stack (with PC one after hitting instr):")
		for i, frame := range stack {
			if frame.Function.Name() == "runtime.newstack" || frame.Function.Name() == "runtime.main" {
				fmt.Printf("Hit in runtime.newstack or runtime.main\n")
				return nil, false
			}
			if !strings.HasPrefix(frame.Function.Name(), "runtime") {
				tc.hit.frame = i
				return &frame, true
			}

			loc := fmt.Sprintf("%v \nLine %v:%v:0x%x",
				frame.File, frame.Line, frame.Function.Name(),
				frame.PC)
			fmt.Println(loc)
		}
	}

	return nil, true
}

/* If non-runtime, stepout takes us to the instr next in linear stream after call.
 * Return false to ignore this hit. */
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

	if strings.HasSuffix(fct_instr[0].Loc.File, "fmt/print.go") || strings.Contains(fct_instr[0].Loc.Function.Name(), "cpu.doinit") {
		return false
	}

	// There aren't any branching instr that touch memory, right?
	// So hitting instr should always be linearly previous?
	// (Or for runtime hit, frame is function that called runtime)
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
 * If hit in runtime, clear wp, step out of runtime and return cleared wp.
 * Leave PC at preceding one (hitting instr).
 * Return false to ignore this hit. */
func (tc *TaintCheck) hittingLine() bool {
	/* TODO for now, assume goroutine that hit the bp is currently selected.
	 * Should instead switch to that goroutine (need to read doc carefully:
	 * https://github.com/go-delve/delve/blob/master/Documentation/api/ClientHowto.md#using-rpcservercommand)
	 * (remember to pass that scope to Disass) */

	tc.printStacktrace()
	non_runtime_frame, handle := tc.handleRuntimeHit()
	if !handle || !tc.prevInstr(non_runtime_frame) {
		return false
	}

	src_line := sourceLine(tc.client, tc.hit.hit_instr.Loc.File, tc.hit.hit_instr.Loc.Line)

	if src_line == "" {
		log.Fatalf("No source line found for PC 0x%x\n", tc.hit.hit_instr.Loc.PC)
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
	fmt.Printf("ZZEM enter isTainted; expr %v\n", exprToString(expr))

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
				fmt.Printf("Eval expr %v\n", exprToString(node.(ast.Expr)))
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

	fmt.Printf("ZZEM isTainted return %v\n", is_tainted)
	return is_tainted
}

// If calling line has an assign or range, return corresp lhs and the next line
// (TODO same caveats about linear assumption as for Assign)
func (tc *TaintCheck) callerLhs(i int) (*ast.Expr, api.Location) {
	stack, err := tc.client.Stacktrace(-1, 100, api.StacktraceSimple, &api.LoadConfig{})
	if err != nil {
		log.Fatalf("Error getting stacktrace: %v\n", err)
	}
	call_file := stack[1].File
	call_line := stack[1].Line
	return getLhs(i, call_file, call_line), api.Location{File: call_file, Line: call_line}
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
			fmt.Println("CallExpr")
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
			fmt.Println("ReturnStmt")
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
			fmt.Println("AssignStmt")
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
			fmt.Println("RangeStmt")
			// TODO handle Range properly (once support tainted composite types in delve):
			// If only part of the rhs is tainted, value expr should only be tainted on corresp iters
			if tc.isTainted(typed_node.X) && typed_node.Value != nil {
				// TODO comment if this works
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
		// TODO add test for append w/ realloc
		// TODO does append of a tainted value hit wp? (Currently is hitting bc of string concat and/or slice already being tainted)
		tc.pending_watchexpr[addr] = append(tc.pending_watchexpr[addr], expr_str)
		fmt.Printf("ZZEM record pending wp for %v, bp addr 0x%x\n", expr_str, addr)
	}
	for _, expr_str := range expr_strs {
		tc.pending_watchexpr[addr] = append(tc.pending_watchexpr[addr], expr_str)
		fmt.Printf("ZZEM record pending wp for %v, bp addr 0x%x\n", expr_str, addr)
	}
	if argno != nil {
		tc.pending_watchargs[addr] = append(tc.pending_watchargs[addr], *argno)
	}
}

func (tc *TaintCheck) onSetWpDone(wp watchpoint) {
	if _, err := tc.client.ClearBreakpoint(tc.hit.hit_bp.ID); err != nil {
		log.Fatalf("Failed to clear bp at 0x%x: %v\n", wp.bp_addr, err)
	}

	delete(tc.pending_watchexpr, wp.bp_addr)
	delete(tc.pending_watchargs, wp.bp_addr)
	tc.round_done_wps[wp] = true
}

func (tc *TaintCheck) setWp(watchexpr string, bp_addr uint64) {
	scope := api.EvalScope{GoroutineID: -1, Frame: tc.hit.frame}

	loadcfg := api.LoadConfig{FollowPointers: true}
	xv, err := tc.client.EvalVariable(scope, watchexpr, loadcfg)
	if err != nil || xv.Addr == 0 {
		log.Fatalf("Failed to eval new watchexpr %v: err %v, xv %+v\n", watchexpr, err, xv)
	}
	wp := watchpoint{bp_addr: bp_addr, wp_addr: xv.Addr}
	fmt.Printf("ZZEM setWp for %v (0x%x)\n", watchexpr, wp.wp_addr)
	if tc.done_wps[wp] {
		// Already traced this addr in a previous round
		fmt.Printf("Already traced in prev round\n") // TODO add test for this
		tc.onSetWpDone(wp)
		return
	}
	// We really want a read-only wp, but rr's read-only hw wp are actually read-write
	if _, err := tc.client.CreateWatchpoint(scope, watchexpr, api.WatchRead|api.WatchWrite); err != nil {
		if !strings.HasPrefix(err.Error(), "Breakpoint exists at") {
			// Check # of wp after create, since it may have been a dup
			bps, list_err := tc.client.ListBreakpoints(true)
			if list_err != nil {
				log.Fatalf("Error listing breakpoints: %v\n", list_err)
			}
			n_wps := 0
			for _, bp := range bps {
				if bp.WatchExpr != "" {
					n_wps += 1
				}
			}
			if n_wps == 4 {
				// Stays pending
				fmt.Printf("Ran out of hw wp; staying pending\n")
				return
			} else {
				log.Fatalf("Failed to set watch for %v: %v\n", watchexpr, err)
			}
		}
	}

	tc.onSetWpDone(wp)
	fmt.Printf("ZZEM set wp for %v (0x%x)\n", watchexpr, wp.wp_addr)
}

// Bp for pending wp hit => try to set a hw wp
func (tc *TaintCheck) onPendingWp() {
	if len(tc.hit.hit_bp.Addrs) != 1 {
		log.Fatalf("Wrong number of addrs at pending wp; addrs %v\n", tc.hit.hit_bp.Addrs)
	}
	bp_addr := tc.hit.hit_bp.Addrs[0]

	if len(tc.pending_watchexpr[bp_addr]) == 0 && len(tc.pending_watchargs[bp_addr]) == 0 {
		log.Fatalf("No pending watches found after hitting 0x%x\n", bp_addr)
	}

	for _, watchexpr := range tc.pending_watchexpr[bp_addr] {
		tc.setWp(watchexpr, bp_addr)
	}
	scope := api.EvalScope{GoroutineID: -1, Frame: tc.hit.frame}
	for _, argno := range tc.pending_watchargs[bp_addr] {
		args, err := tc.client.ListFunctionArgs(scope, api.LoadConfig{})
		if err != nil {
			log.Fatalf("Failed to list function args at 0x%x: %v\n", bp_addr, err)
		}
		tc.setWp(args[argno].Name, bp_addr)
	}
}
