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

// TODO remove unused stuff, update comments on all fcts
type TaintCheck struct {
	client    *rpc2.RPCClient
	hit_bp    *api.Breakpoint
	hit_instr *api.AsmInstruction
	// Frame to check taint in (first non-runtime frame)
	frame int
	// For wp waiting to be set: addr to set at => watchexpr
	pending_wp map[uint64][]string
}

/* If hit was in runtime, stepout to the first non-runtime function.
 * Check that line for taint as usual.
 * TODO in e.g. Printf, tainted line may be up the stack - analyze every non-runtime line? */
func (tc *TaintCheck) handleRuntimeHit() *api.Stackframe {
	// Check for runtime function
	stack, err := tc.client.Stacktrace(-1, 100, api.StacktraceSimple, &api.LoadConfig{})
	// TODO check for partially loaded (in any calls to Stacktrace)
	if err != nil {
		log.Fatalf("Error getting stacktrace: %v\n", err)
	}

	/* This assumes runtime function was called implicitly (e.g. newstack/memmove),
	 * so doesn't create new vars and doesn't propagate taint via return.
	 * TODO eventually consider explicit runtime calls */
	if strings.HasPrefix(stack[0].Function.Name(), "runtime") {
		fmt.Println("Runtime hit - stack (with PC one after hitting instr):")
		for i, frame := range stack {
			if !strings.HasPrefix(frame.Function.Name(), "runtime") {
				tc.frame = i
				return &frame
			}

			loc := fmt.Sprintf("%v \nLine %v:%v:0x%x",
				frame.File, frame.Line, frame.Function.Name(),
				frame.PC)
			fmt.Println(loc)
		}
	}

	return nil
}

/* If non-runtime, stepout takes us to the instr next in linear stream after call */
func (tc *TaintCheck) prevInstr(non_runtime_frame *api.Stackframe) {
	state, err := tc.client.GetState()

	// Hitting instr may be same or diff line as cur instr => get prev instr's line
	pc := state.CurrentThread.PC
	if non_runtime_frame != nil {
		// runtime hit
		pc = non_runtime_frame.PC
	}
	fct_instr, err := tc.client.DisassemblePC(api.EvalScope{GoroutineID: -1, Frame: tc.frame}, pc, api.IntelFlavour) // dst, src
	if err != nil {
		log.Fatalf("Error disassembling at PC 0x%x: %v\n", pc, err)
	}

	// There aren't any branching instr that touch memory, right?
	// So hitting instr should always be linearly previous?
	// (Or for runtime hit, frame is function that called runtime)
	for i, instr := range fct_instr {
		if instr.Loc.PC == pc {
			tc.hit_instr = &fct_instr[i-1]
			return
		}
	}

	log.Fatalf("Failed to find instruction at PC 0x%x: %v\n", pc, err)
}

/* Get instruction and source line corresponding to preceding PC, for selected goroutine.
 * If hit in runtime, clear wp, step out of runtime and return cleared wp.
 * Leave PC at preceding one (hitting instr) */
func (tc *TaintCheck) hittingLine() {
	/* TODO for now, assume goroutine that hit the bp is currently selected.
	 * Should instead switch to that goroutine (need to read doc carefully:
	 * https://github.com/go-delve/delve/blob/master/Documentation/api/ClientHowto.md#using-rpcservercommand)
	 * (remember to pass that scope to Disass) */

	non_runtime_frame := tc.handleRuntimeHit()
	tc.prevInstr(non_runtime_frame)

	src_line := sourceLine(tc.client, tc.hit_instr.Loc.File, tc.hit_instr.Loc.Line)

	if src_line == "" {
		log.Fatalf("No source line found for PC 0x%x\n", tc.hit_instr.Loc.PC)
	}
	hit_loc := fmt.Sprintf("%v \nLine %v:%v:0x%x \n%v \n%v",
		tc.hit_instr.Loc.File, tc.hit_instr.Loc.Line, tc.hit_instr.Loc.Function.Name(),
		tc.hit_instr.Loc.PC, tc.hit_instr.Text, src_line)

	fmt.Printf("\nHit watchpoint for %v (0x%x), at:\n%v\n", tc.hit_bp.WatchExpr, tc.hit_bp.Addr, hit_loc)
}

// TODO fix this -- assumes callee and caller are in same file
// (Not an issue for current example, but should fix soon)
// Get the name of param at index i, in function scope
func paramCalleeName(root *ast.File, fn string, i int) (param string) {
	for _, decl := range root.Decls {
		fn_node, ok := decl.(*ast.FuncDecl)
		if !ok {
			continue
		}
		if fn_node.Name.Name != fn {
			continue
		}
		params := fn_node.Type.Params.List
		if len(params[i].Names) != 1 {
			// idk when this happens
			log.Fatalf("Fn %v param %v has %v names\n", fn, i, len(params[i].Names))
		}
		return params[i].Names[0].Name
	}

	fmt.Printf("No declaration for function %v in AST -- in different file?\n", fn)
	return
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
			xv, err := tc.client.EvalVariable(api.EvalScope{GoroutineID: -1, Frame: tc.frame}, exprToString(node.(ast.Expr)), loadcfg)
			if err != nil || xv.Addr == 0 { // Addr == 0 for e.g. x + 1, but not e.g. x[1]
				// Try evaluating any children
			} else {
				fmt.Printf("Eval expr %v\n", exprToString(node.(ast.Expr)))
				for _, watch_addr := range tc.hit_bp.Addrs {
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

// If calling line has an assign, return its ith lhs and the next line
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
	root, err := parser.ParseFile(fset, tc.hit_instr.Loc.File, nil, parser.SkipObjectResolution)
	if err != nil {
		log.Fatalf("Failed to parse source file %v: %v\n", tc.hit_instr.Loc.File, err)
	}

	// DFS of file's AST
	ast.Inspect(root, func(node ast.Node) bool {
		// PERF: How to properly only inspect one line?
		cur_line := -1
		if node != nil {
			cur_line = fset.Position(node.Pos()).Line
		}
		if cur_line != tc.hit_instr.Loc.Line {
			return true
		}

		switch typed_node := node.(type) {

		case *ast.CallExpr:
			fmt.Println("CallExpr")
			if handledBuiltins[exprToString(typed_node.Fun)] {
				return false // will be handled in assign
			}
			hit_args := []int{}
			for i, arg := range typed_node.Args {
				if tc.isTainted(arg) {
					hit_args = append(hit_args, i)
				}
			}

			if len(hit_args) > 0 {
				var expr_strs []string
				for _, i := range hit_args {
					param_callee := paramCalleeName(root, exprToString(typed_node.Fun), i)
					if param_callee != "" {
						expr_strs = append(expr_strs, param_callee)
					}
				}
				if len(expr_strs) > 0 {
					tc.recordPendingWp(nil, expr_strs, typed_node, fset, nil)
				}
			}

		case *ast.ReturnStmt:
			fmt.Println("ReturnStmt")
			// Watched location is read in return value =>
			// taint corresponding lhs in caller, if any
			// TODO handle function composition (for builtins too - will need diff handling)
			for i, ret := range typed_node.Results {
				if tc.isTainted(ret) {
					caller_lhs, caller_loc := tc.callerLhs(i)
					if caller_lhs != nil {
						// TODO now that recordPendingWp is idempotent, can elim loops in other cases too
						tc.recordPendingWp([]ast.Expr{*caller_lhs}, nil, typed_node, fset, &caller_loc)
					}
				}
			}

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
				tc.recordPendingWp(typed_node.Lhs, nil, typed_node, fset, nil)
			}
		case *ast.RangeStmt:
			fmt.Println("RangeStmt")
			// TODO handle Range properly (once support tainted composite types in delve):
			// If only part of the rhs is tainted, value expr should only be tainted on corresp iters
			if tc.isTainted(typed_node.X) && typed_node.Value != nil {
				// TODO comment if this works
				// Watched location is read on the rhs =>
				// taint value expr
				tc.recordPendingWp([]ast.Expr{typed_node.Value}, nil, typed_node, fset, nil)
			}
		} // end switch

		return true
	})
}

// Find the next line on or after this one with a statement, so we can set a bp.
// May want to consider doing this with PC when handle the non-linear stuff
func (tc *TaintCheck) lineWithStmt(fn *string, file *string, lineno int) api.Location {
	var loc string
	s := file
	if fn != nil {
		lineno = 1
		s = fn
	}

	for { // TODO make loop safer
		loc = fmt.Sprintf("%v:%v", *s, lineno)
		fmt.Printf("trying loc %v\n", loc)
		// TODO(minor): how to pass in substitutePath rules? (2nd ret is related)
		// Lines with instr only
		locs, _, err := tc.client.FindLocation(api.EvalScope{GoroutineID: -1, Frame: tc.frame}, loc, true, nil)
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

// TODO add test for call and expr where both hit
func (tc *TaintCheck) recordPendingWp(exprs []ast.Expr, expr_strs []string, node ast.Node, fset *token.FileSet, loc *api.Location) {
	var pending_loc api.Location
	pos := fset.Position(node.Pos())

	switch typed_node := node.(type) {

	case *ast.CallExpr:
		// First line of function body (params are "fake" at declaration line)
		fn := exprToString(typed_node.Fun)
		pending_loc = tc.lineWithStmt(&fn, nil, 1)

	case *ast.AssignStmt:
		// May not be next line linearly for := in flow control statement
		// but if not, var immediately went out of scope so we don't need a wp anyway
		// TODO except for if/else, maybe others
		// And Range: If next line is }, set on next iter
		pending_loc = tc.lineWithStmt(nil, &pos.Filename, pos.Line+1)

	case *ast.RangeStmt:
		pending_loc = tc.lineWithStmt(nil, &pos.Filename, pos.Line+1)

	case *ast.ReturnStmt:
		// Line after calling line
		pending_loc = tc.lineWithStmt(nil, &loc.File, loc.Line+1)

	}

	addr := pending_loc.PCs[0]
	bp := api.Breakpoint{Addrs: []uint64{addr}}
	if _, err := tc.client.CreateBreakpoint(&bp); err != nil {
		if !strings.HasPrefix(err.Error(), "Breakpoint exists at") {
			log.Fatalf("Failed to create breakpoint at %v: %v\n", addr, err)
		}
	}

	for _, expr := range exprs {
		expr_str := exprToString(expr)
		// TODO if append causes realloc, check if this sets the wp on the new addr (will need to remove this check)
		// TODO does append of a tainted value hit wp? (Currently is hitting bc of string concat)
		if expr_str != tc.hit_bp.WatchExpr {
			tc.pending_wp[addr] = append(tc.pending_wp[addr], expr_str)
			fmt.Printf("ZZEM record pending wp for %v, bp addr 0x%x\n", expr_str, addr)
		}
	}
	for _, expr_str := range expr_strs {
		if expr_str != tc.hit_bp.WatchExpr {
			tc.pending_wp[addr] = append(tc.pending_wp[addr], expr_str)
			fmt.Printf("ZZEM record pending wp for %v, bp addr 0x%x\n", expr_str, addr)
		}
	}
}

func (tc *TaintCheck) setPendingWp() {
	if len(tc.hit_bp.Addrs) != 1 {
		log.Fatalf("Wrong number of addrs at pending wp; addrs %v\n", tc.hit_bp.Addrs)
	}
	addr := tc.hit_bp.Addrs[0]
	watchexprs := tc.pending_wp[addr]
	if watchexprs == nil {
		log.Fatalf("No watchexprs found after hitting 0x%x\n", addr)
	}

	scope := api.EvalScope{GoroutineID: -1, Frame: tc.frame}
	for _, watchexpr := range watchexprs {
		if _, err := tc.client.CreateWatchpoint(scope, watchexpr, api.WatchRead|api.WatchWrite); err != nil {
			fmt.Printf("err: %v\n", err)
			if !strings.HasPrefix(err.Error(), "Breakpoint exists at") {
				// Check # of wp after create, since it may have been a dup
				bps, err := tc.client.ListBreakpoints(true)
				if err != nil {
					log.Fatalf("Error listing breakpoints: %v\n", err)
				}
				n_wps := 0
				for _, bp := range bps {
					if bp.WatchExpr != "" {
						n_wps += 1
					}
				}
				if n_wps == 4 {
					log.Fatalf("Ran out of hardware watchpoints\n")
				} else {
					log.Fatalf("Failed to set watch for %v at 0x%x: %v\n", watchexpr, addr, err)
				}
			}
		}
		fmt.Printf("ZZEM set pending wp for %v\n", watchexpr)
	}

	if _, err := tc.client.ClearBreakpoint(tc.hit_bp.ID); err != nil {
		log.Fatalf("Failed to clear bp at 0x%x: %v\n", addr, err)
	}
	delete(tc.pending_wp, addr)
}
