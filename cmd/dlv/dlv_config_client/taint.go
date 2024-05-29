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

type TaintCheck struct {
	client    *rpc2.RPCClient
	hit_bp    *api.Breakpoint
	hit_instr *api.AsmInstruction
	// Watchpoints as they were when wp was hit
	prev_wp []string
}

/* If hit was in runtime, stepout to the first non-runtime function.
 * Check that line for taint as usual.
 * TODO in e.g. Printf, tainted line may be up the stack - analyze every non-runtime line? */
func (tc *TaintCheck) handleRuntimeHit() {
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
		// Clear all wp for stepout
		tc.clearAllWp()
		fmt.Println("Stepping out of runtime")
		fmt.Println("Stack (with PC one after hitting instr):")
		for _, frame := range stack {
			if !strings.HasPrefix(frame.Function.Name(), "runtime") {
				break
			}

			loc := fmt.Sprintf("%v \nLine %v:%v:0x%x",
				frame.File, frame.Line, frame.Function.Name(),
				frame.PC)
			fmt.Println(loc)

			_, err := tc.client.StepOut()
			if err != nil {
				log.Fatalf("Error stepping out of %v\n", frame.Function.Name())
			}
		}
	}
}

/* If non-runtime, stepout takes us to the instr next in linear stream after call */
func (tc *TaintCheck) prevInstr() {
	state, err := tc.client.GetState()
	runtime_hit := tc.prev_wp != nil
	if !runtime_hit {
		// go to hitting instr for taint check
		fmt.Printf("PC before rev stepi 0x%x\n", state.CurrentThread.PC)
		state, err = tc.client.ReverseStepInstruction(false)
		if err != nil {
			log.Fatalf("Error reverse-stepping: %v\n", err)
		}
		fmt.Printf("PC after rev stepi 0x%x\n", state.CurrentThread.PC)
	}

	// disass function on hitting instr -- if was call, gives calling line
	fct_instr, err := tc.client.DisassemblePC(api.EvalScope{GoroutineID: -1}, state.CurrentThread.PC, api.IntelFlavour) // dst, src
	if err != nil {
		log.Fatalf("Error disassembling at PC 0x%x: %v\n", state.CurrentThread.PC, err)
	}

	for i, instr := range fct_instr {
		if instr.Loc.PC == state.CurrentThread.PC {
			if !runtime_hit {
				tc.hit_instr = &instr
				return
			} else {
				tc.hit_instr = &fct_instr[i-1]
				return
			}
		}
	}

	log.Fatalf("Failed to find instruction at PC 0x%x: %v\n", state.CurrentThread.PC, err)
}

/* Get instruction and source line corresponding to preceding PC, for selected goroutine.
 * If hit in runtime, clear wp, step out of runtime and return cleared wp.
 * Leave PC at preceding one (hitting instr) */
func (tc *TaintCheck) hittingLine() {
	/* TODO for now, assume goroutine that hit the bp is currently selected.
	 * Should instead switch to that goroutine (need to read doc carefully:
	 * https://github.com/go-delve/delve/blob/master/Documentation/api/ClientHowto.md#using-rpcservercommand)
	 * (remember to pass that scope to Disass) */

	/* TODO handle special case: if line hits in runtime and has a function that needs propagation,
	 * will fail (since we're at the line after the runtime call). Need to go back to the calling line
	 * to do the propagation, then go back to the following line. */

	tc.handleRuntimeHit()
	tc.prevInstr()

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

// TODO fix this -- assumes callee and caller are in same file
// Get the ith lhs of an assignment on lineno
func lhsCallerName(fset *token.FileSet, root *ast.File, i int, lineno int) (lhs string) {
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
			lhs_or_blank := exprToString(typed_node.Lhs[i])
			if lhs_or_blank != "_" {
				lhs = lhs_or_blank
			}
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
			xv, err := tc.client.EvalVariable(api.EvalScope{GoroutineID: -1}, exprToString(node.(ast.Expr)), loadcfg)
			fmt.Printf("ZZEM TRY EVAL %v\n", exprToString(node.(ast.Expr)))
			if err != nil || xv.Addr == 0 { // Addr == 0 for e.g. x + 1, but not e.g. x[1]
				fmt.Printf("ZZEM FAILED TO EVAL %v\n", exprToString(node.(ast.Expr)))
				// Try evaluating any children
			} else {
				for _, watch_addr := range tc.hit_bp.Addrs {
					// TODO get these sizes (once support tainted composite types in delve) - bp UserData?
					// For now, overapproximate
					watch_size := uint64(8)
					xv_size := uint64(8)

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

	fmt.Printf("ZZEM RETURN %v\n", is_tainted)
	return is_tainted
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
			// TODO handle special case: Watched location appears in a call and elsewhere on the line.
			// Currently if call hits first, on the second hit we error out trying to step into the call.
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
					tc.setWp(nil, expr_strs, typed_node)
				}
			}

			// TODO handle function composition (for builtins too - will need diff handling)
		case *ast.ReturnStmt:
			// Watched location is read in return value =>
			// taint corresponding lhs in caller
			hit_rets := []int{}
			for i, ret := range typed_node.Results {
				if tc.isTainted(ret) {
					hit_rets = append(hit_rets, i)
				}
			}

			var assign_lineno int
			if len(hit_rets) > 0 {
				var expr_strs []string
				for i := range hit_rets {
					// LEFT OFF: rerun test (did some reorg), then back to the other string case (that only hits in runtime)
					// Then, back to struct stuff in test.go: Check if append hits
					// (I think will require doing the TODO for runtime)
					// When done, check that old test still works

					// We've already inspected the corresp assign node at this point
					lhs_caller := lhsCallerName(fset, root, i, assign_lineno)
					if lhs_caller != "" {
						expr_strs = append(expr_strs, lhs_caller)
					}
				}
				if len(expr_strs) > 0 {
					tc.setWp(nil, expr_strs, typed_node)
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
				tc.setWp(typed_node.Lhs, nil, typed_node)
			}
		case *ast.RangeStmt:
			fmt.Println("ZZEM RANGE")
			// TODO handle Range properly (once support tainted composite types in delve):
			// If only part of the rhs is tainted, value expr should only be tainted on corresp iters
			if tc.isTainted(typed_node.X) && typed_node.Value != nil {
				fmt.Println("ZZEM SET")
				// TODO comment if this works
				// Watched location is read on the rhs =>
				// taint value expr
				tc.setWp([]ast.Expr{typed_node.Value}, nil, typed_node)
			}
		} // end switch

		return true
	})
}

func (tc *TaintCheck) clearAllWp() {
	bps, err := tc.client.ListBreakpoints(true)
	if err != nil {
		log.Fatalf("Error listing breakpoints\n")
	}

	for _, bp := range bps {
		if bp.WatchExpr != "" {
			// not all wp are named
			_, err := tc.client.ClearBreakpoint(bp.ID)
			if err != nil {
				log.Fatalf("Error clearing watchpoint: %v\n", err)
			}
			tc.prev_wp = append(tc.prev_wp, bp.WatchExpr)
		}
	}
}

func (tc *TaintCheck) rewindPC(rewindPC uint64) {
	state, _ := tc.client.GetState()
	name := fmt.Sprintf("rewindPC%x", rewindPC)
	fmt.Printf("Restore from %x to %x\n", state.CurrentThread.PC, rewindPC)
	oldPCbp := api.Breakpoint{Addrs: []uint64{rewindPC}, Name: name}
	if _, err := tc.client.CreateBreakpoint(&oldPCbp); err != nil {
		if !strings.HasPrefix(err.Error(), "Breakpoint exists at") { // ok if existed
			log.Fatalf("Error creating restore PC breakpoint for 0x%x: %v\n", rewindPC, err)
		}
	}

	// May hit wp during rewind
	// selectedGoroutine can be nil here
	for ; state.CurrentThread.PC != rewindPC; state = <-tc.client.Rewind() {
		fmt.Printf("PC after rewind: 0x%x\n", state.CurrentThread.PC)
	}

	if _, err := tc.client.ClearBreakpointByName(name); err != nil {
		log.Fatalf("Error clearing restore PC breakpoint for 0x%x: %v\n", rewindPC, err)
	}

	fmt.Printf("Rewind PC done\n")
}

func (tc *TaintCheck) restore(oldPC uint64) {
	if tc.prev_wp != nil {
		// We've cleared wp and advanced PC
		// Rewind first - possible that adjusting PC put old wp out of scope?
		// Doesn't handle runtime hit in range stmt (will clear value wp then fail to restore), but haven't seen that happen
		tc.rewindPC(oldPC)
		tc.restoreAllWp()
	} else {
		// We're still at hitting instr and didn't clear wp
		_, err := tc.client.StepInstruction(false)
		if err != nil {
			log.Fatalf("Failed to stepInstruction in restore: %v\n", err)
		}
	}
}

// Restore wp, even if set in a different frame from current (e.g. if hit in runtime)
func (tc *TaintCheck) restoreAllWp() {
	for _, wp := range tc.prev_wp {
		scope := api.EvalScope{GoroutineID: -1}
		stack, err := tc.client.Stacktrace(-1, 100, api.StacktraceSimple, &api.LoadConfig{})
		if err != nil {
			log.Fatalf("Error getting stacktrace: %v\n", err)
		}
		i := 0
		for ; i < len(stack); i++ {
			scope.Frame = i
			if _, err := tc.client.CreateWatchpoint(scope, wp, api.WatchRead|api.WatchWrite); err == nil {
				fmt.Printf("Restored %v\n", wp)
				break
			} else if strings.HasPrefix(err.Error(), "Breakpoint exists at") {
				break // e.g. str[0]
			} else if strings.HasPrefix(err.Error(), "could not find symbol") {
				// try next frame - if not in any, will error out at end
				continue
			} else {
				log.Fatalf("Error restoring watchpoint at %v, frame %v: %v\n", wp, i, err)
			}
		}
		if i == len(stack) {
			log.Fatalf("Error restoring watchpoint at %v -- out of scope?\n", wp)
		}
	}
}

// Clear all wp, adjust position so exprs are in scope, then set wp on exprs
func (tc *TaintCheck) setWp(exprs []ast.Expr, expr_strs []string, typed_node ast.Node) {
	if _, ok := typed_node.(*ast.RangeStmt); ok {
		// Check if we already have a wp on range value (i.e. past first iter)
		bps, err := tc.client.ListBreakpoints(true)
		if err != nil {
			log.Fatalf("Error listing breakpoints while handling Range: %v\n", err)
		}

		value := exprToString(exprs[0])
		fmt.Printf("ZZEM CHECKING\n")
		for _, bp := range bps {
			fmt.Printf("watchexpr: %v\n", bp.WatchExpr)
			if bp.WatchExpr == value || bp.WatchExpr == value+"[0]" {
				fmt.Printf("already hv wp for range value\n") // TODO remove
				return
			}
		}
	}

	tc.clearAllWp()

	if _, ok := typed_node.(*ast.CallExpr); ok {
		// Get params in scope
		// Step into fct
		state, err := tc.client.Step()
		if err != nil || state.Exited || state.Err != nil {
			log.Fatalf("Unexpected err %v or state %+v while stepping\n", err, state)
		}
		fmt.Printf("Stepped\n")
	}

	nexts := 1
	if _, ok := typed_node.(*ast.ReturnStmt); ok {
		nexts = 2
	}
	for i := 0; i < nexts; i++ {
		// next so lhs is in scope (handles :=), or to enter fct body (else params are "fake")
		state, err := tc.client.Next()
		if err != nil || state.Exited || state.Err != nil {
			log.Fatalf("Unexpected err %v or state %+v while nexting\n", err, state)
		}
	}

	for _, expr := range exprs {
		expr_str := exprToString(expr)
		// TODO if append causes realloc, check if this sets the wp on the new addr (will need to remove this check)
		// TODO does append of a tainted value hit wp? (Currently is hitting bc of string concat)
		if expr_str != tc.hit_bp.WatchExpr {
			fmt.Printf("Propagating taint from %v to %v\n", tc.hit_bp.WatchExpr, expr_str)
			wp, err := tc.client.CreateWatchpoint(api.EvalScope{GoroutineID: -1}, expr_str, api.WatchRead|api.WatchWrite)
			if err != nil {
				if !strings.HasPrefix(err.Error(), "Breakpoint exists at") { // ok if existed
					log.Fatalf("Error creating watchpoint at %v: %v\n", expr_str, err)
				}
			}

			for _, addr := range wp.Addrs {
				fmt.Printf("created wp: %x\n", addr)
			}
		}
	}
	for _, expr_str := range expr_strs {
		if expr_str != tc.hit_bp.WatchExpr {
			fmt.Printf("Propagating taint from %v to %v\n", tc.hit_bp.WatchExpr, expr_str)
			if _, err := tc.client.CreateWatchpoint(api.EvalScope{GoroutineID: -1}, expr_str, api.WatchRead|api.WatchWrite); err != nil {
				if !strings.HasPrefix(err.Error(), "Breakpoint exists at") { // ok if existed
					log.Fatalf("Error creating watchpoint at %v: %v\n", expr_str, err)
				}
			}
		}
	}
}
