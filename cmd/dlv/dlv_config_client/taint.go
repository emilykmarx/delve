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

/* If hit was in runtime, stepout to the first non-runtime function.
 * Check that line for taint as usual.
 * TODO in e.g. Printf, tainted line may be up the stack - analyze every non-runtime line? */
func handleRuntimeHit(client *rpc2.RPCClient) []string {
	// Check for runtime function
	stack, err := client.Stacktrace(-1, 100, api.StacktraceSimple, &api.LoadConfig{})
	// TODO check for partially loaded (in any calls to Stacktrace)
	if err != nil {
		log.Fatalf("Error getting stacktrace: %v\n", err)
	}

	/* This assumes runtime function was called implicitly (e.g. newstack/memmove),
	 * so doesn't create new vars and doesn't propagate taint via return.
	 * TODO eventually consider explicit runtime calls */
	if strings.HasPrefix(stack[0].Function.Name(), "runtime") {
		// Clear all wp for stepout
		prev_wp := clearAllWp(client)
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

			_, err := client.StepOut()
			if err != nil {
				log.Fatalf("Error stepping out of %v\n", frame.Function.Name())
			}
		}
		return prev_wp
	}
	return nil
}

/* If non-runtime, stepout takes us to the instr next in linear stream after call */
func prevInstr(client *rpc2.RPCClient, runtime_hit bool) (*api.AsmInstruction, []string) {
	state, err := client.GetState()
	var prev_wp []string
	if !runtime_hit {
		// Don't clear wp yet - breaks rev stepi
		fmt.Printf("PC before rev stepi 0x%x\n", state.CurrentThread.PC)
		state, err = client.ReverseStepInstruction(false)
		// Clear all wp for stepout
		prev_wp = clearAllWp(client)
		if err != nil {
			log.Fatalf("Error reverse-stepping: %v\n", err)
		}
		fmt.Printf("PC after rev stepi 0x%x\n", state.CurrentThread.PC)
	}

	// disass function on hitting instr -- if was call, gives calling line
	fct_instr, err := client.DisassemblePC(api.EvalScope{GoroutineID: -1}, state.CurrentThread.PC, api.IntelFlavour) // dst, src
	if err != nil {
		log.Fatalf("Error disassembling at PC 0x%x: %v\n", state.CurrentThread.PC, err)
	}

	for i, instr := range fct_instr {
		if instr.Loc.PC == state.CurrentThread.PC {
			if !runtime_hit {
				return &instr, prev_wp
			}
			return &fct_instr[i-1], prev_wp
		}
	}

	log.Fatalf("Failed to find instruction at PC 0x%x: %v\n", state.CurrentThread.PC, err)
	return nil, nil
}

/* Get instruction and source line corresponding to preceding PC, for selected goroutine.
 * Step out of runtime if applicable.
 * Leaves PC at preceding one (hitting instr) */
func hittingLine(client *rpc2.RPCClient, hit_bp *api.Breakpoint) (*api.AsmInstruction, []string) {
	/* TODO for now, assume goroutine that hit the bp is currently selected.
	 * Should instead switch to that goroutine (need to read doc carefully:
	 * https://github.com/go-delve/delve/blob/master/Documentation/api/ClientHowto.md#using-rpcservercommand)
	 * (remember to pass that scope to Disass) */

	/* TODO handle special case: if line hits in runtime and has a function that needs propagation,
	 * will fail (since we're at the line after the runtime call). Need to go back to the calling line
	 * to do the propagation, then go back to the following line. */

	// Wp were cleared in one of these 2 places
	prev_wp_runtime := handleRuntimeHit(client)
	instr, prev_wp_non_runtime := prevInstr(client, prev_wp_runtime != nil)
	prev_wp := prev_wp_non_runtime
	if prev_wp_non_runtime == nil {
		prev_wp = prev_wp_runtime
	}

	src_line := sourceLine(client, instr.Loc.File, instr.Loc.Line)

	if src_line == "" {
		log.Fatalf("No source line found for PC 0x%x\n", instr.Loc.PC)
	}
	hit_loc := fmt.Sprintf("%v \nLine %v:%v:0x%x \n%v \n%v",
		instr.Loc.File, instr.Loc.Line, instr.Loc.Function.Name(),
		instr.Loc.PC, instr.Text, src_line)

	fmt.Printf("\nHit watchpoint for %v (0x%x), at:\n%v\n", hit_bp.WatchExpr, hit_bp.Addr, hit_loc)

	return instr, prev_wp
}

// TODO fix this -- assumes callee and caller are in same file
// (Not an issue for current example, but should fix soon)
// Get the name of param at index i, in function scope
func paramCalleeName(root *ast.File, fn string, i int) (param string) {
	if handledBuiltins[fn] {
		return // will be handled in assign
	}

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
 * ignoring function args.
 * Requires expr to be in scope. */
func isTainted(client *rpc2.RPCClient, expr ast.Expr, hit_bp *api.Breakpoint) bool {
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
			if handleBuiltinFct(exprToString(typed_node.Fun)) {
				is_tainted = true
			}
			return false
		default:
			// TODO check for incomplete loads (see client API doc)
			xv, err := client.EvalVariable(api.EvalScope{GoroutineID: -1}, exprToString(node.(ast.Expr)), loadcfg)
			if err != nil || xv.Addr == 0 { // Addr == 0 for e.g. x + 1, but not e.g. x[1]
				// Try evaluating any children
			} else {
				for _, watch_addr := range hit_bp.Addrs {
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

	return is_tainted
}

/* Assuming this line hits hit_bp, propagate taint to other exprs on line.
 * Accounts for aliased reads (i.e. those that don't match hit_bp.WatchExpr). */
func propagateTaint(client *rpc2.RPCClient,
	file string, lineno int, hit_bp *api.Breakpoint, prev_wp []string) {

	fset := token.NewFileSet()
	root, err := parser.ParseFile(fset, file, nil, parser.SkipObjectResolution)
	if err != nil {
		log.Fatalf("Failed to parse source file %v: %v\n", file, err)
	}

	// Set to true when undo rev stepi
	// Regardless of control flow, needs to happen exactly once after checking if exprs are tainted
	did_stepi := false

	// DFS of file's AST
	ast.Inspect(root, func(node ast.Node) bool {
		// PERF: How to properly only inspect one line?
		cur_line := -1
		if node != nil {
			cur_line = fset.Position(node.Pos()).Line
		}
		if cur_line != lineno {
			return true
		}

		switch typed_node := node.(type) {

		case *ast.CallExpr:
			// TODO handle special case: Watched location appears in a call and elsewhere on the line.
			// Currently if call hits first, on the second hit we error out trying to step into the call.
			hit_args := []int{}
			for i, arg := range typed_node.Args {
				if isTainted(client, arg, hit_bp) {
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
					setWp(&did_stepi, client, nil, expr_strs, hit_bp, typed_node)
				}
			}

		case *ast.ReturnStmt:
			// Watched location is read in return value =>
			// taint corresponding lhs in caller
			hit_rets := []int{}
			for i, ret := range typed_node.Results {
				if isTainted(client, ret, hit_bp) {
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
					setWp(&did_stepi, client, nil, expr_strs, hit_bp, typed_node)
				}
			}

		case *ast.AssignStmt:
			hit_rhs := false
			for _, rhs := range typed_node.Rhs {
				// TODO properly handle multiple rhs (unsure of semantics)
				if isTainted(client, rhs, hit_bp) {
					hit_rhs = true
				}
			}
			if hit_rhs {
				// Watched location is read on the rhs =>
				// taint lhs
				setWp(&did_stepi, client, typed_node.Lhs, nil, hit_bp, typed_node)
			}
		case *ast.RangeStmt:
			// TODO handle Range properly (once support tainted composite types in delve):
			// If only part of the rhs is tainted, value expr should only be tainted on corresp iters
			if isTainted(client, typed_node.X, hit_bp) && typed_node.Value != nil {
				// Watched location is read on the rhs =>
				// taint value expr
				setWp(&did_stepi, client, []ast.Expr{typed_node.Value}, nil, hit_bp, typed_node)
			}
		} // end switch

		return true
	})

	// must restore before stepi
	restoreAllWp(client, prev_wp)

	// Undo rev stepi, else we'll hit the watchpoint again when we try to continue
	if !did_stepi {
		state, err := client.StepInstruction(false)
		if err != nil || state.Err != nil {
			log.Fatalf("Error restoring PC: %v\n", err)
		}
	}
	state, err := client.GetState()
	fmt.Printf("PC after restore: %x\n", state.CurrentThread.PC)
}

func clearAllWp(client *rpc2.RPCClient) (prev_wp []string) {
	bps, err := client.ListBreakpoints(true)
	if err != nil {
		log.Fatalf("Error listing breakpoints\n")
	}

	for _, bp := range bps {
		if bp.WatchExpr != "" {
			// not all wp are named
			_, err := client.ClearBreakpoint(bp.ID)
			if err != nil {
				log.Fatalf("Error clearing watchpoint: %v\n", err)
			}
			prev_wp = append(prev_wp, bp.WatchExpr)
		}
	}
	return prev_wp
}

// Restore wp, even if set in a different frame from current
func restoreAllWp(client *rpc2.RPCClient, prev_wp []string) {
	for _, wp := range prev_wp {
		scope := api.EvalScope{GoroutineID: -1}
		// May have been set in an earlier frame => try until succeed
		stack, err := client.Stacktrace(-1, 100, api.StacktraceSimple, &api.LoadConfig{})
		if err != nil {
			log.Fatalf("Error getting stacktrace: %v\n", err)
		}
		i := 0
		for ; i < len(stack); i++ {
			scope.Frame = i
			if _, err := client.CreateWatchpoint(scope, wp, api.WatchRead|api.WatchWrite); err == nil {
				fmt.Printf("Restored %v\n", wp)
				break
			} else if strings.HasPrefix(err.Error(), "Breakpoint exists at") {
				break // e.g. str[0]
			} else if !strings.HasPrefix(err.Error(), "could not find symbol") {
				log.Fatalf("Error creating watchpoint at %v, frame %v: %v\n", wp, i, err)
			}
		}
		if i == len(stack) {
			// ok if watchpoint went out of scope during next -- TODO detect that
			fmt.Printf("Error restoring watchpoint at %v -- out of scope?\n", wp)
		}
		fmt.Printf("bp after restore:\n")
		bps, err := client.ListBreakpoints(true)
		for _, bp := range bps {
			fmt.Printf("%v, %x\n", bp.WatchExpr, bp.Addr)
		}
	}
}

// Adjust position so exprs are in scope, then set wp on exprs
func setWp(did_stepi *bool, client *rpc2.RPCClient,
	exprs []ast.Expr, expr_strs []string, hit_bp *api.Breakpoint, typed_node ast.Node) {
	*did_stepi = true

	if _, ok := typed_node.(*ast.CallExpr); ok {
		// Get params in scope
		// Step into fct
		state, err := client.Step()
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
		state, err := client.Next()
		if err != nil || state.Exited || state.Err != nil {
			log.Fatalf("Unexpected err %v or state %+v while nexting\n", err, state)
		}
	}

	for _, expr := range exprs {
		expr_str := exprToString(expr)
		if expr_str != hit_bp.WatchExpr {

			fmt.Printf("Propagating taint from %v to %v\n", hit_bp.WatchExpr, expr_str)
			if _, err := client.CreateWatchpoint(api.EvalScope{GoroutineID: -1}, expr_str, api.WatchRead|api.WatchWrite); err != nil {
				if !strings.HasPrefix(err.Error(), "Breakpoint exists at") { // ok if existed
					log.Fatalf("Error creating watchpoint at %v: %v\n", expr_str, err)
				}
			}
		}
	}
	for _, expr_str := range expr_strs {
		if expr_str != hit_bp.WatchExpr {
			fmt.Printf("Propagating taint from %v to %v\n", hit_bp.WatchExpr, expr_str)
			if _, err := client.CreateWatchpoint(api.EvalScope{GoroutineID: -1}, expr_str, api.WatchRead|api.WatchWrite); err != nil {
				if !strings.HasPrefix(err.Error(), "Breakpoint exists at") { // ok if existed
					log.Fatalf("Error creating watchpoint at %v: %v\n", expr_str, err)
				}
			}
		}
	}
}
