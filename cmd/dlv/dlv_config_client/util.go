package main

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"log"
	"os"
	"regexp"
	"strings"

	"github.com/go-delve/delve/pkg/terminal"
	"github.com/go-delve/delve/service/api"
	"github.com/go-delve/delve/service/rpc2"
)

/* Get instruction and source line corresponding to preceding PC, for selected goroutine.
 * Leaves PC at preceding one. */
func PCToPrevPCLine(client *rpc2.RPCClient, pc uint64) (*api.AsmInstruction, string) {
	/* TODO for now, assume goroutine that hit the bp is currently selected.
	 * Should instead switch to that goroutine (need to read doc carefully:
	 * https://github.com/go-delve/delve/blob/master/Documentation/api/ClientHowto.md#using-rpcservercommand)
	 * (remember to pass that scope to Disass)
	 * May be convenient to do the check for stack resize at same time */

	// Check for runtime function
	stack, err := client.Stacktrace(-1, 100, api.StacktraceSimple, &api.LoadConfig{})
	// TODO check for partially loaded
	if err != nil {
		log.Fatalf("Error getting stacktrace at PC 0x%x: %v\n", pc, err)
	}
	if strings.HasPrefix(stack[0].Function.Name(), "runtime") {
		// TODO if this is e.g. due to memmove, may want to handle - ignoring for now
		fmt.Println("Watchpoint hit in runtime function - ignoring")
		fmt.Println("Stack (with PC one after hitting instr):")
		for _, frame := range stack {
			loc := fmt.Sprintf("%v \nLine %v:%v:0x%x",
				frame.File, frame.Line, frame.Function.Name(),
				frame.PC)
			fmt.Println(loc)
		}
		return nil, ""
	}
	// Don't skip calls -- if previous instr was call, want to step back into that fct
	state, err := client.ReverseStepInstruction(false)
	if err != nil {
		log.Fatalf("Error reverse-stepping at PC 0x%x: %v\n", pc, err)
	}
	prev_pc := state.SelectedGoroutine.CurrentLoc.PC

	// end is exclusive
	_prev_instr, err := client.DisassembleRange(current_scope, prev_pc, pc, api.IntelFlavour) // dst, src
	if err != nil {
		log.Fatalf("Error getting instructions at PC 0x%x: %v\n", prev_pc, err)
	} else if len(_prev_instr) != 1 {
		log.Fatalf("DisassembleRange returned %v instr for PC 0x%x\n", len(_prev_instr), prev_pc)
	}

	prev_instr := _prev_instr[0]

	if os.Setenv("TERM", "dumb") != nil {
		log.Fatalf("Error setting TERM=dumb")
	}

	t := terminal.New(client, nil)
	lines, err := t.GetOutput(fmt.Sprintf("list %v:%v", prev_instr.Loc.File, prev_instr.Loc.Line))
	if err != nil {
		log.Fatalf("Error getting source code for PC 0x%x: %v\n", prev_instr.Loc.PC, err)
	}

	var src_line string
	for _, line := range strings.Split(lines, "\n") {
		var curline int
		if strings.HasPrefix(line, "Showing") || line == "" {
			continue
		}
		if _, err := fmt.Sscanf(line, " %d:", &curline); err != nil {
			log.Fatalf("Failed to parse line number from line: %v: %v\n", line, err)
		}
		if curline != prev_instr.Loc.Line {
			continue
		}
		re := regexp.MustCompile(`\s+(\d+):\s+`)
		src_start := re.FindStringIndex(line)[1]
		if src_start <= len(line)-1 {
			src_line = line[src_start:]
		} else {
			log.Fatalf("Breakpoint PC 0x%x corresponds to empty line\n", prev_instr.Loc.PC)
		}
	}

	if src_line == "" {
		log.Fatalf("No source line found for PC 0x%x\n", prev_instr.Loc.PC)
	}

	return &prev_instr, src_line
}

func exprToString(t ast.Expr) string {
	var buf bytes.Buffer
	printer.Fprint(&buf, token.NewFileSet(), t)
	return buf.String()
}

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

	// TODO fix this -- assumes callee and caller are in same file
	fmt.Printf("No declaration for function %v in AST -- in different file?\n", fn)
	return
}

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
		switch node.(type) {
		case *ast.CallExpr:
			return false
		default:
			// TODO check for incomplete loads (see client API doc)
			xv, err := client.EvalVariable(current_scope, exprToString(node.(ast.Expr)), loadcfg)
			if err != nil || xv.Addr == 0 { // Addr == 0 for e.g. x + 1, but not e.g. x[1]
				// Try evaluating any children
			} else {
				for _, watch_addr := range hit_bp.Addrs {
					// TODO get size of watched region (api.Breakpoint doesn't have it directly)
					watch_size := uint64(8)
					// TODO get size of variable (api.Variable doesn't have it directly)
					xv_size := uint64(8)

					if xv.Addr < watch_addr+watch_size && watch_addr < xv.Addr+xv_size {
						// overlaps
						is_tainted = true
					}
				}

				// Don't evaluate children - their memory is a superset of node's
				// (at least for Index and Selector - haven't thought through others)
				return false
			}
		}
		return true
	})

	return is_tainted
}

/* Assuming lineno reads watchexpr's location, get expressions tainted by the read.
 * Accounts for aliased reads (i.e. those that don't match watchexpr). */
func taintedExprs(client *rpc2.RPCClient, watchexpr string,
	file string, lineno int, hit_bp *api.Breakpoint) (tainted_exprs []string) {

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

		// TODO is it possible to hit another wp while stepping/nexting?
		// Executing a bp-hitting instr via stepInstruction doesn't hit the bp,
		// but executing via continue does - not sure about next/step

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
				// Undo rev stepi, else we'll hit the watchpoint again when we try to step/continue
				state, err := client.StepInstruction(false)
				if err != nil || state.Err != nil {
					log.Fatalf("Error restoring PC: %v\n", err)
				}
				did_stepi = true
				// Watched location was passed as a param =>
				// taint callee's copy of param

				// Get params in scope
				// Step into fct
				state, err = client.Step()
				if err != nil || state.Exited || state.Err != nil {
					log.Fatalf("Unexpected err %v or state %+v while stepping into %v\n", err, state, exprToString(typed_node.Fun))
				}
				// Param is "fake" at function entry => next into function body
				state, err = client.Next()
				if err != nil || state.Exited || state.Err != nil {
					log.Fatalf("Unexpected err %v or state %+v while nexting in %v\n", err, state, exprToString(typed_node.Fun))
				}
			}

			for _, i := range hit_args {
				param_callee := paramCalleeName(root, exprToString(typed_node.Fun), i)
				if param_callee != "" {
					fmt.Printf("Propagating taint from %v to %v\n", watchexpr, param_callee)
					if _, err := client.CreateWatchpoint(current_scope, param_callee, api.WatchRead|api.WatchWrite); err != nil {
						if !strings.HasPrefix(err.Error(), "Breakpoint exists at") { // ok if existed
							log.Fatalf("Error creating watchpoint at %v: %v\n", param_callee, err)
						}
					}
					tainted_exprs = append(tainted_exprs, param_callee)
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
				// Undo rev stepi, else we'll hit the watchpoint again when we try to step
				state, err := client.StepInstruction(false)
				if err != nil || state.Err != nil {
					log.Fatalf("Error restoring PC: %v\n", err)
				}
				did_stepi = true
				// TODO does this handle function composition?
				for i := 0; i < 2; i++ {
					// Get caller lhs in scope (next twice to handle :=)
					state, err := client.Next()
					if err != nil || state.Exited || state.Err != nil {
						log.Fatalf("Unexpected err %v or state %+v while nexting from ret\n", err, state)
					}
					if i == 0 {
						assign_lineno = state.SelectedGoroutine.CurrentLoc.Line
					}
				}
			}
			for i := range hit_rets {
				// We've already inspected the corresp assign node at this point
				lhs_caller := lhsCallerName(fset, root, i, assign_lineno)
				if lhs_caller != "" {
					fmt.Printf("Propagating taint from %v to %v\n", watchexpr, lhs_caller)
					if _, err := client.CreateWatchpoint(current_scope, lhs_caller, api.WatchRead|api.WatchWrite); err != nil {
						if !strings.HasPrefix(err.Error(), "Breakpoint exists at") { // ok if existed
							log.Fatalf("Error creating watchpoint at %v: %v\n", lhs_caller, err)
						}
					}
					tainted_exprs = append(tainted_exprs, lhs_caller)
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
				// Undo rev stepi, else we'll hit the watchpoint again when we try to next
				state, err := client.StepInstruction(false)
				if err != nil || state.Err != nil {
					log.Fatalf("Error restoring PC: %v\n", err)
				}
				did_stepi = true
				// next so lhs is in scope (handles :=)
				state, err = client.Next()
				if err != nil || state.Exited || state.Err != nil {
					log.Fatalf("Unexpected err %v or state %+v while nexting\n", err, state)
				}
				// Watched location is read on the rhs =>
				// taint lhs
				for _, lhs := range typed_node.Lhs {
					expr_str := exprToString(lhs)
					if expr_str != watchexpr {

						fmt.Printf("Propagating taint from %v to %v\n", watchexpr, expr_str)
						if _, err := client.CreateWatchpoint(current_scope, expr_str, api.WatchRead|api.WatchWrite); err != nil {
							if !strings.HasPrefix(err.Error(), "Breakpoint exists at") { // ok if existed
								log.Fatalf("Error creating watchpoint at %v: %v\n", expr_str, err)
							}
						}
					}
				}
			}
		case *ast.RangeStmt:
			// TODO handle Range properly (once support tainted composite types):
			// If only part of the rhs is tainted, value expr should only be tainted on corresp iters
			if isTainted(client, typed_node.X, hit_bp) && typed_node.Value != nil {
				// Watched location is read on the rhs =>
				// taint value expr
				expr_str := exprToString(typed_node.Value)
				if expr_str != watchexpr {
					// Undo rev stepi, else we'll hit the watchpoint again when we try to next
					state, err := client.StepInstruction(false)
					if err != nil || state.Err != nil {
						log.Fatalf("Error restoring PC: %v\n", err)
					}
					did_stepi = true
					// next so lhs is in scope (handles :=)
					state, err = client.Next()
					if err != nil || state.Exited || state.Err != nil {
						log.Fatalf("Unexpected err %v or state %+v while nexting\n", err, state)
					}

					fmt.Printf("Propagating taint from %v to %v\n", watchexpr, expr_str)
					if _, err := client.CreateWatchpoint(current_scope, expr_str, api.WatchRead|api.WatchWrite); err != nil {
						if !strings.HasPrefix(err.Error(), "Breakpoint exists at") { // ok if existed
							log.Fatalf("Error creating watchpoint at %v: %v\n", expr_str, err)
						}
					}
				}
			}
		} // end switch

		return true
	})

	if !did_stepi {
		state, err := client.StepInstruction(false)
		if err != nil || state.Err != nil {
			log.Fatalf("Error restoring PC: %v\n", err)
		}
	}

	return tainted_exprs
}
