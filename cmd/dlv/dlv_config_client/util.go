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
func PCToPrevPCLine(client *rpc2.RPCClient, pc uint64) (api.AsmInstruction, string) {
	/* TODO for now, assume goroutine that hit the bp is currently selected.
	 * Should instead switch to that goroutine (need to read doc carefully:
	 * https://github.com/go-delve/delve/blob/master/Documentation/api/ClientHowto.md#using-rpcservercommand)
	 * (remember to pass that scope to Disass)
	 * May be convenient to do the check for stack resize at same time */

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

	return prev_instr, src_line
}

// Get identifiers that hit hit_bp, based on their current addrs
func hitIdentifiers(client *rpc2.RPCClient, fset *token.FileSet, root *ast.File, lineno int, hit_bp *api.Breakpoint) (hit_idents []string) {
	// 1. Get identifiers
	idents := []*ast.Ident{}
	ast.Inspect(root, func(node ast.Node) bool {
		cur_line := -1
		if node != nil {
			cur_line = fset.Position(node.Pos()).Line
		}
		if cur_line != lineno {
			return true
		}
		switch typed_node := node.(type) {
		case *ast.Ident:
			idents = append(idents, typed_node)
		}
		return true
	})

	// 2. Get addrs
	if os.Setenv("TERM", "dumb") != nil {
		log.Fatalf("Error setting TERM=dumb")
	}

	for _, ident := range idents {
		t := terminal.New(client, nil)
		// PERF: may be able to do this in single client call (with \n)
		addr_line, err := t.GetOutput("p &" + ident.Name)
		if err != nil {
			// Things like package names don't have addresses
			continue
		}
		parts := strings.Split(addr_line, "(")
		part := parts[len(parts)-1]
		addr_str := part[:len(part)-1]
		var ident_addr uint64
		fmt.Sscanf(addr_str, "0x%x", &ident_addr)

		for _, watched_addr := range hit_bp.Addrs {
			if watched_addr == ident_addr {
				hit_idents = append(hit_idents, ident.Name)
			}
		}
	}

	return hit_idents
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

	// TODO model propagation for built-ins?
	fmt.Printf("(No declaration for function %v in AST -- ok if built-in)\n", fn)
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

/* Whether expr is read in outer_expr, ignoring param passing,
* since propagation for that is handled within the function.
* E.g. `x := f(watchexpr)` doesn't necessarily taint x (depending on f),
* but  `x := f() + watchexpr` does */
func readsExpr(outer_expr ast.Node, expr string) bool {
	is_read := false
	ast.Inspect(outer_expr, func(node ast.Node) bool {
		switch typed_node := node.(type) {
		case *ast.CallExpr:
			// don't explore this branch
			return false
		case *ast.Ident:
			if typed_node.Name == expr {
				is_read = true
			}
		}
		return true
	})

	return is_read
}

/* Assuming lineno reads watchexpr's location, get expressions tainted by the read.
 * Accounts for aliased reads (i.e. those that don't match watchexpr). */
func taintedExprs(client *rpc2.RPCClient, watchexpr string, file string, lineno int, hit_bp *api.Breakpoint) (tainted_exprs []string) {
	fset := token.NewFileSet()
	root, err := parser.ParseFile(fset, file, nil, parser.SkipObjectResolution)
	if err != nil {
		log.Fatalf("Failed to parse source file %v: %v\n", file, err)
	}

	// Get hit idents while we're at hit PC (seems possible they could go out of scope on next PC)
	hit_idents := hitIdentifiers(client, fset, root, lineno, hit_bp)
	// Undo rev stepi, else we'll hit the watchpoint again when we try to step
	state, err := client.StepInstruction(false)
	if err != nil || state.Err != nil {
		log.Fatalf("Error restoring PC: %v\n", err)
	}

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

			// Get params in scope
			// Step into fct
			state, err := client.Step()
			if err != nil || state.Exited || state.Err != nil {
				log.Fatalf("Unexpected err %v or state %+v while stepping into %v\n", err, state, exprToString(typed_node.Fun))
			}
			// Param is "fake" at function entry => next into function body
			state, err = client.Next()
			if err != nil || state.Exited || state.Err != nil {
				log.Fatalf("Unexpected err %v or state %+v while nexting in %v\n", err, state, exprToString(typed_node.Fun))
			}

			for i, arg := range typed_node.Args {
				// Check if any hit_ident is read in arg
				hit_arg := false
				for _, hit_ident := range hit_idents {
					if readsExpr(arg, hit_ident) {
						hit_arg = true
					}
				}

				if !hit_arg {
					continue
				}

				// Watched location was passed as a param =>
				// taint callee's copy of param

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
			for i, ret := range typed_node.Results {
				// Check if any hit_ident is read in ret
				hit_ret := false
				for _, hit_ident := range hit_idents {
					if readsExpr(ret, hit_ident) {
						hit_ret = true
					}
				}

				if !hit_ret {
					continue
				}

				var assign_lineno int
				for i := 0; i < 2; i++ {
					// Get caller lhs in scope (next twice to handle :=)
					state, err = client.Next()
					if err != nil || state.Exited || state.Err != nil {
						log.Fatalf("Unexpected err %v or state %+v while nexting from ret\n", err, state)
					}
					if i == 0 {
						assign_lineno = state.SelectedGoroutine.CurrentLoc.Line
					}
				}
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
				for _, hit_ident := range hit_idents {
					if readsExpr(rhs, hit_ident) {
						hit_rhs = true
					}
				}
			}
			if hit_rhs {
				// Watched location is read on the rhs =>
				// taint lhs
				for _, lhs := range typed_node.Lhs {
					expr_str := exprToString(lhs)
					if expr_str != watchexpr {
						// next so lhs is in scope (handles :=)
						state, err := client.Next()
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
			}

		} // end switch

		return true
	})

	return tainted_exprs
}
