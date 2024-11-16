package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"log"
	"reflect"
	"strings"

	"github.com/go-delve/delve/pkg/proc"
	"github.com/go-delve/delve/service/api"
)

// Taint propagation logic

type TaintFlow uint8

const (
	DataFlow TaintFlow = 1 << iota
	ControlFlow
	DataAndControlFlow
)

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

// If calling line has an assign or range, return corresp lhs and the next line's location
// (TODO same caveats about linear assumption as for Assign)
func (tc *TaintCheck) callerLhs(i int) (*ast.Expr, api.Location) {
	stack, err := tc.client.Stacktrace(-1, 100, api.StacktraceSimple, &api.LoadConfig{})
	if err != nil {
		log.Fatalf("Error getting stacktrace: %v\n", err)
	}
	caller_frame := tc.hit.frame + 1
	call_file := stack[caller_frame].File
	call_line := stack[caller_frame].Line
	next_line := tc.lineWithStmt(nil, call_file, call_line+1, caller_frame)
	caller_lhs := getLhs(i, call_file, call_line)
	if caller_lhs == nil {
		tc.printStacktrace()
		log.Fatalf("Failed to find caller lhs; call file %v, call line %v (stacktrace above)\n", call_file, call_line)
	}
	return caller_lhs, next_line
}

/* If expr involves memory that overlaps the watched region,
 * ignoring function args (except builtins),
 * return the expression for the overlapping region, or "" if the entire region overlaps
 * (e.g. .field for struct, "" for int)
 * Requires expr to be in scope. */
func (tc *TaintCheck) isTainted(expr ast.Expr) *string {
	var overlap_expr *string
	found_overlap := ""
	composite_lit := false
	field_names := map[string]string{} // expr used to init field => field name

	ast.Inspect(expr, func(node ast.Node) bool {
		if overlap_expr != nil {
			return false // we're done
		}
		if node == nil {
			return true
		}
		switch typed_node := node.(type) {
		case *ast.CallExpr:
			if tc.handleAppend(typed_node) {
				overlap_expr = &found_overlap
			}
			return false
		case *ast.CompositeLit:
			// Evaluate children to check which field is tainted
			// Only support struct literal currently
			composite_lit = true
			for _, elt := range typed_node.Elts {
				kv := strings.Split(exprToString(elt), ":")
				field_names[strings.TrimSpace(kv[1])] = kv[0]
				// TODO support literal with unnamed fields
				// (parse struct type decl, or impl EvalVariable for CompositeLit?),
				// and multiple tainted fields
			}
		case ast.Expr:
			// TODO check for incomplete loads (see client API doc)
			// If type not supported, still check overlap (e.g. struct)
			// Use EvalWatchexpr rather than EvalVariable so watch-related fields (e.g. Watchsz and Addr) are set
			xv, err := tc.client.EvalWatchexpr(api.EvalScope{GoroutineID: -1, Frame: tc.hit.frame}, exprToString(node.(ast.Expr)), true)
			if err != nil {
				// Try evaluating any children
			} else {
				for _, watch_addr := range tc.hit.hit_bp.Addrs {
					watch_size := uint64((proc.WatchType)(tc.hit.hit_bp.WatchType).Size())
					xv_size := uint64(xv.Watchsz)

					if memOverlap(xv.Addr, xv_size, watch_addr, watch_size) {
						if composite_lit {
							if tainted_field, ok := field_names[exprToString(node.(ast.Expr))]; !ok {
								log.Fatalf("Failed to find field name for %v\n", exprToString(node.(ast.Expr)))
							} else {
								found_overlap = "." + tainted_field
							}
						}
						if xv.Kind == reflect.Struct {
							// TODO will this handle composite lit nested in a composite lit?
							// Take the first field that overlaps (TODO support multiple tainted fields)
							found_overlap += tc.taintedField(xv.Name, xv, watch_addr, watch_size)
						}

						overlap_expr = &found_overlap
					}
				}

				// Don't evaluate children
				// (at least for Index and Selector - haven't thought through others)
				return false
			}
		}
		return true
	})

	return overlap_expr
}

// For struct xv, find the fully-qualified name of its overlapping field, minus `name`
// (handling nested structs)
func (tc *TaintCheck) taintedField(name string, xv *api.Variable, watch_addr uint64, watch_size uint64) string {
	if xv.Kind != reflect.Struct {
		return ""
	}
	for _, field := range xv.Children {
		eval_name := name + "." + field.Name
		xv, err := tc.client.EvalWatchexpr(api.EvalScope{GoroutineID: -1, Frame: tc.hit.frame}, eval_name, true)
		if err == nil && memOverlap(xv.Addr, uint64(xv.Watchsz), watch_addr, watch_size) {
			name = "." + field.Name + tc.taintedField(eval_name, xv, watch_addr, watch_size)
		}
	}

	return name
}

var builtinFcts = map[string]bool{
	// Propagate taint
	"append": true, "copy": true,
	"min": true, "max": true,
	"imag": true, "complex": true,
	// Arguably propagate taint
	"len": true, "make": true,
	// Don't propagate taint
	"cap": true, "clear": true, "close": true,
	"delete": true, "new": true, "panic": true,
	"print": true, "println": true,
}

// Whether return value is tainted
func (tc *TaintCheck) handleAppend(call_node *ast.CallExpr) bool {
	// Any elem tainted, or slice already tainted => ret tainted
	// (handles possible realloc)
	if exprToString(call_node.Fun) != "append" {
		return false
	}
	for _, arg := range call_node.Args {
		if tc.isTainted(arg) != nil {
			return true
		}
	}
	return false
}

/* Assuming this line hits a watchpoint, record pending watchpoints for newly tainted exprs on line.
 * Accounts for aliased reads (i.e. those that don't match hit_bp.WatchExpr). */
func (tc *TaintCheck) propagateTaint() {
	fset := token.NewFileSet()
	root, err := parser.ParseFile(fset, tc.hit.hit_instr.Loc.File, nil, parser.SkipObjectResolution)
	if err != nil {
		log.Fatalf("Failed to parse source file %v: %v\n", tc.hit.hit_instr.Loc.File, err)
	}

	// DFS of file's AST
	ast.Inspect(root, func(node ast.Node) bool {
		// PERF: How to properly only inspect one line?
		var start token.Position
		var end token.Position
		if node != nil {
			start = fset.Position(node.Pos())
			end = fset.Position(node.End())
		}
		hit_line := tc.hit.hit_instr.Loc.Line
		if !(start.Line <= hit_line && hit_line <= end.Line) {
			return true
		}
		// hit line is part of node

		switch typed_node := node.(type) {

		case *ast.CallExpr:
			fn := exprToString(typed_node.Fun)
			if fn == "copy" {
				if tc.isTainted(typed_node.Args[1]) != nil {
					// Expr will be in scope, but can't set wp yet if runtime hit (often is, in memmove) -
					// wps set from a newer frame will go OOS when exit that frame
					pending_loc := tc.lineWithStmt(nil, start.Filename, start.Line+1, tc.hit.frame)
					tc.recordPendingWp(exprToString(typed_node.Args[0]), pending_loc, nil)
				}
			} else if builtinFcts[fn] || fn == "runtime.KeepAlive" {
				// append will be handled in assign/range
			} else {
				full_args := typed_node.Args
				if recvr_name, _, isMethod := strings.Cut(fn, "."); isMethod {
					// method => check receiver for taint, and
					// count it in args to match what we'll do when creating wp
					recvr := ast.Ident{NamePos: typed_node.Pos(), Name: recvr_name} // printable
					full_args = append([]ast.Expr{&recvr}, full_args...)
				}
				for i, arg := range full_args {
					if overlap_expr := tc.isTainted(arg); overlap_expr != nil { // caller arg tainted => propagate to callee arg
						// TODO handle passing param to func lit not assigned to variable (e.g. goroutine in funclit test)
						// First line of function body (params are "fake" at declaration line)
						pending_loc := tc.lineWithStmt(&fn, "", -1, tc.hit.frame)
						tc.recordPendingWp(*overlap_expr, pending_loc, &i)
					}
				}
			}

		case *ast.ReturnStmt:
			// Watched location is read in return value =>
			// taint corresponding assign lhs/range value in caller, if any
			// TODO handle function composition (for builtins too - will need diff handling)
			for i, ret := range typed_node.Results {
				if overlap_expr := tc.isTainted(ret); overlap_expr != nil {
					caller_lhs, caller_loc := tc.callerLhs(i)
					// Line after calling line
					watchexpr := exprToString(*caller_lhs) + *overlap_expr
					tc.recordPendingWp(watchexpr, caller_loc, nil)
				}
			}

		// May not be next line linearly for := in flow control statement
		// but if not, var immediately went out of scope so we don't need a wp anyway
		// TODO except for if/else, maybe others
		// And Range: If next line is }, set on next iter
		// Need to handle case where never enter loop (never hit bp => main never terminates)
		// ^ When fix this - keep in mind that wps go OOS when exit frame they're set in -
		// so don't e.g. set a wp for a runtime hit while in the runtime frame (runtime_hits tests checks this)
		case *ast.AssignStmt:
			for _, rhs := range typed_node.Rhs {
				// TODO properly handle multiple rhs (unsure of semantics)
				if overlap_expr := tc.isTainted(rhs); overlap_expr != nil {
					// Watched location is read on the rhs => taint lhs
					pending_loc := tc.lineWithStmt(nil, end.Filename, end.Line+1, tc.hit.frame)
					for _, lhs := range typed_node.Lhs {
						watchexpr := exprToString(lhs) + *overlap_expr
						tc.recordPendingWp(watchexpr, pending_loc, nil)
					}
				}
			}
		case *ast.RangeStmt:
			// TODO handle Range properly (once support tainted composite types in delve):
			// If only part of the rhs is tainted, value expr should only be tainted on corresp iters
			if tc.isTainted(typed_node.X) != nil && typed_node.Value != nil {
				// Watched location is read on the rhs =>
				// taint value expr
				pending_loc := tc.lineWithStmt(nil, start.Filename, start.Line+1, tc.hit.frame)
				tc.recordPendingWp(exprToString(typed_node.Value), pending_loc, nil)
			}
		} // end switch

		return true
	})
}
