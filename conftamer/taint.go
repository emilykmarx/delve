package conftamer

import (
	"go/ast"
	"go/parser"
	"go/token"
	"log"
	"reflect"
	"strings"

	"github.com/go-delve/delve/service/api"
	"github.com/hashicorp/go-set"
)

// Taint propagation logic

type TaintFlow string

const (
	DataFlow    TaintFlow = "Data Flow"
	ControlFlow TaintFlow = "Control Flow"
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

// TODO (future) consider making tests more organized - e.g. split into "isTainted" and "propagateTaint",
// so don't need to e.g. write an assign and range test for every new construct
// (e.g. don't have a test for return callexpr/cast)

/* If expr involves memory that overlaps the watched region,
 * ignoring function args (except builtins),
 * return the expression for the overlapping region, or "" if the entire region overlaps
 * (e.g. .field for struct, "" for int).
 * Also return the start&end addresses of the overlapping region.
 * Requires expr to be in scope.
 * If in branch body, always overlap. */
func (tc *TaintCheck) isTainted(expr ast.Expr) (*string, uint64, uint64) {
	if tc.hit.hit_bp.WatchType == 0 {
		// We've been called for a bp hit in a branch body (not a wp hit)
		overlap_expr := ""
		return &overlap_expr, 0, 0
	}

	var overlap_expr *string
	found_overlap := ""
	var overlap_start, overlap_end uint64
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
			if arg_addr := tc.handleAppend(typed_node); arg_addr != 0 {
				// For now, just apply taint from start addr of last tainted arg to whole array
				overlap_expr = &found_overlap
				overlap_start = arg_addr
				// Preserve taint of old slice, append taint of new elems
			} else if !casts.Contains(exprToString(typed_node.Fun)) {
				// casted expr is tainted if its arg is
				return false
			}
		case *ast.CompositeLit:
			// Evaluate children to check which field is tainted
			composite_lit = true
			for _, elt := range typed_node.Elts {
				kv := strings.Split(exprToString(elt), ":")
				field_names[strings.TrimSpace(kv[1])] = kv[0]
			}
		case ast.Expr:
			// TODO check for incomplete loads (see client API doc)
			// If type not supported, still check overlap (e.g. struct)
			// Use EvalWatchexpr rather than EvalVariable so watch-related fields (e.g. Watchsz and Addr) are set
			xv, err := tc.client.EvalWatchexpr(api.EvalScope{GoroutineID: -1, Frame: tc.hit.frame}, exprToString(node.(ast.Expr)), true)
			if err != nil {
				// Try evaluating any children (for e.g. `x+1`)
			} else {
				watch_addr := tc.hit.hit_bp.Addr
				watch_size := watchSize(tc.hit.hit_bp)
				xv_size := uint64(xv.Watchsz)

				var overlap bool
				overlap_start, overlap_end, overlap = memOverlap(xv.Addr, xv_size, watch_addr, watch_size)
				if overlap {
					if composite_lit {
						if tainted_field, ok := field_names[exprToString(node.(ast.Expr))]; !ok {
							log.Fatalf("Failed to find field name for %v\n", exprToString(node.(ast.Expr)))
						} else {
							found_overlap = "." + tainted_field
						}
					}
					if xv.Kind == reflect.Struct {
						found_overlap += tc.taintedField(xv.Name, xv, watch_addr, watch_size)
					}

					overlap_expr = &found_overlap
				}

				// Don't evaluate children
				// (at least for Index and Selector - haven't thought through others)
				return false
			}
		}
		return true
	})

	return overlap_expr, overlap_start, overlap_end
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
		if err == nil {
			if _, _, overlap := memOverlap(xv.Addr, uint64(xv.Watchsz), watch_addr, watch_size); overlap {
				name = "." + field.Name + tc.taintedField(eval_name, xv, watch_addr, watch_size)
			}
		}
	}

	return name
}

// TODO handle the rest that do propagate
var builtinFcts = set.From([]string{
	// Propagate taint
	"append", "copy",
	"min", "max",
	"imag", "complex",
	// Arguably propagate taint
	"len", "make",
	// Don't propagate taint
	"cap", "clear", "close",
	"delete", "new", "panic",
	"print", "println",
})

var casts = set.From([]string{
	"bool",
	"string",
	"int", "int8", "int16", "int32", "int64",
	"uint", "uint8", "uint16", "uint32", "uint64", "uintptr",
	"byte",
	"rune",
	"float32", "float64",
	"complex64", "complex128",
})

// If return value is tainted by any arg, return start addr of last tainted arg
func (tc *TaintCheck) handleAppend(call_node *ast.CallExpr) uint64 {
	// Any elem tainted, or slice already tainted => ret tainted
	// (handles possible realloc)
	if exprToString(call_node.Fun) != "append" {
		return 0
	}
	for _, arg := range call_node.Args {
		if overlap_expr, overlap_start, _ := tc.isTainted(arg); overlap_expr != nil {
			return overlap_start
		}
	}
	return 0
}

/* Assuming this line hits a watchpoint (or we're in a branch body),
 * record pending watchpoints for newly tainted exprs on line.
 * Accounts for aliased reads (i.e. those that don't match hit_bp.WatchExpr). */
func (tc *TaintCheck) propagateTaint() {
	file, line, _ := tc.hitLocation()

	fset := token.NewFileSet()
	root, err := parser.ParseFile(fset, file, nil, parser.SkipObjectResolution)
	if err != nil {
		log.Fatalf("Failed to parse source file %v: %v\n", file, err)
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
		if !(start.Line <= line && line <= end.Line) {
			return true
		}
		// hit line is part of node

		switch typed_node := node.(type) {
		case *ast.IfStmt:
			if start.Line == line {
				else_start := 0
				// Enter if[else] => record pending wp for beginning of both if and else branch bodies
				body_end := fset.Position(typed_node.Body.Rbrace).Line - 1
				if typed_node.Else != nil {
					else_node := typed_node.Else.(*ast.BlockStmt)
					body_end = fset.Position(else_node.Rbrace).Line - 1
					else_start = fset.Position(else_node.Pos()).Line + 1
				}
				body_start := line + 1
				pending_loc := tc.lineWithStmt(nil, start.Filename, body_start, tc.hit.frame)
				overlap_expr, overlap_start, overlap_end := tc.isTainted(typed_node.Cond)
				if overlap_expr == nil {
					// Shouldn't be, since we just hit a wp for if condition
					log.Panicf("Hit wp for ifStmt %+v, but isTainted didn't find taint", typed_node.Cond)
				}
				tc.recordPendingWp("", pending_loc, nil, body_start, body_end, overlap_start, overlap_end)
				if else_start != 0 {
					pending_loc := tc.lineWithStmt(nil, start.Filename, else_start, tc.hit.frame)
					tc.recordPendingWp("", pending_loc, nil, body_start, body_end, overlap_start, overlap_end)
				}
			}

		case *ast.CallExpr:
			call_expr := exprToString(typed_node.Fun)
			if call_expr == "copy" {
				if overlap_expr, overlap_start, overlap_end := tc.isTainted(typed_node.Args[1]); overlap_expr != nil {
					// Copies min(len(new), len(old)). So if old is longer, and this is a config load, shorten overlap to new.
					// (If not config load, doesn't matter since we'll store old's taint byte-by-byte.)
					xv, err := tc.client.EvalWatchexpr(api.EvalScope{GoroutineID: -1, Frame: tc.hit.frame}, exprToString(typed_node.Args[0]), true)
					if err != nil {
						// I think new should always be evaluatable?
						log.Panicf("eval %v for copy builtin: %v", exprToString(typed_node.Args[0]), err)
					}
					overlap_end = min(overlap_start+uint64(xv.Watchsz), overlap_end)

					// Expr will be allocated, but if on stack and runtime hit, need to set wp in correct scope, so stack OOS watchpoints
					// are set correctly (TODO add test for this)
					pending_loc := tc.lineWithStmt(nil, start.Filename, start.Line+1, tc.hit.frame)
					tc.recordPendingWp(exprToString(typed_node.Args[0]), pending_loc, nil, 0, 0, overlap_start, overlap_end)
				}
			} else if builtinFcts.Contains(call_expr) || casts.Contains(call_expr) || call_expr == "runtime.KeepAlive" {
				// builtins will be handled in assign/range
			} else {
				// If method: check receiver for taint if non-pointer, and
				// count it in args to match what we'll do when creating wp
				pending_loc := tc.lineWithStmt(&call_expr, "", -1, tc.hit.frame)
				for i, arg := range tc.fullArgs(typed_node) {
					if overlap_expr, overlap_start, overlap_end := tc.isTainted(arg); overlap_expr != nil { // caller arg tainted => propagate to callee arg
						// TODO handle passing param to func lit not assigned to variable (e.g. goroutine in funclit test)
						// First line of function body (params are "fake" at declaration line)
						tc.recordPendingWp(*overlap_expr, pending_loc, &i, 0, 0, overlap_start, overlap_end)
					}
				}
			}

		case *ast.ReturnStmt:
			// Watched location is read in return value =>
			// taint corresponding assign lhs/range value in caller, if any
			// TODO handle function composition (for builtins too - will need diff handling)
			for i, ret := range typed_node.Results {
				if overlap_expr, overlap_start, overlap_end := tc.isTainted(ret); overlap_expr != nil {
					caller_lhs, caller_loc := tc.callerLhs(i)
					// Line after calling line
					watchexpr := exprToString(*caller_lhs) + *overlap_expr
					tc.recordPendingWp(watchexpr, caller_loc, nil, 0, 0, overlap_start, overlap_end)
				}
			}

		// May not be next line linearly for := in flow control statement
		// but if not, var immediately went out of scope so we don't need a wp anyway
		// TODO except for if/else (e.g. if{x=1}else{x=2}), maybe others
		// And Range: If next line is }, set on next iter
		// Need to handle case where never enter loop (never hit bp => main never terminates)
		// ^ When fix this - keep in mind that wps go OOS when exit frame they're set in -
		// so don't e.g. set a wp for a runtime hit while in the runtime frame (runtime_hits tests checks this)
		case *ast.AssignStmt:
			for _, rhs := range typed_node.Rhs {
				// TODO properly handle multiple rhs (unsure of semantics)
				if overlap_expr, overlap_start, overlap_end := tc.isTainted(rhs); overlap_expr != nil {
					// Watched location is read on the rhs => taint lhs
					pending_loc := tc.lineWithStmt(nil, end.Filename, end.Line+1, tc.hit.frame)
					for _, lhs := range typed_node.Lhs {
						watchexpr := exprToString(lhs) + *overlap_expr
						tc.recordPendingWp(watchexpr, pending_loc, nil, 0, 0, overlap_start, overlap_end)
					}
				}
			}
		case *ast.RangeStmt:
			// TODO handle Range properly (once support tainted composite types in delve):
			// If only part of the rhs is tainted, value expr should only be tainted on corresp iters
			if overlap_expr, overlap_start, overlap_end := tc.isTainted(typed_node.X); overlap_expr != nil && typed_node.Value != nil {
				// Watched location is read on the rhs =>
				// taint value expr
				pending_loc := tc.lineWithStmt(nil, start.Filename, start.Line+1, tc.hit.frame)
				tc.recordPendingWp(exprToString(typed_node.Value), pending_loc, nil, 0, 0, overlap_start, overlap_end)
			}
		} // end switch

		return true
	})
}
