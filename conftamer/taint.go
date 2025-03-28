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

// Assuming calling line has an assign or range, return corresp lhs and the next line's location
// (TODO same caveats about linear assumption as for Assign)
func (tc *TaintCheck) callerLhs(i int, frame int) (*ast.Expr, api.Location) {
	stack, err := tc.client.Stacktrace(-1, 100, api.StacktraceSimple, &api.LoadConfig{})
	if err != nil {
		log.Fatalf("Error getting stacktrace: %v\n", err)
	}
	caller_frame := frame + 1
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
 * Also return the start&end addresses of the overlapping region, and true if multiline composite lit.
 * Requires expr to be in scope.
 * If in branch body, always overlap. */
func (tc *TaintCheck) isTainted(expr ast.Expr, hit *Hit, fset *token.FileSet) (*string, uint64, uint64, bool) {
	if hit == nil {
		overlap_expr := ""
		return &overlap_expr, 0, 0, false
	}

	var overlap_expr *string
	found_overlap := ""
	var overlap_start, overlap_end uint64
	var composite_lit, multiline_composite_lit bool
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
			if arg_addr := tc.handleAppend(typed_node, hit, fset); arg_addr != 0 {
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
			rbrace := fset.Position(typed_node.Rbrace).Line
			lbrace := fset.Position(typed_node.Lbrace).Line
			multiline_composite_lit = rbrace > lbrace
		case ast.Expr:
			// TODO check for incomplete loads (see client API doc)
			// If type not supported, still check overlap (e.g. struct)
			// Use EvalWatchexpr rather than EvalVariable so watch-related fields (e.g. Watchsz and Addr) are set
			xv, err := tc.client.EvalWatchexpr(api.EvalScope{GoroutineID: -1, Frame: hit.frame}, exprToString(node.(ast.Expr)), true)
			if err != nil {
				// Try evaluating any children (for e.g. `x+1`)
			} else {
				watch_addr := hit.hit_bp.Addr
				watch_size := watchSize(hit.hit_bp)
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
						found_overlap += tc.taintedField(xv.Name, xv, watch_addr, watch_size, hit.frame)
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

	return overlap_expr, overlap_start, overlap_end, multiline_composite_lit
}

// For struct xv, find the fully-qualified name of its overlapping field, minus `name`
// (handling nested structs)
func (tc *TaintCheck) taintedField(name string, xv *api.Variable, watch_addr uint64, watch_size uint64, frame int) string {
	if xv.Kind != reflect.Struct {
		return ""
	}
	for _, field := range xv.Children {
		eval_name := name + "." + field.Name
		xv, err := tc.client.EvalWatchexpr(api.EvalScope{GoroutineID: -1, Frame: frame}, eval_name, true)
		if err == nil {
			if _, _, overlap := memOverlap(xv.Addr, uint64(xv.Watchsz), watch_addr, watch_size); overlap {
				name = "." + field.Name + tc.taintedField(eval_name, xv, watch_addr, watch_size, frame)
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
func (tc *TaintCheck) handleAppend(call_node *ast.CallExpr, hit *Hit, fset *token.FileSet) uint64 {
	// Any elem tainted, or slice already tainted => ret tainted
	// (handles possible realloc)
	if exprToString(call_node.Fun) != "append" {
		return 0
	}
	for _, arg := range call_node.Args {
		if overlap_expr, overlap_start, _, _ := tc.isTainted(arg, hit, fset); overlap_expr != nil {
			return overlap_start
		}
	}
	return 0
}

// Add first line of branch body to locs, and return last line of branch body
// TODO also check for wp hits in each elseif
func (tc *TaintCheck) handleIfStmt(branch ast.Node, fset *token.FileSet, locs *[]api.Location, frame int) int {
	start := fset.Position(branch.Pos()).Line
	file := fset.File(branch.Pos()).Name()
	body_start := tc.lineWithStmt(nil, file, start+1, frame)
	*locs = append(*locs, body_start)
	// Will traverse bodies in linear order
	switch typed_node := branch.(type) {
	case *ast.IfStmt:
		// if/elseif
		body_end := fset.Position(typed_node.Body.Rbrace).Line - 1
		if typed_node.Else != nil {
			body_end = tc.handleIfStmt(typed_node.Else, fset, locs, frame)
		}
		return body_end
	case *ast.BlockStmt:
		// else
		return fset.Position(typed_node.Rbrace).Line - 1
	default:
		log.Panicf("Unhandled branch type %+v\n", typed_node)
		return 0
	}
}

/* Assuming this line hits a watchpoint (or we're in a branch body),
 * record pending watchpoints for newly tainted exprs on line.
 * Either set a breakpoint for when to set watchpoint (e.g. function args), or
 * record sequence of commands needed - e.g. lhs of :=, or a reference
 * (since we watch its target which is about to change), runtime hit. */
func (tc *TaintCheck) propagateTaint(file string, line int, hit *Hit, frame int) {
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
				// Enter if[elseif/else] => set up state so we'll next through the branch body
				locs := []api.Location{}
				body_end := tc.handleIfStmt(typed_node, fset, &locs, frame)
				overlap_expr, overlap_start, overlap_end, _ := tc.isTainted(typed_node.Cond, hit, fset)
				if overlap_expr == nil {
					// Shouldn't be, since we just hit a wp for if condition
					log.Panicf("Hit wp for ifStmt %+v, but isTainted didn't find taint", typed_node.Cond)
				}

				tc.pendingWatchpoint(tc.cmd_pending_wp, "", nil, locs[0].Line, body_end, overlap_start, overlap_end, hit)
			}

		case *ast.CallExpr:
			call_expr := exprToString(typed_node.Fun)
			if call_expr == "copy" {
				if overlap_expr, overlap_start, overlap_end, _ := tc.isTainted(typed_node.Args[1], hit, fset); overlap_expr != nil {
					// Copies min(len(new), len(old)). So if new is shorter, shorten overlap and watchexpr.
					xv, err := tc.client.EvalWatchexpr(api.EvalScope{GoroutineID: -1, Frame: frame}, exprToString(typed_node.Args[0]), true)
					if err != nil {
						// I think new should always be evaluatable?
						log.Panicf("eval %v for copy builtin: %v", exprToString(typed_node.Args[0]), err)
					}
					overlap_end = min(overlap_start+uint64(xv.Watchsz), overlap_end)

					// Expr will be allocated, but if on stack and runtime hit, need to set wp in correct scope, so stack OOS watchpoints
					// are set correctly (TODO add test for this)
					pending_loc := tc.lineWithStmt(nil, start.Filename, start.Line+1, frame)
					existing_info := tc.bp_pending_wps[pending_loc.PCs[0]]
					tc.pendingWatchpoint(&existing_info, exprToString(typed_node.Args[0]), nil, 0, 0, overlap_start, overlap_end, hit)
					tc.bp_pending_wps[pending_loc.PCs[0]] = existing_info
					tc.setBp(pending_loc.PCs[0])
				}
			} else if builtinFcts.Contains(call_expr) || casts.Contains(call_expr) || call_expr == "runtime.KeepAlive" {
				// builtins will be handled in assign/range
			} else {
				// If method: check receiver for taint if non-pointer, and
				// count it in args to match what we'll do when creating wp
				pending_loc := tc.lineWithStmt(&call_expr, "", 0, frame)
				for i, arg := range tc.fullArgs(typed_node, file, frame) {
					if overlap_expr, overlap_start, overlap_end, _ := tc.isTainted(arg, hit, fset); overlap_expr != nil { // caller arg tainted => propagate to callee arg
						// TODO handle passing param to func lit not assigned to variable (e.g. goroutine in funclit test)
						// First line of function body (params are "fake" at declaration line)
						existing_info := tc.bp_pending_wps[pending_loc.PCs[0]]
						tc.pendingWatchpoint(&existing_info, *overlap_expr, &i, 0, 0, overlap_start, overlap_end, hit)
						tc.bp_pending_wps[pending_loc.PCs[0]] = existing_info
						tc.setBp(pending_loc.PCs[0])
					}
				}
			}

		case *ast.ReturnStmt:
			// Watched location is read in return value =>
			// taint corresponding assign lhs/range value in caller, if any
			// TODO handle function composition (for builtins too - will need diff handling)
			for i, ret := range typed_node.Results {
				if overlap_expr, overlap_start, overlap_end, _ := tc.isTainted(ret, hit, fset); overlap_expr != nil {
					caller_lhs, caller_loc := tc.callerLhs(i, frame)
					// Line after calling line
					watchexpr := exprToString(*caller_lhs) + *overlap_expr
					existing_info := tc.bp_pending_wps[caller_loc.PCs[0]]
					tc.pendingWatchpoint(&existing_info, watchexpr, nil, 0, 0, overlap_start, overlap_end, hit)
					tc.bp_pending_wps[caller_loc.PCs[0]] = existing_info
					tc.setBp(caller_loc.PCs[0])
				}
			}

		case *ast.AssignStmt:
			for _, rhs := range typed_node.Rhs {
				// TODO properly handle multiple rhs (unsure of semantics)
				if overlap_expr, overlap_start, overlap_end, multiline_composite_lit := tc.isTainted(rhs, hit, fset); overlap_expr != nil {
					// Watched location is read on the rhs => taint lhs
					for _, lhs := range typed_node.Lhs {
						watchexpr := exprToString(lhs) + *overlap_expr
						// If multiline composite lit, next can take us back to assign line, but setting immediately seems to work (only if multiline)
						if multiline_composite_lit {
							pending_wp := PendingWp{}
							tc.pendingWatchpoint(&pending_wp, watchexpr, nil, 0, 0, overlap_start, overlap_end, hit)
							tc.setPendingWatchpoints(&pending_wp, hit.thread, hit.frame)
						} else {
							tc.pendingWatchpoint(tc.cmd_pending_wp, watchexpr, nil, 0, 0, overlap_start, overlap_end, hit)
						}
					}
				}
			}
		case *ast.RangeStmt:
			// TODO handle Range properly (once support tainted composite types in delve):
			// If only part of the rhs is tainted, value expr should only be tainted on corresp iters
			if overlap_expr, overlap_start, overlap_end, _ := tc.isTainted(typed_node.X, hit, fset); overlap_expr != nil && typed_node.Value != nil {
				// Watched location is read on the rhs =>
				// taint value expr
				pending_loc := tc.lineWithStmt(nil, start.Filename, start.Line+1, frame)
				existing_info := tc.bp_pending_wps[pending_loc.PCs[0]]
				tc.pendingWatchpoint(&existing_info, exprToString(typed_node.Value), nil, 0, 0, overlap_start, overlap_end, hit)
				tc.bp_pending_wps[pending_loc.PCs[0]] = existing_info
				tc.setBp(pending_loc.PCs[0])
			}
		} // end switch

		return true
	})
}
