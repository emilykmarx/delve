package conftamer

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"log"
	"log/slog"
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

// A tainted memory region to be watched
type TaintedRegion struct {
	// The overlapping region
	overlap_expr  *string // tainted expression (if arg, an expression to be appended to the callee's arg)
	overlap_arg   *int    // index of tainted arg
	overlap_start uint64
	overlap_end   uint64

	// Where watchpoint can be set
	// Immediately, once found (unless runtime hit)
	set_now bool
	// Location, if can be found statically
	set_location *api.Location
	// Sequence of commands needed, if must find dynamically
	cmds []Command

	// If region is in branch condition, the branch body
	body_start int
	body_end   int
}

// Get the ith lhs of an assign/range on lineno, if any
// If lineno instead has return or if stmt, return the node
// TODO test "_"
func getLhs(i int, file string, lineno int) (lhs *ast.Expr, caller_node *ast.Node) {
	fset := token.NewFileSet()
	root, err := parser.ParseFile(fset, file, nil, parser.SkipObjectResolution)
	if err != nil {
		log.Panicf("Failed to parse source file %v: %v\n", file, err)
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

		case *ast.ReturnStmt:
			caller_node = &node

		case *ast.IfStmt:
			caller_node = &node
		}

		return true
	})

	return lhs, caller_node
}

// Assuming hit was for a return stmt, populate cmd sequence to reach
// where the return value is assigned (via assign or range),
// or used as condition in if statement.
// Includes skipping any lines of the form `return f()`.
// Return true if we support this form of propagation -
// TODO handle function composition (for builtins too - will need diff handling). Any others?
func (tc *TaintCheck) propagateReturn(lhs_i int, hit *Hit, tainted_region *TaintedRegion) bool {
	tainted_region.cmds = runtime_stepout_cmd_seq(hit)

	stack := tc.stacktrace()
	fmt.Printf("propagateReturn - hit %+v\n", *hit)
	tc.printStacktrace()
	var caller_lhs *ast.Expr
	var caller_node *ast.Node

	// Check caller frame for assign/range, if stmt, or return stmt
	// (loop is just to handle any additional return stmts)
	for caller_frame := len(tainted_region.cmds); caller_frame < len(stack); caller_frame++ {
		found_ret := false // whether current frame has a return stmt
		call_file := stack[caller_frame].File
		call_line := stack[caller_frame].Line
		caller_lhs, caller_node = getLhs(lhs_i, call_file, call_line)
		if caller_lhs == nil && caller_node == nil {
			tc.printStacktrace()
			// Indicates caller catches tainted return value in a way we haven't handled
			tc.Logf(slog.LevelWarn, hit, "Failed to find caller lhs; call file %v, call line %v (stacktrace above)\n", call_file, call_line)
			return false
		}
		stack_len := hit.stack_len - caller_frame

		if caller_lhs != nil {
			watchexpr := exprToString(*caller_lhs) + *tainted_region.overlap_expr
			tainted_region.overlap_expr = &watchexpr
		} else if _, ok := (*caller_node).(*ast.ReturnStmt); ok {
			// Propagate to next frame
			// Nexting from return exits its stack frame => expect to be in caller frame
			stack_len -= 1
			found_ret = true
		} else if ifstmt, ok := (*caller_node).(*ast.IfStmt); ok {
			// If stmt => set up to next through it as if the condition hit a watchpoint
			locs := []int{}
			fset := token.NewFileSet()
			parser.ParseFile(fset, call_file, nil, parser.SkipObjectResolution)
			tc.handleIfStmt(ifstmt, fset, &locs, tainted_region, caller_frame)
		} else {
			log.Panicf("getLhs returned unhandled node %+v\n", *caller_node)
		}

		// Next from assign/ret/if
		caller_next := Command{cmd: api.Next, stack_len: stack_len, lineno: call_line}
		tainted_region.cmds = append(tainted_region.cmds, caller_next)

		if !found_ret {
			break
		}
	}

	fmt.Printf("propagateReturn return %+v\n", *tainted_region)
	return true
}

// Handle types with reference elements
func (tc *TaintCheck) evalWatchExprRecursive(scope api.EvalScope, expr string, vars *[]*api.Variable) error {
	xv, err := tc.client.EvalWatchexpr(scope, expr, true)
	if err != nil {
		return err
	}

	if xv.ElemsAreReferences {
		// Make recursive call for each element
		for i := 0; i < int(xv.Len); i++ {
			elem := fmt.Sprintf("%v[%v]", expr, i)
			if err := tc.evalWatchExprRecursive(scope, elem, vars); err != nil {
				return err
			}
		}
	} else {
		*vars = append(*vars, xv)
	}

	return nil
}

// TODO (future) consider making tests more organized - e.g. split into "isTainted" and "propagateTaint",
// so don't need to e.g. write an assign and range test for every new construct
// (e.g. don't have a test for return callexpr/cast)

/* If expr involves memory that overlaps the watched region,
 * ignoring function calls (except append and casts),
 * return overlapping region (watchexpr will be the overlapping portion of expr, "" if full -
 * propagateTaint will prepend the relevant expr as needed).
 * Requires expr to be in scope.
 * If in branch body, always overlap. */
func (tc *TaintCheck) isTainted(expr ast.Expr, hit *Hit, fset *token.FileSet) *TaintedRegion {
	tainted_region := TaintedRegion{} // to be populated, if region is tainted
	found_overlap := ""               //  the expression for the overlapping region, or "" if the entire region overlaps
	// (e.g. .field for struct, "" for int)

	if hit.hit_bp == nil {
		// Finished next in branch body
		tainted_region.overlap_expr = &found_overlap
		return &tainted_region
	}

	composite_lit := false
	field_names := map[string]string{} // expr used to init field => field name

	ast.Inspect(expr, func(node ast.Node) bool {
		if tainted_region.overlap_expr != nil {
			return false // we're done
		}
		if node == nil {
			return true
		}
		switch typed_node := node.(type) {
		case *ast.CallExpr:
			if arg_addr := tc.handleAppend(typed_node, hit, fset); arg_addr != 0 {
				// For now, just apply taint from start addr of last tainted arg to whole array
				tainted_region.overlap_expr = &found_overlap
				tainted_region.overlap_start = arg_addr
				// Preserve taint of old slice, append taint of new elems
			} else if !tc.isCast(typed_node) {
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
			// Multiline composite lit => next can take us back to assign line, but setting immediately seems to work (only if multiline)
			tainted_region.set_now = rbrace > lbrace
		case ast.Expr:
			// TODO check for incomplete loads (see client API doc)
			// If type not supported, still check overlap (e.g. struct)
			// Use EvalWatchexpr rather than EvalVariable so watch-related fields (e.g. Watchsz and Addr) are set
			xvs := []*api.Variable{}
			fmt.Printf("ZZEM eval %v\n", exprToString(node.(ast.Expr)))
			err := tc.evalWatchExprRecursive(hit.scope, exprToString(node.(ast.Expr)), &xvs)
			if err != nil {
				fmt.Printf("eval err: %v\n", err.Error())
				// Try evaluating any AST children (for e.g. `x+1`)
			} else {
				for _, xv := range xvs {
					watch_addr := hit.hit_bp.Addr
					watch_size := watchSize(hit.hit_bp)
					xv_size := uint64(xv.Watchsz)
					fmt.Printf("watch region %#x:%v, xv %#x:%v\n", watch_addr, watch_size, xv.Addr, xv_size)

					var overlap bool
					tainted_region.overlap_start, tainted_region.overlap_end, overlap = memOverlap(xv.Addr, xv_size, watch_addr, watch_size)
					if overlap {
						if composite_lit {
							if tainted_field, ok := field_names[exprToString(node.(ast.Expr))]; !ok {
								log.Panicf("Failed to find field name for %v\n", exprToString(node.(ast.Expr)))
							} else {
								found_overlap = "." + tainted_field
							}
						}
						if xv.Kind == reflect.Struct {
							found_overlap += tc.taintedField(xv.Name, xv, watch_addr, watch_size, hit.scope.Frame)
						}

						tainted_region.overlap_expr = &found_overlap
					}
				}

				// Don't evaluate children
				// (at least for Index and Selector - haven't thought through others)
				return false
			}
		}
		return true
	})

	if tainted_region.overlap_expr != nil {
		fmt.Printf("isTainted return %+v\n", tainted_region)
		return &tainted_region
	} else {
		fmt.Printf("isTainted return nil\n")
		return nil
	}
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

// If return value is tainted by any arg, return start addr of last tainted arg
func (tc *TaintCheck) handleAppend(call_node *ast.CallExpr, hit *Hit, fset *token.FileSet) uint64 {
	// Any elem tainted, or slice already tainted => ret tainted
	// (handles possible realloc)
	if exprToString(call_node.Fun) != "append" {
		return 0
	}
	for _, arg := range call_node.Args {
		if tainted_region := tc.isTainted(arg, hit, fset); tainted_region != nil {
			return tainted_region.overlap_start
		}
	}
	return 0
}

// Update start and end of branch body in tainted_region and in tc, and clear tainted_region's overlap_expr
func (tc *TaintCheck) handleIfStmt(branch ast.Node, fset *token.FileSet, body_starts *[]int, tainted_region *TaintedRegion, frame int) {
	tainted_region.overlap_expr = nil // isTainted populated it with ""
	start := fset.Position(branch.Pos()).Line
	file := fset.File(branch.Pos()).Name()
	body_start := tc.lineWithStmt(file, start+1, frame)
	*body_starts = append(*body_starts, body_start.Line)
	tainted_region.body_start = (*body_starts)[0]
	tc.body_start = tainted_region.body_start
	// Will traverse bodies in linear order
	switch typed_node := branch.(type) {
	case *ast.IfStmt:
		// if/elseif
		tainted_region.body_end = fset.Position(typed_node.Body.Rbrace).Line - 1
		tc.body_end = tainted_region.body_end
		if typed_node.Else != nil {
			tc.handleIfStmt(typed_node.Else, fset, body_starts, tainted_region, frame)
		}
	case *ast.BlockStmt:
		// else
		tainted_region.body_end = fset.Position(typed_node.Rbrace).Line - 1
		tc.body_end = tainted_region.body_end
	default:
		log.Panicf("Unhandled branch type %+v\n", typed_node)
	}
}

// The command sequence needed to reach the next line in first non-runtime frame
func next_cmd_seq(hit *Hit) []Command {
	next_cmd := Command{cmd: api.Next, stack_len: hit.stack_len - hit.scope.Frame, lineno: hit.hit_instr.Loc.Line}
	return append(runtime_stepout_cmd_seq(hit), next_cmd)
}

// The command sequence needed to stepout of runtime
// If not setting breakpoint (i.e. "set now" or seq of commands), must always stepout of runtime first
func runtime_stepout_cmd_seq(hit *Hit) []Command {
	runtime_cmds := []Command{}
	if hit.scope.Frame > 0 {
		// runtime hit => prepend stepouts and adjust frame for next
		for i := 1; i <= hit.scope.Frame; i++ {
			stack_len := hit.stack_len - i
			runtime_cmds = append(runtime_cmds, Command{cmd: api.StepOut, stack_len: stack_len})
		}
	}
	return runtime_cmds
}

/* Assuming this line hits a watchpoint (or we're in a branch body),
 * return the expression on the line that is newly tainted as a result (only support one).
 * Also populate ret with info on when new watchpoint can be set -
 * either at a breakpoint (e.g. function args), or
 * after a sequence of commands - e.g. lhs of :=, or a reference
 * (since we watch its target which is about to change), or runtime hit. */
func (tc *TaintCheck) propagateTaint(hit *Hit) *TaintedRegion {
	fset := token.NewFileSet()
	root, err := parser.ParseFile(fset, hit.hit_instr.Loc.File, nil, parser.SkipObjectResolution)
	if err != nil {
		log.Panicf("Failed to parse source file %v: %v\n", hit.hit_instr.Loc.File, err)
	}

	// Will be used if location must be determined dynamically
	// XXX any way to get rid of thread in Hit? Is confusing since shouldn't use it for location (bc of runtime hits). At least comment that somewhere...
	var ret *TaintedRegion
	defer func() {
		if ret != nil {
			fmt.Printf("propagateTaint return %+v\n", ret)
		} else {
			fmt.Printf("propagateTaint return nil\n")
		}
	}()

	// DFS of file's AST
	ast.Inspect(root, func(node ast.Node) bool {
		// PERF: How to properly only inspect one line?
		var start token.Position
		var end token.Position
		if node != nil {
			start = fset.Position(node.Pos())
			end = fset.Position(node.End())
		}
		if !(start.Line <= hit.hit_instr.Loc.Line && hit.hit_instr.Loc.Line <= end.Line) {
			return true
		}
		// hit line is part of node

		switch typed_node := node.(type) {
		case *ast.IfStmt:
			if start.Line == hit.hit_instr.Loc.Line && tc.config.Taint_flow != DataFlow {
				// Enter if[elseif/else] => set up state so we'll next through the branch body
				tainted_region := tc.isTainted(typed_node.Cond, hit, fset)
				if tainted_region == nil {
					// Can happen when watchpoint hits for a case we don't consider tainted - e.g. index into array
					tc.Logf(slog.LevelWarn, hit, "Hit wp for ifStmt %+v, but isTainted didn't find taint", exprToString(typed_node.Cond))
				} else {
					locs := []int{}
					tc.handleIfStmt(typed_node, fset, &locs, tainted_region, hit.scope.Frame)
					tainted_region.cmds = next_cmd_seq(hit)
					ret = tainted_region
				}
			}

		case *ast.CallExpr:
			call_expr := exprToString(typed_node.Fun)
			fmt.Printf("CallExpr %v\n", exprToString(typed_node))
			if call_expr == "copy" {
				tainted_region := tc.isTainted(typed_node.Args[1], hit, fset)
				if tainted_region != nil {
					// Copies min(len(new), len(old)). So if new is shorter, shorten overlap.
					xv, err := tc.client.EvalWatchexpr(hit.scope, exprToString(typed_node.Args[0]), true)
					if err != nil {
						// I think new should always be evaluatable?
						log.Panicf("eval %v for copy builtin: %v", exprToString(typed_node.Args[0]), err)
					}
					tainted_region.overlap_end = min(tainted_region.overlap_start+uint64(xv.Watchsz), tainted_region.overlap_end)

					// Expr will be allocated, but if on stack and runtime hit, need to set wp in correct scope, so stack OOS watchpoints
					// are set correctly (TODO add test for this)
					pending_loc := tc.lineWithStmt(start.Filename, start.Line+1, hit.scope.Frame)
					tainted_region.set_location = &pending_loc
					watchexpr := exprToString(typed_node.Args[0])
					tainted_region.overlap_expr = &watchexpr
					ret = tainted_region
				}
			} else if builtinFcts.Contains(call_expr) || tc.isCast(typed_node) || call_expr == "runtime.KeepAlive" {
				// builtins will be handled in assign/range
			} else {
				// If method: check receiver for taint if non-pointer, and
				// count it in args to match what we'll do when creating wp
				decl_loc := tc.fnDecl(call_expr, hit)
				file := decl_loc.File
				lineno := decl_loc.Line + 1
				pending_loc := tc.lineWithStmt(file, lineno, hit.scope.Frame)
				for i, arg := range tc.fullArgs(typed_node, hit) {
					tainted_region := tc.isTainted(arg, hit, fset)
					if tainted_region != nil { // caller arg tainted
						if runtimeOrInternal(file) {
							// Callee is in runtime/internal pkg => don't propagate to args
							// (may additionally want to unconditionally treat as if retval is tainted -
							// will need to handle fact that size of arg overlap != retval size)
							tc.Logf(slog.LevelWarn, hit, "Function with tainted args is in runtime/internal - will not propagate into it")
						} else {
							// Propagate to callee's arg
							// TODO handle passing param to func lit not assigned to variable (e.g. goroutine in funclit test)
							// First line of function body (params are "fake" at declaration line)
							tainted_region.overlap_arg = &i
							tainted_region.set_location = &pending_loc
							ret = tainted_region
						}
					}
				}
			}

		case *ast.ReturnStmt:
			fmt.Println("ReturnStmt")
			// Watched location is read in return value =>
			// taint corresponding assign lhs/range value in caller, if any
			for i, retval := range typed_node.Results {
				tainted_region := tc.isTainted(retval, hit, fset)
				if tainted_region != nil {
					if tc.propagateReturn(i, hit, tainted_region) {
						ret = tainted_region
					}
				}
			}

		case *ast.AssignStmt:
			fmt.Println("AssignStmt")
			for _, rhs := range typed_node.Rhs {
				// TODO properly handle multiple rhs (unsure of semantics) - will need to allow this fct to return multiple tainted regions
				tainted_region := tc.isTainted(rhs, hit, fset)
				if tainted_region != nil {
					// Watched location is read on the rhs => taint lhs
					for _, lhs := range typed_node.Lhs {
						watchexpr := exprToString(lhs) + *tainted_region.overlap_expr
						tainted_region.overlap_expr = &watchexpr
					}
					if !tainted_region.set_now {
						tainted_region.cmds = next_cmd_seq(hit)
					} else {
						tainted_region.cmds = runtime_stepout_cmd_seq(hit)
					}
					ret = tainted_region
				}
			}
		case *ast.RangeStmt:
			// TODO handle Range properly (once support tainted composite types in delve):
			// If only part of the rhs is tainted, value expr should only be tainted on corresp iters
			tainted_region := tc.isTainted(typed_node.X, hit, fset)
			if tainted_region != nil && typed_node.Value != nil {
				// Watched location is read on the rhs =>
				// taint value expr
				pending_loc := tc.lineWithStmt(start.Filename, start.Line+1, hit.scope.Frame)
				tainted_region.set_location = &pending_loc
				watchexpr := exprToString(typed_node.Value)
				tainted_region.overlap_expr = &watchexpr
				ret = tainted_region
			}
		} // end switch

		return true
	})

	return ret
}
