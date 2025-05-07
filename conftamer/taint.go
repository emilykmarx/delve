package conftamer

import (
	"go/ast"
	"go/parser"
	"go/token"
	"log"
	"log/slog"
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

// A tainted (perhaps partially) memory region to be watched
// Old region hits a watchpoint, meaning it may be tainted
// New region is copy of old, i.e. is same type (for data flow)
type TaintedRegion struct {
	// Old/new regions, as they appear on the line:
	// e.g. if only s.f is tainted but line is s2 = s, old/new are s/s2
	// We'll use m-c map to determine only s2.f is tainted
	// The new region should evaluate to the same type/sizes
	new_expr   *string         // newly tainted expression (empty if not recorded on watchpoint hit)
	new_argno  *int            // index of newly tainted arg
	old_region []*api.Variable // list of vars that old region evaluates to (order matters)
	// Whether to concatenate tainting vals across xvs
	concat_xvs bool

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
// TODO handle function composition (for builtins too - will need diff handling). Any others? e.g. x = f() + "str"
func (tc *TaintCheck) propagateReturn(lhs_i int, hit *Hit, tainted_region *TaintedRegion) bool {
	tainted_region.cmds = runtime_stepout_cmd_seq(hit)

	stack := tc.stacktrace()
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
			tc.Logf(slog.LevelWarn, hit, "Failed to find caller lhs; call file %v, call line %v (stacktrace above)", call_file, call_line)
			return false
		}
		stack_len := hit.stack_len - caller_frame

		if caller_lhs != nil {
			// Assignment
			watchexpr := exprToString(*caller_lhs)
			tainted_region.new_expr = &watchexpr
		} else if _, ok := (*caller_node).(*ast.ReturnStmt); ok {
			// Propagate to next frame
			// Nexting from return exits its stack frame => expect to be in caller frame
			stack_len -= 1
			found_ret = true
		} else if ifstmt, ok := (*caller_node).(*ast.IfStmt); ok {
			// If stmt => set up to next through it as if the condition hit a watchpoint
			if tc.config.Taint_flow != DataFlow {
				locs := []int{}
				fset := token.NewFileSet()
				parser.ParseFile(fset, call_file, nil, parser.SkipObjectResolution)
				tc.handleIfStmt(ifstmt, fset, &locs, tainted_region, caller_frame)
			} else {
				return false // ignoring control-flow taint => don't propagate
			}
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

	return true
}

// TODO (future) consider making tests more organized - e.g. split into "isTainted" and "propagateTaint",
// so don't need to e.g. write an assign and range test for every new construct
// (e.g. don't have a test for return callexpr/cast)

func (tc *TaintCheck) isTainted(expr ast.Expr, hit *Hit, fset *token.FileSet) (TaintedRegion, bool) {
	return tc.evalWatchexpr(expr, hit, fset, true)
}

/* Eval expr and record its xv(s), ignoring function calls (except casts and append)
 * and any children of evaluatable expressions.
 * If tainted_only, stop when find an expr that overlaps the watchpoint, e.g.:
 * 	- If expr is struct => record struct, even if only one field overlaps.
 * 	- If expr is struct.field => record struct.field.
 * Panic if would record multiple exprs.
 * Return true if expr overlaps the watchpoint.
 * If in branch body, always overlap.
 * Also populate set_now. */
func (tc *TaintCheck) evalWatchexpr(expr ast.Expr, hit *Hit, fset *token.FileSet, tainted_only bool) (TaintedRegion, bool) {
	tainted_region := TaintedRegion{} // to be populated
	is_tainted := false

	if hit.hit_bp == nil {
		// Finished next in branch body
		return tainted_region, true
	}

	ast.Inspect(expr, func(node ast.Node) bool {
		if node == nil {
			return true
		}
		switch typed_node := node.(type) {
		case *ast.CallExpr:
			if exprToString(typed_node.Fun) == "append" {
				// append => return args appended together
				tainted_region.old_region, is_tainted, tainted_region.concat_xvs = tc.handleAppend(typed_node, hit, fset)
				return false
			} else if !tc.isCast(typed_node.Fun) {
				// regular function call => ignore (another call to isTainted checks its args)
				return false
			} else {
				// cast => continue to inspect its arg
			}
		case *ast.CompositeLit:
			rbrace := fset.Position(typed_node.Rbrace).Line
			lbrace := fset.Position(typed_node.Lbrace).Line
			// Multiline composite lit => next can take us back to assign line, but setting immediately seems to work (only if multiline)
			tainted_region.set_now = rbrace > lbrace
		case ast.Expr:
			// If type not supported, still check overlap
			// Use EvalWatchexpr rather than EvalVariable so watch-related fields (e.g. Watchsz and Addr) are set correctly
			tc.Logf(slog.LevelDebug, hit, "isTainted eval %v", exprToString(typed_node))
			xvs, err := tc.client.EvalWatchexpr(hit.scope, exprToString(typed_node), true)
			if err != nil {
				if strings.Contains(err.Error(), "can not convert") {
					// May want to add support for some of these in delve
					tc.Logf(slog.LevelWarn, hit, "Eval %v: %v", exprToString(typed_node), err)
					// Don't eval children
					return false
				} else {
					// Try evaluating any AST children (for e.g. binary ops)
				}
			} else {
				// 1. Filter out region that doesn't overlap watchpoint at all
				// (may overlap but not be tainted - will check m-c map when record pending watchpoint)
				for _, xv := range xvs {
					watch_addr := hit.hit_bp.Addr
					watch_size := watchSize(hit.hit_bp)
					xv_size := uint64(xv.Watchsz)
					tc.Logf(slog.LevelDebug, hit, "isTainted check overlap - watch region %#x:%v, xv %#x:%v", watch_addr, watch_size, xv.Addr, xv_size)

					_, _, is_tainted = memOverlap(xv.Addr, xv_size, watch_addr, watch_size)
					if is_tainted {
						break
					}
				}

				// 2. Record region
				if !tainted_only || is_tainted {
					if len(tainted_region.old_region) > 0 {
						// Need to think through how to handle this
						log.Panicf("Multiple tainted regions in %v", exprToString(expr))
					}
					tainted_region.old_region = xvs
				}

				// Don't evaluate children
				// (at least for Index and Selector - haven't thought through others),
				// but still consider other exprs in tree
				return false
			}
		}
		return true
	})

	tc.Logf(slog.LevelDebug, hit, "isTainted return %v: %+v", is_tainted, tainted_region)
	return tainted_region, is_tainted
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

// Append xvs for each arg to get new slice's []xv
// Return true if any arg tainted
// TODO handle strcat similarly
func (tc *TaintCheck) handleAppend(call_node *ast.CallExpr, hit *Hit, fset *token.FileSet) ([]*api.Variable, bool, bool) {
	slice_tainted := false
	slice_xvs := []*api.Variable{}
	for _, arg := range call_node.Args {
		tainted_region, is_tainted := tc.evalWatchexpr(arg, hit, fset, false)
		if is_tainted {
			slice_tainted = true
		}
		slice_xvs = append(slice_xvs, tainted_region.old_region...)
	}

	// slice of non-reference elems => flatten xvs' tainting vals into a single array (to match returned slice)
	concat_xvs := !slice_xvs[0].ReferenceElem
	return slice_xvs, slice_tainted, concat_xvs
}

// Update start and end of branch body in tainted_region and in tc
func (tc *TaintCheck) handleIfStmt(branch ast.Node, fset *token.FileSet, body_starts *[]int, tainted_region *TaintedRegion, frame int) {
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
 * return the region(s) on the line that is newly tainted as a result.
 * Also populate ret with info on when new watchpoint can be set -
 * either at a breakpoint (e.g. function args), or
 * after a sequence of commands - e.g. lhs of :=, or a reference
 * (since we watch its target which is about to change), or runtime hit. */
func (tc *TaintCheck) propagateTaint(hit *Hit) []TaintedRegion {
	fset := token.NewFileSet()
	root, err := parser.ParseFile(fset, hit.hit_instr.Loc.File, nil, parser.SkipObjectResolution)
	if err != nil {
		log.Panicf("Failed to parse source file %v: %v\n", hit.hit_instr.Loc.File, err)
	}

	// Will be used if location must be determined dynamically
	// XXX any way to get rid of thread in Hit? Is confusing since shouldn't use it for location (bc of runtime hits). At least comment that somewhere...
	ret := []TaintedRegion{}
	defer func() {
		tc.Logf(slog.LevelDebug, hit, "propagateTaint return %+v", ret)
	}()

	// DFS of file's AST
	ast.Inspect(root, func(node ast.Node) bool {
		var start token.Position
		var end token.Position
		if node != nil {
			start = fset.Position(node.Pos())
			end = fset.Position(node.End())
		}
		if !(start.Line <= hit.hit_instr.Loc.Line && hit.hit_instr.Loc.Line <= end.Line) {
			// PERF: How to properly only inspect these lines?
			return true
		}
		// hit line is part of node

		switch typed_node := node.(type) {
		case *ast.IfStmt:
			tc.Logf(slog.LevelDebug, hit, "Start propagateTaint - IfStmt cond %v", exprToString(typed_node.Cond))
			if start.Line == hit.hit_instr.Loc.Line && tc.config.Taint_flow != DataFlow {
				// Enter if[elseif/else] => set up state so we'll next through the branch body
				tainted_region, is_tainted := tc.isTainted(typed_node.Cond, hit, fset)
				if !is_tainted {
					// Can happen when watchpoint hits for a case we don't consider tainted - e.g. index into array
					tc.Logf(slog.LevelWarn, hit, "Hit wp for ifStmt %+v, but isTainted didn't find taint", exprToString(typed_node.Cond))
				} else {
					locs := []int{}
					tc.handleIfStmt(typed_node, fset, &locs, &tainted_region, hit.scope.Frame)
					tainted_region.cmds = next_cmd_seq(hit)
					ret = append(ret, tainted_region)
				}
			}
			tc.Logf(slog.LevelDebug, hit, "Finish propagateTaint - IfStmt cond %v", exprToString(typed_node.Cond))

		case *ast.CallExpr:
			call_expr := exprToString(typed_node.Fun)
			tc.Logf(slog.LevelDebug, hit, "Start propagateTaint - CallExpr %v", exprToString(typed_node))
			if call_expr == "copy" {
				// If src is tainted, taint dst
				tainted_region, is_tainted := tc.isTainted(typed_node.Args[1], hit, fset)
				if is_tainted {
					// Copies min(len(new), len(old)) - SetWatchpoint() will handle
					// TODO switch to set_now instead of assuming linear
					pending_loc := tc.lineWithStmt(start.Filename, start.Line+1, hit.scope.Frame)
					tainted_region.set_location = &pending_loc
					watchexpr := exprToString(typed_node.Args[0])
					tainted_region.new_expr = &watchexpr
					ret = append(ret, tainted_region)
				}
			} else if builtinFcts.Contains(call_expr) || tc.isCast(typed_node.Fun) || call_expr == "runtime.KeepAlive" {
				// builtins and casts will be handled in assign/range
			} else {
				// If method: check receiver for taint if non-pointer, and
				// count it in args to match what we'll do when creating wp
				decl_loc := tc.fnDecl(call_expr, hit)
				file := decl_loc.File
				lineno := decl_loc.Line + 1
				pending_loc := tc.lineWithStmt(file, lineno, hit.scope.Frame)
				for i, arg := range tc.fullArgs(typed_node, hit) {
					tainted_region, is_tainted := tc.isTainted(arg, hit, fset)
					if is_tainted { // caller arg tainted
						if runtimeOrInternal(file) {
							// Callee is in runtime/internal pkg => don't propagate to args
							// (may additionally want to unconditionally treat as if retval is tainted -
							// will need to handle fact that size of arg overlap != retval size)
							tc.Logf(slog.LevelWarn, hit, "Function with tainted args is in runtime/internal - will not propagate into it")
						} else {
							// Propagate to callee's arg
							// TODO handle passing param to func lit not assigned to variable (e.g. goroutine in funclit test)
							// First line of function body (params are "fake" at declaration line)
							tainted_region.new_argno = &i
							tainted_region.set_location = &pending_loc
							ret = append(ret, tainted_region)
						}
					}
				}
			}
			tc.Logf(slog.LevelDebug, hit, "Finish propagateTaint - CallExpr %v", exprToString(typed_node))

		case *ast.ReturnStmt:
			tc.Logf(slog.LevelDebug, hit, "Start propagateTaint - ReturnStmt lhs ret %v", exprToString(typed_node.Results[0]))
			// Watched location is read in return value =>
			// taint corresponding assign lhs/range value in caller, if any
			for i, retval := range typed_node.Results {
				tainted_region, is_tainted := tc.isTainted(retval, hit, fset)
				if is_tainted {
					if tc.propagateReturn(i, hit, &tainted_region) {
						ret = append(ret, tainted_region)
					}
				}
			}
			tc.Logf(slog.LevelDebug, hit, "Finish propagateTaint - ReturnStmt lhs ret %v", exprToString(typed_node.Results[0]))

		case *ast.AssignStmt:
			tc.Logf(slog.LevelDebug, hit, "Start propagateTaint - AssignStmt lhs %v", exprToString(typed_node.Lhs[0]))
			for _, rhs := range typed_node.Rhs {
				// For now, taint each lhs (TODO which should be tainted - could do heuristic e.g. same type as rhs)
				rhs_tainted_region, is_tainted := tc.isTainted(rhs, hit, fset)
				if is_tainted {
					// Watched location is read on the rhs => taint lhs
					for _, lhs := range typed_node.Lhs {
						watchexpr := exprToString(lhs)
						rhs_tainted_region.new_expr = &watchexpr
						if !rhs_tainted_region.set_now {
							rhs_tainted_region.cmds = next_cmd_seq(hit)
						} else {
							rhs_tainted_region.cmds = runtime_stepout_cmd_seq(hit)
						}
						ret = append(ret, rhs_tainted_region)
					}
				}
			}
			tc.Logf(slog.LevelDebug, hit, "Finish propagateTaint - AssignStmt lhs %v", exprToString(typed_node.Lhs[0]))

		case *ast.RangeStmt:
			tc.Logf(slog.LevelDebug, hit, "Start propagateTaint - RangeStmt lhs %v", exprToString(typed_node.Value))
			// TODO need new test for this since watching underlying data (cur one doesn't hit in range)
			if start.Line == hit.hit_instr.Loc.Line {
				// TODO handle Range properly (once support tainted composite types in delve):
				// If only part of the rhs is tainted, value expr should only be tainted on corresp iters
				tainted_region, is_tainted := tc.isTainted(typed_node.X, hit, fset)
				if is_tainted && typed_node.Value != nil {
					// Watched location is read on the rhs =>
					// taint value expr
					pending_loc := tc.lineWithStmt(start.Filename, start.Line+1, hit.scope.Frame)
					tainted_region.set_location = &pending_loc
					watchexpr := exprToString(typed_node.Value)
					tainted_region.new_expr = &watchexpr
					ret = append(ret, tainted_region)
				}
			}
			tc.Logf(slog.LevelDebug, hit, "Finish propagateTaint - RangeStmt lhs %v", exprToString(typed_node.Value))
		} // end switch

		return true
	})

	return ret
}
