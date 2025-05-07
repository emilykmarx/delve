package conftamer

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/printer"
	"go/token"
	"log"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/go-delve/delve/pkg/proc"
	"github.com/go-delve/delve/pkg/terminal"
	"github.com/go-delve/delve/service/api"
	"github.com/go-delve/delve/service/rpc2"
	"github.com/google/go-cmp/cmp"
	set "github.com/hashicorp/go-set"
)

// Call `f` for each addr in watchpoint's region.
// Return true if f returned true for any addr.
func forEachWatchaddr(watchpoint *api.Breakpoint, f func(watchaddr uint64) bool) bool {
	ret := false
	watch_end := watchpoint.Addrs[0] + watchSize(watchpoint)
	for watchaddr := watchpoint.Addrs[0]; watchaddr < watch_end; watchaddr++ {
		if f(watchaddr) {
			ret = true
		}
	}
	return ret
}

func newTaintingVals() TaintingVals {
	return TaintingVals{
		Params:    *set.New[TaintingParam](0),
		Behaviors: *set.New[TaintingBehavior](0),
	}
}

func MakeTaintingVals(tp *TaintingParam, tb *TaintingBehavior) TaintingVals {
	v := newTaintingVals()
	if tp != nil {
		v.Params.Insert(*tp)
	}
	if tb != nil {
		v.Behaviors.Insert(*tb)
	}
	return v
}

func union(tv1 TaintingVals, tv2 TaintingVals) TaintingVals {
	return TaintingVals{
		Params:    *tv1.Params.Union(&tv2.Params),
		Behaviors: *tv1.Behaviors.Union(&tv2.Behaviors),
	}
}

// Add tainting_vals to any existing entry in m-p[watchaddr]
// If new entry, insert it
// No-op if tainting_vals is empty
func (tc *TaintCheck) updateTaintingVals(watchaddr uint64, tainting_vals TaintingVals, thread *api.Thread) {
	if cmp.Equal(tainting_vals, newTaintingVals()) {
		return
	}
	existing_taint := tc.mem_param_map[watchaddr]
	new_taint := union(tainting_vals, existing_taint)
	tc.mem_param_map[watchaddr] = new_taint

	event := Event{EventType: MemParamMapUpdate, Address: watchaddr, Size: 1, TaintingVals: &new_taint}
	WriteEvent(thread, tc.event_log, event)
}

// Fill in any empty params at m-p[watchaddr]
func (tc *TaintCheck) populateParam(watchaddr uint64, param string) {
	existing_taint := tc.mem_param_map[watchaddr]
	new_params := existing_taint.Params
	existing_taint.Params.ForEach(func(tp TaintingParam) bool {
		if tp.Param.Param == "" {
			new_params.Remove(tp)
			tp.Param.Param = param
			new_params.Insert(tp)
		}
		return true
	})
	new_taint := union(TaintingVals{Params: new_params}, TaintingVals{Behaviors: existing_taint.Behaviors})
	tc.mem_param_map[watchaddr] = new_taint
}

// Update tainting vals for ith variable, at given offset (expect i and offset are in bounds).
func (pending_wp *PendingWp) updateTaintingVals(tainting_vals TaintingVals, i int, offset uint64) {
	existing_taint := pending_wp.tainting_vals[i][offset]
	new_taint := union(tainting_vals, existing_taint)
	pending_wp.tainting_vals[i][offset] = new_taint
}

func insert[T comparable](s *set.Set[T], val T) {
	if s.Empty() {
		*s = *set.New[T](1)
	}
	s.Insert(val)
}

// Parse params assuming \n-separated. Return offset => param
func (tc *TaintCheck) readParams(overlap_start uint64, overlap_end uint64, frame int) map[uint64]string {
	param_taint := map[uint64]string{}
	// 1. Parse all params
	buf_contents := ""
	for watchaddr := overlap_start; watchaddr < overlap_end; watchaddr++ {
		eval_expr := fmt.Sprintf("*(*uint8)(%#x)", watchaddr)
		s := api.EvalScope{GoroutineID: -1, Frame: frame}
		xv, err := tc.client.EvalVariable(s, eval_expr, api.LoadConfig{})
		if err != nil {
			log.Panicf("read param char at %#x: %v\n", watchaddr, err)
		}
		var char uint8
		if _, err := fmt.Sscanf(xv.Value, "%d", &char); err != nil {
			log.Panicf("parse param char at %#x: %v\n", watchaddr, err)
		}
		buf_contents += string(char)
	}
	params := strings.Split(buf_contents, "\n")
	// 2. Map offsets to params
	param_idx := 0
	len_consumed := len(params[param_idx])
	for offset := 0; offset < len(buf_contents); offset++ {
		if buf_contents[offset] == '\n' && param_idx < len(params)-1 {
			// \n (not the last one)
			param_idx++
			len_consumed += len(params[param_idx])
		} else {
			param_taint[uint64(offset)] = params[param_idx]
		}
	}

	return param_taint
}

func hasEmptyParam(tainting_vals TaintingVals) bool {
	empty := false
	tainting_vals.Params.ForEach(func(tp TaintingParam) bool {
		if tp.Param.Param == "" {
			if !empty {
				empty = true
			} else {
				// multiple empty params at an address - unsure if possible or what to do
				log.Panicf("mem-param map has multiple empty params: %+v\n", tainting_vals)
			}
		}
		return true
	})
	return empty
}

// pretty-print
func (pendingwp PendingWp) String() string {
	return fmt.Sprintf("{watchexprs %v watchargs %v tainting_vals %+v commands %+v}",
		pendingwp.watchexprs, pendingwp.watchargs, pendingwp.tainting_vals, pendingwp.cmds)
}
func printJSON(i ...interface{}) string {
	if b, err := json.Marshal(i); err == nil {
		return string(b)
	}
	return "cannot marshal for logging"
}
func (t TaintedRegion) String() string {
	old_region := ""
	for i, xv := range t.old_region {
		s := fmt.Sprintf("%#x (sz %#x)", xv.Addr, xv.Watchsz)
		if i > 0 {
			old_region += ", "
		}
		old_region += s
	}
	// handle nils
	return fmt.Sprintf("{new_expr %v new_argno %v old_region %s}", printJSON(t.new_expr), printJSON(t.new_argno), old_region)
}

// Get line of source (as string)
func sourceLine(client *rpc2.RPCClient, file string, lineno int) string {
	if os.Setenv("TERM", "dumb") != nil {
		log.Panicf("Error setting TERM=dumb")
	}

	t := terminal.New(client, nil)
	// PERF faster way to do this?
	lines, err := t.GetOutput(fmt.Sprintf("list %v:%v", file, lineno))
	if err != nil {
		log.Panicf("Error getting source code for %v:%v: %v\n", file, lineno, err)
	}

	var src_line string
	for _, line := range strings.Split(lines, "\n") {
		var curline int
		if strings.HasPrefix(line, "Showing") || line == "" {
			continue
		}
		if _, err := fmt.Sscanf(line, " %d:", &curline); err != nil {
			log.Panicf("Failed to parse line number from %v:%v: %v\n", file, line, err)
		}
		if curline != lineno {
			continue
		}
		re := regexp.MustCompile(`\s+(\d+):\s+`)
		src_start := re.FindStringIndex(line)[1]
		if src_start <= len(line)-1 {
			src_line = line[src_start:]
		} else {
			return ""
		}
	}

	return src_line
}

func exprToString(t ast.Expr) string {
	var buf bytes.Buffer
	printer.Fprint(&buf, token.NewFileSet(), t)
	return buf.String()
}

// Return overlapping region: start, exclusive end, ok
func memOverlap(start1 uint64, sz1 uint64, start2 uint64, sz2 uint64) (uint64, uint64, bool) {
	end1 := start1 + sz1 // exclusive
	end2 := start2 + sz2
	overlap_start := max(start1, start2)
	overlap_end := min(end1, end2)
	if overlap_start < overlap_end {
		return overlap_start, overlap_end, true
	}
	return 0, 0, false
}

func getThread(ID int, state *api.DebuggerState) *api.Thread {
	for _, thread := range state.Threads {
		if ID == thread.ID {
			return thread
		}
	}
	log.Panicf("thread %v not found", ID)
	return nil
}

func (tc *TaintCheck) stacktrace() []api.Stackframe {
	// TODO check for partially loaded (in any calls with LoadConfig- see client API doc), and hitting max depth
	stack, err := tc.client.Stacktrace(-1, 100, api.StacktraceSimple, &api.LoadConfig{})
	if err != nil {
		log.Panicf("Error getting stacktrace: %v\n", err)
	}
	return stack
}

func (tc *TaintCheck) printStacktrace() {
	stack := tc.stacktrace()
	for _, frame := range stack {
		loc := fmt.Sprintf("%v \nLine %v:%v:0x%x",
			frame.File, frame.Line, frame.Function.Name(),
			frame.PC)
		tc.Logf(slog.LevelDebug, nil, loc)
	}
}

// Whether the stack contains a print-/log-flavored function
func (tc *TaintCheck) hitInPrint() bool {
	stack := tc.stacktrace()

	for _, frame := range stack {
		fn := frame.Function.Name()
		if ignoreSourceLine(fn) {
			return true
		}
	}
	return false
}

// Whether to ignore this hit based on the source line
func ignoreSourceLine(src_line string) bool {
	line := strings.ToLower(src_line)
	return strings.Contains(line, "print") ||
		strings.Contains(line, "debugf") ||
		strings.Contains(line, "infof") ||
		strings.Contains(line, "warnf") ||
		strings.Contains(line, "errorf") ||
		strings.Contains(line, "fatalf")
}

// Whether file is in go's runtime or internal packages, based on filename.
// (Don't use parseFn, since some runtime functions get reflect.X linkname.)
// TODO (minor) take path to go src as config item (for now assume any path containing /src/internal or /src/runtime is in go src)
func runtimeOrInternal(file string) bool {
	return strings.Contains(file, "/src/internal") || strings.Contains(file, "/src/runtime")
}

// Given a callexpr node, return full args including non-pointer receiver name (or "" if pointer receiver)
func (tc *TaintCheck) fullArgs(node *ast.CallExpr, hit *Hit) []ast.Expr {
	full_args := node.Args
	call_expr := exprToString(node.Fun)
	decl_loc := tc.fnDecl(call_expr, hit)
	decl_tokens := strings.Split(sourceLine(tc.client, decl_loc.File, decl_loc.Line), " ")

	if decl_tokens[1][0] == '(' {
		// method
		recvr := ""
		if !strings.Contains(decl_tokens[2], "*") {
			// non-pointer receiver => get its name from the callexpr
			// remove fn name
			call_tokens := strings.Split(exprToString(node.Fun), ".")
			recvr = strings.Join(call_tokens[:len(call_tokens)-1], ".")
		}

		recvr_node := ast.Ident{NamePos: node.Pos(), Name: recvr}
		full_args = append([]ast.Expr{&recvr_node}, full_args...)
	}
	return full_args
}

// Find the function declaration location,
// given the call expr - e.g. recvr.f() or pkg.f()
func (tc *TaintCheck) fnDecl(call_expr string, hit *Hit) api.Location {
	locs, _, err := tc.client.FindLocation(hit.scope, call_expr, true, nil)
	if err != nil {
		if strings.Contains(err.Error(), "ambiguous") {
			// TODO (minor) - ast has package name in File - fixes this case, maybe the below too?
			// Ambiguous name => qualify with package name
			// Can't use lineWithStmt - !hasInstr counts comment, hasInstr skips package line
			pkg := ""
			found := false
			for i := 0; i < 100; i++ { // Likely won't need to skip more than a few lines?
				src_line := sourceLine(tc.client, hit.hit_instr.Loc.File, i)
				pkg, found = strings.CutPrefix(src_line, "package ")
				if found {
					break
				}
			}
			qualified_fn := pkg + "." + call_expr
			locs, _, err = tc.client.FindLocation(hit.scope, qualified_fn, true, nil)
			if err != nil {
				if strings.Contains(err.Error(), "ambiguous") {
					// Package name is ambiguous => qualify with directory
					tokens := strings.Split(hit.hit_instr.Loc.File, "/")
					dir := tokens[len(tokens)-3]
					qualified_fn = filepath.Join(dir, qualified_fn)
					locs, _, err = tc.client.FindLocation(hit.scope, qualified_fn, true, nil)
					if err != nil {
						log.Panicf("Error finding function %v in frame %v: %v\n", qualified_fn, hit.scope.Frame, err)
					}
				}
			}
		} else {
			log.Panicf("Error finding function %v in frame %v: %v\n", call_expr, hit.scope.Frame, err)
		}
	}
	// Don't check loc's PCs here - won't use them, and
	// fn decl loc has "PC" but empty "PCs" , whereas first line loc has "PC" and "PCs" (with PCs matching PC)
	// (at least for call_assign_1.go)
	if len(locs) > 1 {
		// Unsure when this would happen - don't support for now
		log.Panicf("Too many locations: %v\n", locs)
	}
	return locs[0]
}

func watchSize(wp *api.Breakpoint) uint64 {
	return uint64((proc.WatchType)(wp.WatchType).Size())
}

// Find the next line on or after this one with a statement, so we can set a bp.
func (tc *TaintCheck) lineWithStmt(file string, lineno int, frame int) api.Location {
	var loc string

	for i := 0; i < 100; i++ { // Likely won't need to skip more than a few lines?
		loc = fmt.Sprintf("%v:%v", file, lineno)
		// TODO(minor): how to pass in substitutePath rules? (2nd ret is related)
		// Lines with instr only
		locs, _, err := tc.client.FindLocation(api.EvalScope{GoroutineID: -1, Frame: frame}, loc, true, nil)
		if len(locs) == 1 {
			return locs[0]
		}
		if err != nil && !strings.HasPrefix(err.Error(), "could not find statement") {
			log.Panicf("Error finding location: %v\n", err)
		}
		if len(locs) > 1 || (len(locs) > 0 && len(locs[0].PCs) != 1) {
			// Unsure when this would happen - don't support for now
			log.Panicf("Too many locations: %v\n", locs)
		}
		lineno += 1
	}

	log.Panicf("Failed to find location %v in frame %v\n", loc, frame)
	return api.Location{}
}

func (tc *TaintCheck) setBp(addr uint64) {
	bp := api.Breakpoint{Addrs: []uint64{addr}}
	if _, err := tc.client.CreateBreakpoint(&bp); err != nil {
		if !strings.HasPrefix(err.Error(), "Breakpoint exists at") {
			log.Panicf("Failed to create breakpoint at %v: %v\n", addr, err)
		}
	}
}

func (tc *TaintCheck) startTarget(cmd string, state *api.DebuggerState) {
	var new_state *api.DebuggerState
	var err error
	if cmd == api.Next {
		tc.Logf(slog.LevelDebug, nil, "Next")
		new_state, err = tc.client.Next()
		if err != nil {
			log.Panicf("Next: %v\n", err)
		}
	} else if cmd == api.StepOut {
		tc.Logf(slog.LevelDebug, nil, "StepOut")
		new_state, err = tc.client.StepOut()
		if err != nil {
			log.Panicf("Stepout: %v\n", err)
		}
	} else if cmd != api.Continue {
		log.Panicf("unsupported cmd in sequence: %v\n", cmd)
	} else {
		tc.Logf(slog.LevelDebug, nil, "Continue")
		new_state = <-tc.client.Continue()
	}
	*state = *new_state
}

// Get client and target source line (based on hit_instr)
func (tc *TaintCheck) Logf(lvl slog.Level, hit *Hit, format string, args ...any) {
	if !tc.logger.Enabled(context.Background(), lvl) {
		return
	}
	var pcs [1]uintptr
	runtime.Callers(2, pcs[:])
	r := slog.NewRecord(time.Now(), lvl, fmt.Sprintf(format, args...), pcs[0])
	if hit != nil {
		// May be called from bp hit or wp hit (where wp hit may not have hit_bp, if called from Run())
		if hit.hit_instr != nil {
			r.Add("target_file", hit.hit_instr.Loc.File, "target_line", hit.hit_instr.Loc.Line)
		} else {
			r.Add("target_file", hit.hit_bp.File, "target_line", hit.hit_bp.Line)
		}
	}
	_ = tc.logger.Handler().Handle(context.Background(), r)
}

func (tc *TaintCheck) isCast(call_expr_node ast.Expr) bool {
	call_expr := exprToString(call_expr_node)
	_, err := tc.client.EvalWatchexpr(api.EvalScope{GoroutineID: -1}, call_expr, true)
	if err != nil {
		if fn, ok := strings.CutPrefix(err.Error(), "function calls not allowed without using 'call': "); ok {
			// Found regular function call
			if fn != exprToString(call_expr_node.(*ast.CallExpr).Fun) {
				// Node of form `cast(regular call())`` => treat as cast (will get to the regular call later in Inspect)
				return true
			} else {
				// Node of form `regular call()`
				return false
			}
		} else {
			// Cast that dlv doesn't support evaluating (gives "symbol not found")
			return true
		}
	} else {
		// Cast that dlv supports evaluating
		return true
	}
}
