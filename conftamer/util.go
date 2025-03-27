package conftamer

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/printer"
	"go/token"
	"log"
	"os"
	"regexp"
	"strings"

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
func (tc *TaintCheck) updateTaintingVals(watchaddr uint64, tainting_vals TaintingVals, thread *api.Thread) {
	if cmp.Equal(tainting_vals, newTaintingVals()) {
		// Ignore if empty
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

// If offset is beyond pending_wp's len, append - else union with any existing at offset
func (pending_wp *PendingWp) updateTaintingVals(tainting_vals TaintingVals, offset uint64) {
	existing_taint := newTaintingVals()
	if uint64(len(pending_wp.tainting_vals)) > offset {
		existing_taint = pending_wp.tainting_vals[offset]
	}
	new_taint := union(tainting_vals, existing_taint)
	if uint64(len(pending_wp.tainting_vals)) > offset {
		pending_wp.tainting_vals[offset] = new_taint
	} else {
		pending_wp.tainting_vals = append(pending_wp.tainting_vals, new_taint)
	}
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
	for offset := uint64(0); offset <= overlap_end-overlap_start; offset++ {
		if offset == uint64(len_consumed) && param_idx < len(params)-1 {
			// \n (not the last one)
			param_idx++
			len_consumed += len(params[param_idx])
		} else {
			param_taint[offset] = params[param_idx]
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
	return fmt.Sprintf("{watchexprs %v watchargs %v tainting_vals %+v branch body %v:%v commands %+v}",
		pendingwp.watchexprs, pendingwp.watchargs, pendingwp.tainting_vals, pendingwp.body_start, pendingwp.body_end, pendingwp.cmds)
}

// Get line of source (as string)
func sourceLine(client *rpc2.RPCClient, file string, lineno int) string {
	if os.Setenv("TERM", "dumb") != nil {
		log.Fatalf("Error setting TERM=dumb")
	}

	t := terminal.New(client, nil)
	// PERF faster way to do this?
	lines, err := t.GetOutput(fmt.Sprintf("list %v:%v", file, lineno))
	if err != nil {
		log.Fatalf("Error getting source code for %v:%v: %v\n", file, lineno, err)
	}

	var src_line string
	for _, line := range strings.Split(lines, "\n") {
		var curline int
		if strings.HasPrefix(line, "Showing") || line == "" {
			continue
		}
		if _, err := fmt.Sscanf(line, " %d:", &curline); err != nil {
			log.Fatalf("Failed to parse line number from %v:%v: %v\n", file, line, err)
		}
		if curline != lineno {
			continue
		}
		re := regexp.MustCompile(`\s+(\d+):\s+`)
		src_start := re.FindStringIndex(line)[1]
		if src_start <= len(line)-1 {
			src_line = line[src_start:]
		} else {
			log.Fatalf("Empty line at %v:%v\n", file, line)
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

func (tc *TaintCheck) printBps() {
	bps, list_err := tc.client.ListBreakpoints(true)
	if list_err != nil {
		log.Fatalf("Error listing breakpoints: %v\n", list_err)
	}
	for _, bp := range bps {
		if bp.WatchExpr != "" {
			log.Printf("Watchpoint at %x\n", bp.Addr)
		} else {
			log.Printf("Breakpoint at %x\n", bp.Addr)
		}
	}

}

func printThreads(state *api.DebuggerState) {
	log.Println("Threads:")
	for _, th := range state.Threads {
		log.Printf("%v at %v\n", th.ID, th.Function.Name_)
	}
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

func (tc *TaintCheck) printStacktrace() {
	stack, err := tc.client.Stacktrace(-1, 100, api.StacktraceSimple, &api.LoadConfig{})
	if err != nil {
		log.Fatalf("Error getting stacktrace: %v\n", err)
	}
	for _, frame := range stack {
		loc := fmt.Sprintf("%v \nLine %v:%v:0x%x",
			frame.File, frame.Line, frame.Function.Name(),
			frame.PC)
		log.Println(loc)
	}
}

// Whether the stack contains a print-flavored function
func (tc *TaintCheck) hitInPrint() bool {
	stack, err := tc.client.Stacktrace(-1, 100, api.StacktraceSimple, &api.LoadConfig{})
	if err != nil {
		log.Fatalf("Error getting stacktrace: %v\n", err)
	}

	for _, frame := range stack {
		fn := frame.Function.Name()
		if strings.Contains(strings.ToLower(fn), ("print")) {
			return true
		}
	}
	return false
}

// Given a callexpr node, return full args including non-pointer receiver name (or "" if pointer receiver)
func (tc *TaintCheck) fullArgs(node *ast.CallExpr, file string, frame int) []ast.Expr {
	full_args := node.Args
	call_expr := exprToString(node.Fun)
	decl_loc := tc.fnDecl(call_expr, file, frame)
	// Decl:			pkg.<optional recvr type, perhaps ptr>.<fn name>
	// CallExpr:	<optional pkg>.<optional recvr expr, perhaps with selector(s)>.<fn name>

	decl_tokens := strings.Split(decl_loc.Function.Name(), ".")
	if len(decl_tokens) > 2 {
		// method
		recvr := ""
		if !strings.Contains(decl_loc.Function.Name(), "*") {
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

// Find the function declaration location - e.g. pkg.(*Recvr).f(),
// given the call expr - e.g. recvr.f() or pkg.f()
func (tc *TaintCheck) fnDecl(call_expr string, file string, frame int) api.Location {
	locs, _, err := tc.client.FindLocation(api.EvalScope{GoroutineID: -1, Frame: frame}, call_expr, true, nil)
	if err != nil {
		if strings.Contains(err.Error(), "ambiguous") {
			// Ambiguous name => qualify with package name
			tokens := strings.Split(file, "/")
			pkg := tokens[len(tokens)-2]
			if pkg == "dlv_config_client" { // running in test
				pkg = "main"
			}
			qualified_fn := pkg + "." + call_expr
			locs, _, err = tc.client.FindLocation(api.EvalScope{GoroutineID: -1, Frame: frame}, qualified_fn, true, nil)
			if err != nil {
				log.Fatalf("Error finding function %v in frame %v: %v\n", qualified_fn, frame, err)
			}
		} else {
			log.Fatalf("Error finding function %v in frame %v: %v\n", call_expr, frame, err)
		}
	}
	// Don't check loc's PCs here - won't use them, and
	// fn decl loc has "PC" but empty "PCs" , whereas first line loc has "PC" and "PCs" (with PCs matching PC)
	// (at least for call_assign_1.go)
	if len(locs) > 1 {
		// Unsure when this would happen - don't support for now
		log.Fatalf("Too many locations: %v\n", locs)
	}
	return locs[0]
}

func watchSize(wp *api.Breakpoint) uint64 {
	return uint64((proc.WatchType)(wp.WatchType).Size())
}

// Find the next line on or after this one with a statement, so we can set a bp.
func (tc *TaintCheck) lineWithStmt(call_expr *string, file string, lineno int, frame int) api.Location {
	var loc string
	if call_expr != nil {
		decl_loc := tc.fnDecl(*call_expr, file, frame)
		file = decl_loc.File
		lineno = decl_loc.Line + 1
	}

	for i := 0; i < 100; i++ { // Likely won't need to skip more than a few lines?
		loc = fmt.Sprintf("%v:%v", file, lineno)
		// TODO(minor): how to pass in substitutePath rules? (2nd ret is related)
		// Lines with instr only
		locs, _, err := tc.client.FindLocation(api.EvalScope{GoroutineID: -1, Frame: frame}, loc, true, nil)
		if len(locs) == 1 {
			return locs[0]
		}
		if err != nil && !strings.HasPrefix(err.Error(), "could not find statement") {
			log.Fatalf("Error finding location: %v\n", err)
		}
		if len(locs) > 1 || (len(locs) > 0 && len(locs[0].PCs) != 1) {
			// Unsure when this would happen - don't support for now
			log.Fatalf("Too many locations: %v\n", locs)
		}
		lineno += 1
	}

	log.Fatalf("Failed to find location %v in frame %v\n", loc, frame)
	return api.Location{}
}

func (tc *TaintCheck) setBp(addr uint64) {
	bp := api.Breakpoint{Addrs: []uint64{addr}}
	if _, err := tc.client.CreateBreakpoint(&bp); err != nil {
		if !strings.HasPrefix(err.Error(), "Breakpoint exists at") {
			log.Fatalf("Failed to create breakpoint at %v: %v\n", addr, err)
		}
	}
}
