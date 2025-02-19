package main

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/printer"
	"go/token"
	"log"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/go-delve/delve/pkg/proc"
	"github.com/go-delve/delve/pkg/terminal"
	"github.com/go-delve/delve/service/api"
	"github.com/go-delve/delve/service/rpc2"
	"github.com/hashicorp/go-set"
)

// Return value of register reg_name
func reg(reg_name string, regs api.Registers) uint64 {
	for _, reg := range regs {
		if reg.Name == reg_name {
			val, err := strconv.ParseUint(reg.Value, 0, 64)
			if err != nil {
				log.Panicf("convert reg %v to int", reg.Value)
			}
			return val
		}
	}
	log.Panicf("reg %v not found", reg_name)
	return 0
}

// Call `f` for each addr in watchpoint's region.
// Return true if f returned true for any addr.
func (tc *TaintCheck) forEachWatchaddr(watchpoint *api.Breakpoint, f func(watchaddr uint64) bool) bool {
	ret := false
	watch_end := watchpoint.Addrs[0] + watchSize(watchpoint)
	for watchaddr := watchpoint.Addrs[0]; watchaddr < watch_end; watchaddr++ {
		if f(watchaddr) {
			ret = true
		}
	}
	return ret
}

// For each addr in watchpoint's region, add taint in pendingWp state to any existing entry in m-p map
// If new entry, insert it
func (tc *TaintCheck) updateTaintingVals(bp_addr uint64, watchpoint *api.Breakpoint) {
	added_taint := tc.pending_wps[bp_addr].tainting_vals.params
	tc.forEachWatchaddr(watchpoint, func(watchaddr uint64) bool {
		existing_taint := tc.mem_param_map[watchaddr].params
		new_taint := added_taint.Union(&existing_taint)
		tc.mem_param_map[watchaddr] = TaintingVals{params: *set.From(new_taint.Slice())}
		fmt.Printf("\tMemory-parameter map: 0x%x => %+v\n", watchaddr, tc.mem_param_map[watchaddr].params)
		return true // unused
	})
}

// Assuming a watchpoint has hit overlapping watchaddr, get its tainting values from the mem-param map
func (tc *TaintCheck) taintingVals(watchaddr uint64) TaintingVals {
	tainting_vals, ok := tc.mem_param_map[watchaddr]
	if !ok {
		log.Fatalf("No mem-param map entry for watchpoint %v\n", tc.hit.hit_bp.WatchExpr)
	}
	return tainting_vals
}

// pretty-print
func (pendingwp PendingWp) String() string {
	return fmt.Sprintf("{watchexprs %v watchargs %v tainting_vals %+v}",
		pendingwp.watchexprs, pendingwp.watchargs, pendingwp.tainting_vals)
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

func memOverlap(addr1 uint64, sz1 uint64, addr2 uint64, sz2 uint64) bool {
	return addr1 < addr2+sz2 && addr2 < addr1+sz1
}

func (tc *TaintCheck) printBps() {
	bps, list_err := tc.client.ListBreakpoints(true)
	if list_err != nil {
		log.Fatalf("Error listing breakpoints: %v\n", list_err)
	}
	for _, bp := range bps {
		if bp.WatchExpr != "" {
			fmt.Printf("Watchpoint at %x\n", bp.Addr)
		} else {
			fmt.Printf("Breakpoint at %x\n", bp.Addr)
		}
	}

}

func printThreads(state *api.DebuggerState) {
	fmt.Println("Threads:")
	for _, th := range state.Threads {
		fmt.Printf("%v at %v\n", th.ID, th.Function.Name_)
	}
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
		fmt.Println(loc)
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
func (tc *TaintCheck) fullArgs(node *ast.CallExpr) []ast.Expr {
	full_args := node.Args
	call_expr := exprToString(node.Fun)
	decl_loc := tc.fnDecl(call_expr, tc.hit.frame)
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
func (tc *TaintCheck) fnDecl(call_expr string, frame int) api.Location {
	locs, _, err := tc.client.FindLocation(api.EvalScope{GoroutineID: -1, Frame: frame}, call_expr, true, nil)
	if err != nil {
		if strings.Contains(err.Error(), "ambiguous") {
			// Ambiguous name => qualify with package name
			tokens := strings.Split(tc.hit.hit_instr.Loc.File, "/")
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
// TODO May want to consider doing this with PC when handle the non-linear stuff
func (tc *TaintCheck) lineWithStmt(call_expr *string, file string, lineno int, frame int) api.Location {
	var loc string
	if call_expr != nil {
		decl_loc := tc.fnDecl(*call_expr, frame)
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
