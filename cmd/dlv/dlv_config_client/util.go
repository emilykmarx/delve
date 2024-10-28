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
	"strings"

	"github.com/go-delve/delve/pkg/terminal"
	"github.com/go-delve/delve/service/api"
	"github.com/go-delve/delve/service/rpc2"
)

// Add pending wp's tainted vals to existing ones
func (tc *TaintCheck) updateTaintingVals(info PendingWp, bp_addr uint64, watchaddr uint64) {
	for new_val := range info.tainting_vals.params {
		tc.mem_param_map[watchaddr].params[new_val] = struct{}{}
	}
	tc.pending_wps[bp_addr] = info
}

// If wp hits for an addr not in the mem-param map,
// may be because that wp was moved => if so, update mem-param map entry to new addr
// and return entry's vals
func (tc *TaintCheck) updateMovedWps(hit_wp_addr uint64) *TaintingVals {
	// TODO: add a test for this - works in xenon when it's needed, but not needed deterministically
	bps, list_err := tc.client.ListBreakpoints(true)
	if list_err != nil {
		log.Fatalf("Error listing breakpoints: %v\n", list_err)
	}
	for _, bp := range bps {
		if bp.Addrs[0] == hit_wp_addr {
			for _, prev_addr := range bp.PreviousAddrs {
				if tainting_vals, ok := tc.mem_param_map[prev_addr]; ok {
					delete(tc.mem_param_map, prev_addr)
					tc.mem_param_map[hit_wp_addr] = tainting_vals
					return &tainting_vals
				}
			}
		}
	}
	return nil
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

// Find the next line on or after this one with a statement, so we can set a bp.
// TODO May want to consider doing this with PC when handle the non-linear stuff
func (tc *TaintCheck) lineWithStmt(fn *string, file string, lineno int, frame int) api.Location {
	var loc string
	if fn != nil {
		locs, _, err := tc.client.FindLocation(api.EvalScope{GoroutineID: -1, Frame: frame}, *fn, true, nil)
		if err != nil {
			if strings.Contains(err.Error(), "ambiguous") {
				// Ambiguous name => qualify with package name
				tokens := strings.Split(tc.hit.hit_instr.Loc.File, "/")
				pkg := tokens[len(tokens)-2]
				if pkg == "dlv_config_client" { // running in test
					pkg = "main"
				}
				qualified_fn := pkg + "." + *fn
				locs, _, err = tc.client.FindLocation(api.EvalScope{GoroutineID: -1, Frame: frame}, qualified_fn, true, nil)
				if err != nil {
					log.Fatalf("Error finding function %v in frame %v: %v\n", qualified_fn, frame, err)
				}
			} else {
				log.Fatalf("Error finding function %v in frame %v: %v\n", *fn, frame, err)
			}
		}
		file = locs[0].File
		lineno = locs[0].Line + 1
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
