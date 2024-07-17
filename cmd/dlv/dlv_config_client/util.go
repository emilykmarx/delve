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

// TODO (minor): Combine these 3 deletion fcts - Go has generics now
// Remove watcharg from list of pending ones for this bp_addr (if it existed)
func (tc *TaintCheck) deleteWatchArg(watcharg int, bp_addr uint64) {
	info, ok := tc.pending_wps[bp_addr]
	if !ok {
		return
	}
	new_watchargs := []int{}
	for _, argno := range info.watchargs {
		if argno != watcharg {
			new_watchargs = append(new_watchargs, argno)
		}
	}
	info.watchargs = new_watchargs
	tc.pending_wps[bp_addr] = info
}

// Remove watchexpr from list of pending ones for this bp_addr (if it existed)
func (tc *TaintCheck) deleteWatchExpr(watchexpr string, bp_addr uint64) {
	info, ok := tc.pending_wps[bp_addr]
	if !ok {
		return
	}
	new_watchexprs := []string{}
	for _, expr := range info.watchexprs {
		if expr != watchexpr {
			new_watchexprs = append(new_watchexprs, expr)
		}
	}
	info.watchexprs = new_watchexprs
	tc.pending_wps[bp_addr] = info
}

// Remove watchaddr from list of pending ones for this bp_addr (if it existed)
func (tc *TaintCheck) deleteWatchAddr(watchaddr uint64, bp_addr uint64) {
	info, ok := tc.pending_wps[bp_addr]
	if !ok {
		return
	}
	new_watchaddrs := []uint64{}
	for _, addr := range info.watchaddrs {
		if addr != watchaddr {
			new_watchaddrs = append(new_watchaddrs, addr)
		}
	}
	info.watchaddrs = new_watchaddrs
	tc.pending_wps[bp_addr] = info
}

// number of existing wps
func (tc *TaintCheck) nWps() int {
	bps, list_err := tc.client.ListBreakpoints(true)
	if list_err != nil {
		log.Fatalf("Error listing breakpoints: %v\n", list_err)
	}
	n_wps := 0
	for _, bp := range bps {
		if bp.WatchExpr != "" {
			n_wps += 1
		}
	}

	return n_wps
}

// pretty-print
func (pendingwp PendingWp) String() string {
	return fmt.Sprintf("{watchexprs %v watchargs %v watchaddrs %x}",
		pendingwp.watchexprs, pendingwp.watchargs, pendingwp.watchaddrs)
}

// Get line of source (as string)
func sourceLine(client *rpc2.RPCClient, file string, lineno int) string {
	if os.Setenv("TERM", "dumb") != nil {
		log.Fatalf("Error setting TERM=dumb")
	}

	t := terminal.New(client, nil)
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

var handledBuiltins = map[string]bool{"append": true}

// TODO should also consider modeling other built-ins
// Whether return value is tainted
func (tc *TaintCheck) handleBuiltinFct(call_node *ast.CallExpr) bool {
	if exprToString(call_node.Fun) == "append" {
		fmt.Println("handling builtin")
		// Any elem tainted, or slice already tainted => ret tainted
		// (handles possible realloc)
		for _, arg := range call_node.Args {
			if tc.isTainted(arg) {
				return true
			}
		}
	}
	return false
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
