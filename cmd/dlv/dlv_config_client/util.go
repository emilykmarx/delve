package main

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/parser"
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

/* Get instruction and source line corresponding to preceding PC, for selected goroutine */
func PCToPrevPCLine(client *rpc2.RPCClient, pc uint64) (api.AsmInstruction, string) {
	/* TODO for now, assume goroutine that hit the bp is currently selected.
	 * Should instead switch to that goroutine (need to read doc carefully:
	 * https://github.com/go-delve/delve/blob/master/Documentation/api/ClientHowto.md#using-rpcservercommand)
	 * (remember to pass that scope to Disass)
	 * May be convenient to do the check for stack resize at same time */

	state, err := client.ReverseStepInstruction(false)
	if err != nil {
		log.Fatalf("Error reverse-stepping at PC 0x%x: %v\n", pc, err)
	}
	prev_pc := state.SelectedGoroutine.CurrentLoc.PC
	state, err = client.StepInstruction(false)
	if err != nil {
		log.Fatalf("Error stepping at PC 0x%x: %v\n", prev_pc, err)
	}
	cur_pc := state.SelectedGoroutine.CurrentLoc.PC
	if pc != cur_pc {
		log.Fatalf("Failed to restore PC 0x%x; current PC is 0x%x\n", prev_pc, cur_pc)
	}

	// end is exclusive
	_prev_instr, err := client.DisassembleRange(current_scope, prev_pc, pc, api.IntelFlavour) // dst, src
	if err != nil {
		log.Fatalf("Error getting instructions at PC 0x%x: %v\n", prev_pc, err)
	} else if len(_prev_instr) != 1 {
		log.Fatalf("DisassembleRange returned %v instr for PC 0x%x\n", len(_prev_instr), prev_pc)
	}

	prev_instr := _prev_instr[0]

	if os.Setenv("TERM", "dumb") != nil {
		log.Fatalf("Error setting TERM=dumb")
	}

	t := terminal.New(client, nil)
	lines, err := t.GetOutput(fmt.Sprintf("list %v:%v", prev_instr.Loc.File, prev_instr.Loc.Line))
	if err != nil {
		log.Fatalf("Error getting source code for PC 0x%x: %v\n", prev_instr.Loc.PC, err)
	}

	var src_line string
	for _, line := range strings.Split(lines, "\n") {
		var curline int
		if strings.HasPrefix(line, "Showing") || line == "" {
			continue
		}
		if _, err := fmt.Sscanf(line, " %d:", &curline); err != nil {
			log.Fatalf("Failed to parse line number from line: %v: %v\n", line, err)
		}
		if curline != prev_instr.Loc.Line {
			continue
		}
		re := regexp.MustCompile(`\s+(\d+):\s+`)
		src_start := re.FindStringIndex(line)[1]
		if src_start <= len(line)-1 {
			src_line = line[src_start:]
		} else {
			log.Fatalf("Breakpoint PC 0x%x corresponds to empty line\n", prev_instr.Loc.PC)
		}
	}

	if src_line == "" {
		log.Fatalf("No source line found for PC 0x%x\n", prev_instr.Loc.PC)
	}

	return prev_instr, src_line
}

func exprToString(t ast.Expr) string {
	var buf bytes.Buffer
	printer.Fprint(&buf, token.NewFileSet(), t)
	return buf.String()
}

// Get exprs that are written on a line, excluding watchexpr
func getExprsWritten(watchexpr string, file string, lineno int) (exprs_written []string) {
	fset := token.NewFileSet()
	root, err := parser.ParseFile(fset, file, nil, parser.SkipObjectResolution)
	if err != nil {
		log.Fatalf("Failed to parse source file %v: %v\n", file, err)
	}

	ast.Inspect(root, func(node ast.Node) bool {
		// PERF: How to properly only inspect one line?
		cur_line := -1
		if node != nil {
			cur_line = fset.Position(node.Pos()).Line
		}
		if cur_line != lineno {
			return true
		}

		switch typed_node := node.(type) {
		case *ast.AssignStmt:
			for _, expr_written := range typed_node.Lhs {
				expr_str := exprToString(expr_written)
				if expr_str != watchexpr {
					exprs_written = append(exprs_written, expr_str)
				}
			}
		}
		// TODO fct calls
		return true
	})

	return exprs_written
}

const (
	CODEQL_QUERY_PATH      = "../codeql-home/codeql-repo/go/ql/examples/snippets/"
	CODEQL_QUERY_FILE      = "tmp_query.ql"
	CODEQL_FILE_TEMPLATE   = "XXX_FILE"
	CODEQL_LINENO_TEMPLATE = "-1"
)

func WriteQueryFile(file string, lineno int) {
	input, err := os.ReadFile(CODEQL_QUERY_PATH + "util.qll")
	if err != nil {
		log.Fatalf("Error reading query template file: %v\n", err)
	}

	lines := strings.Split(string(input), "\n")

	for i := range lines {
		lines[i] = strings.ReplaceAll(lines[i], CODEQL_FILE_TEMPLATE, file)
		lines[i] = strings.ReplaceAll(lines[i], CODEQL_LINENO_TEMPLATE, fmt.Sprintf("%v", lineno))
	}
	output := strings.Join(lines, "\n")
	err = os.WriteFile(CODEQL_QUERY_FILE, []byte(output), 0644)
	if err != nil {
		log.Fatalf("Error writing query file: %v\n", err)
	}
}

func ReadQueryOutput() {

}
