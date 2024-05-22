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

// Get the name of param at index i, in function scope
func paramCalleeName(root *ast.File, fn string, i int) (param string) {
	for _, decl := range root.Decls {
		fn_node, ok := decl.(*ast.FuncDecl)
		if !ok {
			continue
		}
		if fn_node.Name.Name != fn {
			continue
		}
		params := fn_node.Type.Params.List
		if len(params[i].Names) != 1 {
			// idk when this happens
			log.Fatalf("Fn %v param %v has %v names\n", fn, i, len(params[i].Names))
		}
		return params[i].Names[0].Name
	}

	// TODO model propagation for built-ins?
	fmt.Printf("No declaration for function %v in AST -- ok if built-in\n", fn)
	return
}

/* Assuming lineno reads watchexpr's location,
 * get expressions tainted by the read.
 * Note we don't check that watchexpr was read in the source,
 * to handle aliasing */
func taintedExprs(client *rpc2.RPCClient, watchexpr string, file string, lineno int) (tainted_exprs []string) {
	fset := token.NewFileSet()
	root, err := parser.ParseFile(fset, file, nil, parser.SkipObjectResolution)
	if err != nil {
		log.Fatalf("Failed to parse source file %v: %v\n", file, err)
	}

	// DFS of file's AST
	ast.Inspect(root, func(node ast.Node) bool {
		// PERF: How to properly only inspect one line?
		cur_line := -1
		if node != nil {
			cur_line = fset.Position(node.Pos()).Line
		}
		if cur_line != lineno {
			return true
		}

		// TODO is it possible to hit another wp while stepping/nexting?

		switch typed_node := node.(type) {
		case *ast.CallExpr:
			// Assume watched location was passed as a param =>
			// taint callee's copy of all params
			for i := range typed_node.Args {
				state, err := client.Step()
				if err != nil || state.Exited || state.Err != nil {
					log.Fatalf("Unexpected err %v or state %+v while stepping into %v\n", err, state, exprToString(typed_node.Fun))
				}
				state, err = client.Next()
				if err != nil || state.Exited || state.Err != nil {
					log.Fatalf("Unexpected err %v or state %+v while nexting in %v\n", err, state, exprToString(typed_node.Fun))
				}

				param_callee := paramCalleeName(root, exprToString(typed_node.Fun), i)
				if param_callee != "" {
					tainted_exprs = append(tainted_exprs, param_callee)
				}
			}

		case *ast.AssignStmt:
			// Assume watched location is one of the rhs values =>
			// taint any vars assigned
			for _, lhs := range typed_node.Lhs {
				expr_str := exprToString(lhs)
				if expr_str != watchexpr {
					tainted_exprs = append(tainted_exprs, expr_str)
				}
			}
		}

		return true
	})

	return tainted_exprs
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
