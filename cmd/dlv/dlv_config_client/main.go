package main

import (
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"

	"github.com/go-delve/delve/pkg/terminal"
	"github.com/go-delve/delve/service/api"
	"github.com/go-delve/delve/service/rpc2"
)

var (
	current_scope = api.EvalScope{GoroutineID: -1, Frame: 0}
)

/* Get instruction and source line corresponding to preceding PC in the function,
 * assuming preceding PC did not branch. */
func PCToPrevPCLine(client *rpc2.RPCClient, PC uint64) (api.AsmInstruction, string) {
	fct_instrs, err := client.DisassemblePC(current_scope, PC, api.IntelFlavour) // dst, src
	if err != nil {
		log.Fatalf("Error getting instructions at PC 0x%x: %v\n", PC, err)
	}

	var prev_instr api.AsmInstruction
	for i, instr := range fct_instrs {
		if instr.Loc.PC == PC {
			if i == 0 {
				log.Fatalf("No previous instruction for PC 0x%x\n", PC)
			}
			prev_instr = fct_instrs[i-1]
		}
	}

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

func main() {
	fmt.Println("Starting delve config client\n")
	listenAddr := "localhost:4040"
	client := rpc2.NewClient(listenAddr)

	// Continue until variable declaration
	var_decl_bp := api.Breakpoint{File: "/home/emily/projects/config_tracing/delve/cmd/dlv/dlv_config_client/test/test.go", Line: 12}
	if _, err := client.CreateBreakpoint(&var_decl_bp); err != nil {
		log.Fatalf("Error creating breakpoint at %v: %v\n", var_decl_bp, err)
	}

	//config_var := "conf.search[0]"
	config_var := "stack"

	if state := <-client.Continue(); state.Exited || state.Err != nil {
		log.Fatalf("Unexpected state %+v before hitting declaration of watch variable: %v\n", state, config_var)
	}

	// read-only not supported in delve yet
	if _, err := client.CreateWatchpoint(current_scope, config_var, api.WatchRead|api.WatchWrite); err != nil {
		log.Fatalf("Error creating watchpoint at %v: %v\n", config_var, err)
	}

	// TODO add a runtime.KeepAlive() to watched variables
	state := <-client.Continue()

	for ; !state.Exited; state = <-client.Continue() {
		if state.Err != nil {
			log.Fatalf("Error in debugger state: %v\n", state.Err)
		}

		for _, thread := range state.Threads {
			hit_bp := thread.Breakpoint
			if hit_bp != nil {
				instr, src_line := PCToPrevPCLine(client, thread.PC)
				hit_loc := fmt.Sprintf("%v:%v:%v:0x%x \n%v \n%v",
					thread.File, instr.Loc.Line, thread.Function.Name(),
					instr.Loc.PC, instr.Text, src_line)
				if hit_bp.WatchExpr != "" {
					// TODO skip if due to stack resize (but not if same line does a resize and a real read)

					/* Note PC has advanced one past the breakpoint by now.
					 * TODO handle the case where this PC is in a different function than the breakpoint,
					 * i.e. breakpoint was at a CALL. */
					fmt.Printf("Hit watchpoint for %v\nAt %v\n\n", hit_bp.WatchExpr, hit_loc)
				} else {
					fmt.Printf("Hit breakpoint at %v\n\n", hit_loc)
				}
			}
		}

		for _, wp_oos := range state.WatchOutOfScope {
			fmt.Printf("Watchpoint on %v went out of scope since last continue\n", wp_oos.WatchExpr)
		}
	}

	fmt.Printf("Target exited with status %v\n", state.ExitStatus)
	fmt.Println("Detaching delve config client")
	client.Detach(false)
}
