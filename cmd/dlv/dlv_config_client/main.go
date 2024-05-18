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

func main() {
	fmt.Printf("Starting delve config client\n\n")
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

	// TODO this still triggers on writes as well -- seems to be an rr issue (`rwatch` does the same)
	// Either fix rr, or ignore write hits (e.g. use rr to compare value before and after)
	if _, err := client.CreateWatchpoint(current_scope, config_var, api.WatchRead); err != nil {
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
				if hit_bp.WatchExpr != "" {
					instr, src_line := PCToPrevPCLine(client, state.SelectedGoroutine.CurrentLoc.PC)
					hit_loc := fmt.Sprintf("%v:%v:%v:0x%x \n%v \n%v",
						instr.Loc.File, instr.Loc.Line, instr.Loc.Function.Name(),
						instr.Loc.PC, instr.Text, src_line)
					// TODO skip if due to stack resize (but not if same line does a resize and a real read)

					// Note PC has advanced one past the breakpoint by now, for hardware breakpoints (but not software)
					fmt.Printf("Hit watchpoint for %v\nAt %v\n\n", hit_bp.WatchExpr, hit_loc)
				} else {
					fmt.Printf("Hit breakpoint in %v\n\n", hit_bp.FunctionName)
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
