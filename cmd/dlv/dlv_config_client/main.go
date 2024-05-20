package main

import (
	"fmt"
	"log"
	"os/exec"

	"github.com/go-delve/delve/service/api"
	"github.com/go-delve/delve/service/rpc2"
)

var (
	current_scope = api.EvalScope{GoroutineID: -1, Frame: 0}
)

const (
	CODEQL_DB = "../codeql-home/test_df_db"
)

/* Given a watched variable and a line on which a read watchpoint hits,
 * query CodeQL for tainted variables */
func PropagateTaint(watched_var string, file string, lineno int) {
	WriteQueryFile(file, lineno)

	cmd := exec.Command("codeql", "database", "analyze",
		CODEQL_DB,
		CODEQL_QUERY_FILE,
		"--format=csv", "--output=tmp_codeql_results.csv",
		"--threads=6", "--verbose", "--rerun")
	if cmd.Run() != nil {
		log.Fatalf("Error querying CodeQL for %v in %v:%v\n", watched_var, file, lineno)
	}

	ReadQueryOutput()

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

	// TODO this still triggers on writes as well -- seems to be an rr issue (`rwatch` does the same, even in cpp)
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

					PropagateTaint(hit_bp.WatchExpr, instr.Loc.File, instr.Loc.Line)
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
