package main

import (
	"fmt"
	"log"

	"github.com/go-delve/delve/service/api"
	"github.com/go-delve/delve/service/rpc2"
)

func main() {
	fmt.Println("Starting delve config client")
	listenAddr := "localhost:4040"
	client := rpc2.NewClient(listenAddr)
	var_decl_bp := api.Breakpoint{File: "/home/emily/projects/config_tracing/delve/cmd/dlv/dlv_config_client/test/test.go", Line: 25}
	if _, err := client.CreateBreakpoint(&var_decl_bp); err != nil {
		log.Fatalf("Error creating breakpoint at %v: %v\n", var_decl_bp, err)
	}
	// Continue until var is in scope
	config_var := "stack"
	if state := <-client.Continue(); state.Exited {
		log.Fatalf("Exited before hitting declaration of watch variable %v\n", config_var)
	}

	current_scope := api.EvalScope{GoroutineID: -1, Frame: 0}
	// read-only not supported in delve yet
	if _, err := client.CreateWatchpoint(current_scope, config_var, api.WatchRead|api.WatchWrite); err != nil {
		log.Fatalf("Error creating watchpoint at %v: %v\n", config_var, err)
	}

	state := <-client.Continue()

	for ; !state.Exited; state = <-client.Continue() {
		if state.Err != nil {
			log.Fatalf("Error in debugger state: %v\n", state.Err)
		}

		for _, thread := range state.Threads {
			hit_bp := thread.Breakpoint
			if hit_bp != nil {
				if hit_bp.WatchExpr == config_var {
					// TODO skip if due to stack resize (but not if same line does a resize and a real read)
					fmt.Printf("Hit watchpoint for %v at %v\n", config_var, thread.Line)
				} else {
					fmt.Printf("Hit breakpoint at %v:%v\n", thread.File, thread.Function)
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
