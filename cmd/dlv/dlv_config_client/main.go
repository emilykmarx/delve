package main

import (
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/go-delve/delve/service/api"
	"github.com/go-delve/delve/service/rpc2"
)

// PERF: Avoid re-parsing files
// TODO handle >4 wp

func main() {
	fmt.Printf("Starting delve config client\n\n")
	log.SetFlags(log.Lshortfile)
	listenAddr := "localhost:4040"
	client := rpc2.NewClient(listenAddr)
	/*
		initial_bp_file := "/usr/local/go/src/net/dnsconfig_unix.go"
		initial_bp_line := 144 // about to return conf
	*/

	initial_bp_file := "/home/emily/projects/config_tracing/delve/cmd/dlv/dlv_config_client/test/test.go"
	initial_bp_line := 43

	// Continue until variable declaration
	var_decl_bp := api.Breakpoint{File: initial_bp_file, Line: initial_bp_line}
	if _, err := client.CreateBreakpoint(&var_decl_bp); err != nil {
		if !strings.HasPrefix(err.Error(), "Breakpoint exists at") { // ok if existed
			log.Fatalf("Error creating breakpoint at %v: %v\n", var_decl_bp, err)
		}
	}

	//config_var := "s"
	config_var := "conf.search"
	//	config_var := "stack"

	if state := <-client.Continue(); state.Exited || state.Err != nil {
		log.Fatalf("Unexpected state %+v before hitting declaration of watch variable: %v\n", state, config_var)
	}

	// We really want a read-only wp, but rr's read-only hw wp are actually read-write
	fmt.Printf("Setting initial watchpoint on %v\n", config_var)
	if _, err := client.CreateWatchpoint(api.EvalScope{GoroutineID: -1}, config_var, api.WatchRead|api.WatchWrite); err != nil {
		if !strings.HasPrefix(err.Error(), "Breakpoint exists at") { // ok if existed
			log.Fatalf("Error creating watchpoint at %v: %v\n", config_var, err)
		}
	}

	// TODO somehow prevent compiler from reading watched vars from registers -
	// runtime.KeepAlive() helps, but only if placed correctly (at end of scope doesn't always work)
	state := <-client.Continue()

	for ; !state.Exited; state = <-client.Continue() {
		if state.Err != nil {
			log.Fatalf("Error in debugger state: %v\n", state.Err)
		}

		for _, thread := range state.Threads {
			hit_bp := thread.Breakpoint
			if hit_bp != nil {
				if hit_bp.WatchExpr != "" {
					tc := TaintCheck{client: client, hit_bp: hit_bp}
					// Note PC has advanced one past the breakpoint by now, for hardware breakpoints (but not software)

					fmt.Println("\n\n*** Hit watchpoint ***")
					fmt.Println("Bp before handling:")
					bps, err := tc.client.ListBreakpoints(true)
					if err != nil {
						log.Fatalf("ERR")
					}
					for _, bp := range bps {
						for _, addr := range bp.Addrs {
							fmt.Printf("%v, %x\n", bp.WatchExpr, addr)
						}
					}
					tc.hittingLine()
					tc.propagateTaint()
					tc.restore(thread.PC)
					fmt.Println("Bp after handling:")
					bps, err = tc.client.ListBreakpoints(true)
					if err != nil {
						log.Fatalf("ERR")
					}
					for _, bp := range bps {
						for _, addr := range bp.Addrs {
							fmt.Printf("%v, %x\n", bp.WatchExpr, addr)
						}
					}
				} else {
					fmt.Printf("Hit breakpoint in %v\n", hit_bp.FunctionName)
				}
			}
		}

		for _, wp_oos := range state.WatchOutOfScope {
			fmt.Printf("Watchpoint on %v went out of scope since last continue\n", wp_oos.WatchExpr)
			os.Exit(1)
		}
	}

	fmt.Printf("Target exited with status %v\n", state.ExitStatus)
	fmt.Println("Detaching delve config client")
	client.Detach(false)
}
