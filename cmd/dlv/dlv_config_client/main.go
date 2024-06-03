package main

import (
	"fmt"
	"log"

	"github.com/go-delve/delve/service/rpc2"
)

// PERF: Avoid re-parsing files

// One round of replay
func (tc *TaintCheck) replay() {
	fmt.Println("Replay")

	state := <-tc.client.Continue()

	for ; !state.Exited; state = <-tc.client.Continue() {
		fmt.Println("continued")
		if state.Err != nil {
			log.Fatalf("Error in debugger state: %v\n", state.Err)
		}

		for _, thread := range state.Threads {
			hit_bp := thread.Breakpoint
			if hit_bp != nil {
				tc.hit = Hit{hit_bp: hit_bp}
				if hit_bp.WatchExpr != "" {
					// Note PC has advanced one past the breakpoint by now, for hardware breakpoints (but not software)

					fmt.Printf("\n\n*** Hit watchpoint for %v ***\n", hit_bp.WatchExpr)
					if !tc.hittingLine() {
						fmt.Printf("Ignoring\n")
						continue
					}
					tc.propagateTaint()
				} else {
					fmt.Printf("\n\nHit breakpoint at %v:%v (0x%x)\n", hit_bp.File, hit_bp.Line, hit_bp.Addr)
					tc.onPendingWp()
				}
			}
		}

		for _, wp_oos := range state.WatchOutOfScope {
			fmt.Printf("Watchpoint on %v went out of scope since last continue\n", wp_oos.WatchExpr)
		}
	}

	// Clear wp but keep bp
	bps, list_err := tc.client.ListBreakpoints(true)
	if list_err != nil {
		log.Fatalf("Error listing breakpoints: %v\n", list_err)
	}
	for _, bp := range bps {
		if bp.WatchExpr != "" {
			fmt.Printf("Clearing bp for 0x%x\n", bp.Addr)
			tc.client.ClearBreakpoint(bp.ID)
		}
	}

	for wp := range tc.round_done_wps {
		tc.done_wps[wp] = true
	}
	tc.round_done_wps = make(map[watchpoint]bool)

	fmt.Printf("Target exited with status %v\n", state.ExitStatus)
	tc.client.Restart(false)
}

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
	initial_bp_line := 12

	//config_var := "s"
	//config_var := "conf.search"
	config_var := "vars[0]"

	// TODO somehow prevent compiler from reading watched vars from registers -
	// runtime.KeepAlive() helps, but only if placed correctly (at end of scope doesn't always work)

	pending_watchexpr := make(map[uint64][]string)
	pending_watchargs := make(map[uint64][]int)
	done_wps := make(map[watchpoint]bool)
	round_done_wps := make(map[watchpoint]bool)
	tc := TaintCheck{client: client,
		pending_watchexpr: pending_watchexpr, pending_watchargs: pending_watchargs,
		done_wps: done_wps, round_done_wps: round_done_wps}
	init_loc := tc.lineWithStmt(nil, initial_bp_file, initial_bp_line)

	fmt.Printf("Setting initial watchpoint on %v\n", config_var)
	tc.recordPendingWp(nil, []string{config_var}, init_loc, nil)

	for len(tc.pending_watchexpr) > 0 || len(tc.pending_watchargs) > 0 {
		tc.replay()
	}

	fmt.Println("Detaching delve config client")
	client.Detach(false)
}
