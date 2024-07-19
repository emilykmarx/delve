package main

import (
	"flag"
	"fmt"
	"log"

	"github.com/go-delve/delve/service/rpc2"
)

// PERF: Avoid re-parsing files

// One round of replay
func (tc *TaintCheck) replay() {
	fmt.Printf("\n\n*** Begin replay\n")
	state := <-tc.client.Continue()

	for ; !state.Exited; state = <-tc.client.Continue() {
		if state.Err != nil {
			log.Fatalf("Error in debugger state: %v\n", state.Err)
		}

		for _, thread := range state.Threads {
			hit_bp := thread.Breakpoint
			if hit_bp != nil {
				tc.hit = Hit{hit_bp: hit_bp}
				if hit_bp.WatchExpr != "" {
					// Note PC has advanced one past the breakpoint by now, for hardware breakpoints (but not software)
					tc.onWatchpointHit()
				} else {
					tc.onPendingWpBpHit()
				}
			}
		}

		fmt.Printf("Mem-config map after continue (before removing OOS):\n")
		for k, v := range tc.mem_param_map {
			fmt.Printf("0x%x => %+v\n", k, v)
		}

		for _, wp_oos := range state.WatchOutOfScope {
			fmt.Printf("Watchpoint on 0x%x went out of scope since last continue\n", wp_oos.Addrs[0])
			delete(tc.mem_param_map, wp_oos.Addrs[0])
		}
	}

	// Clear wp but keep bp
	bps, list_err := tc.client.ListBreakpoints(true)
	if list_err != nil {
		log.Fatalf("Error listing breakpoints: %v\n", list_err)
	}
	for _, bp := range bps {
		if bp.WatchExpr != "" {
			tc.client.ClearBreakpoint(bp.ID)
		}
	}

	for wp := range tc.round_done_wps {
		tc.done_wps[wp] = struct{}{}
	}
	tc.round_done_wps = make(map[DoneWp]struct{})

	fmt.Printf("Target exited with status %v\n", state.ExitStatus)
	tc.client.Restart(false)
}

func main() {
	fmt.Printf("Starting delve config client\n\n")
	log.SetFlags(log.Lshortfile)
	initial_bp_file := flag.String("initial_bp_file", "", "File to set initial breakpoint")
	initial_bp_line := flag.Int("initial_bp_line", 0, "Line number to set initial breakpoint")
	initial_watchexpr := flag.String("initial_watchexpr", "", "Expression to set initial watchpoint")
	flag.Parse()

	listenAddr := "localhost:4040"
	client := rpc2.NewClient(listenAddr)

	// TODO somehow prevent compiler from reading watched vars from registers -
	// runtime.KeepAlive() helps, but only if placed correctly (at end of scope doesn't always work)

	tc := TaintCheck{client: client,
		pending_wps: make(map[uint64]PendingWp),
		done_wps:    make(map[DoneWp]struct{}), round_done_wps: make(map[DoneWp]struct{}),
		mem_param_map: make(map[uint64]TaintingVals)}
	init_loc := tc.lineWithStmt(nil, *initial_bp_file, *initial_bp_line)

	fmt.Printf("Configuration variable: %v\n", *initial_watchexpr)
	tc.config_var = *initial_watchexpr
	tc.config_bp = init_loc.PC
	tc.recordPendingWp(*initial_watchexpr, init_loc, nil)

	for len(tc.pending_wps) > 0 {
		tc.replay()
	}

	fmt.Println("Detaching delve config client")
	client.Detach(false)
}
