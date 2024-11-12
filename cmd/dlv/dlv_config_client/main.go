package main

import (
	"flag"
	"fmt"
	"log"

	"github.com/go-delve/delve/service/rpc2"
)

// PERF: Avoid re-parsing files

// Run the target until exit
func (tc *TaintCheck) run() {
	state := <-tc.client.Continue()

	for ; !state.Exited; state = <-tc.client.Continue() {
		if state.Err != nil {
			log.Fatalf("Error in debugger state: %v\n", state.Err)
		}

		for _, thread := range state.Threads {
			hit_bp := thread.Breakpoint
			if hit_bp != nil {
				tc.hit = Hit{hit_bp: hit_bp}
				tc.thread = thread
				// TODO see gdoc (Instr that would hit multiple*) - may need more logic here for multiple hits
				if hit_bp.WatchExpr != "" {
					tc.onWatchpointHit()
				} else {
					// Assumes the hit bp is for a pending wp (but could instead be e.g. fatalpanic)
					tc.onPendingWpBpHit()
				}
			}
		}

		for _, wp_oos := range state.WatchOutOfScope {
			fmt.Printf("Watchpoint on %v went out of scope since last continue\n", wp_oos.WatchExpr)
			delete(tc.mem_param_map, wp_oos.Addrs[0])
		}
	}

	fmt.Printf("Target exited with status %v\n", state.ExitStatus)
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
		pending_wps:   make(map[uint64]PendingWp),
		mem_param_map: make(map[uint64]TaintingVals)}

	init_loc := tc.lineWithStmt(nil, *initial_bp_file, *initial_bp_line, 0)

	// This will be replaced by a config breakpoint
	fmt.Printf("Configuration variable: %v\n", *initial_watchexpr)
	tc.recordPendingWp(*initial_watchexpr, init_loc, nil)

	tc.run()

	fmt.Println("Detaching delve config client") // Also kills server, despite function doc (even on unmodified dlv)
	client.Detach(false)
}
