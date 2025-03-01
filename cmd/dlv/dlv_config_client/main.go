package main

import (
	"flag"
	"fmt"
	"log"

	"github.com/go-delve/delve/pkg/proc"
	"github.com/go-delve/delve/service/rpc2"
)

// Run the target until exit
func (tc *TaintCheck) run() {
	state := <-tc.client.Continue()

	for ; !state.Exited; state = <-tc.client.Continue() {
		if state.Err != nil {
			log.Fatalf("Error in debugger state: %v\n", state.Err)
		}
		tc.updateMovedWps()

		for _, thread := range state.Threads {
			hit_bp := thread.Breakpoint
			if hit_bp != nil {
				tc.hit = Hit{hit_bp: hit_bp}
				tc.thread = thread
				// TODO see gdoc (Instr that would hit multiple*) - may need more logic here for multiple hits
				fmt.Printf("CLIENT bp: %+v\n", hit_bp)
				if hit_bp.Name == proc.SyscallEntryBreakpoint {
					tc.onSyscallEntryBpHit()
				} else if hit_bp.WatchExpr != "" {
					tc.onWatchpointHit()
				} else {
					// Assumes the hit bp is for a pending wp (but could instead be e.g. fatalpanic)
					fmt.Printf("thread at bp, line %v\n", thread.Line)
					tc.onPendingWpBpHit()
				}
			}
		}

		// TODO also need to remove any PreviousAddrs?
		for _, wp_oos := range state.WatchOutOfScope {
			loc := state.SelectedGoroutine.CurrentLoc
			fmt.Printf("Watchpoint on %v went out of scope - current goroutine at %v:%v (0x%x) \n",
				wp_oos.WatchExpr, loc.File, loc.Line, loc.PC)
			tc.forEachWatchaddr(wp_oos, func(watchaddr uint64) bool {
				delete(tc.mem_param_map, watchaddr)
				return true // unused
			})
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
	move_wps := flag.Bool("move_wps", true, "Whether to request move object on setting software watchpoint")
	flag.Parse()

	listenAddr := "localhost:4040"
	client := rpc2.NewClient(listenAddr)

	// TODO somehow prevent compiler from reading watched vars from registers -
	// runtime.KeepAlive() helps, but only if placed correctly (at end of scope doesn't always work)
	// This includes when a struct is initialized just before using it as a recvr (i.e. recvr := Recvr{X: x} recvr.f())

	tc := TaintCheck{client: client,
		move_wps:      *move_wps,
		pending_wps:   make(map[uint64]PendingWp),
		mem_param_map: make(map[uint64]TaintingVals),
		behavior_map:  make(map[BehaviorValue]TaintingVals)}

	init_loc := tc.lineWithStmt(nil, *initial_bp_file, *initial_bp_line, 0)

	// This will be replaced by a config breakpoint
	fmt.Printf("Configuration variable: %v\n", *initial_watchexpr)
	tc.recordPendingWp(*initial_watchexpr, init_loc, nil)

	tc.run()

	fmt.Println("Detaching delve config client") // Also kills server, despite function doc (even on unmodified dlv)
	client.Detach(false)
}
