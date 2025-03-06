package main

import (
	"flag"
	"log"

	"github.com/go-delve/delve/conftamer"
)

func main() {
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds | log.Lshortfile)

	initial_bp_file := flag.String("initial_bp_file", "", "File to set initial breakpoint")
	initial_bp_line := flag.Int("initial_bp_line", 0, "Line number to set initial breakpoint")
	initial_watchexpr := flag.String("initial_watchexpr", "", "Expression to set initial watchpoint")
	module := flag.String("module", "", "Target module name")
	move_wps := flag.Bool("move_wps", true, "Whether to request move object on setting software watchpoint")
	event_log_file := flag.String("event_log_file", "", "Filename for event log")
	behavior_map_file := flag.String("behavior_map_file", "", "Filename for final behavior map")
	flag.Parse()

	conftamer, err := conftamer.New(*initial_bp_file, *initial_bp_line, *initial_watchexpr, *module, *move_wps,
		*event_log_file, *behavior_map_file)
	if err != nil {
		log.Panicf("conftamer.New: %v\n", err.Error())
	}
	conftamer.Run()
}
