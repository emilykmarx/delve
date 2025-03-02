package main

import (
	"flag"
	"log"

	"github.com/go-delve/delve/conftamer"
)

func main() {
	log.SetFlags(log.Lshortfile)

	initial_bp_file := flag.String("initial_bp_file", "", "File to set initial breakpoint")
	initial_bp_line := flag.Int("initial_bp_line", 0, "Line number to set initial breakpoint")
	initial_watchexpr := flag.String("initial_watchexpr", "", "Expression to set initial watchpoint")
	module := flag.String("module", "", "Target module name")
	move_wps := flag.Bool("move_wps", true, "Whether to request move object on setting software watchpoint")
	flag.Parse()

	conftamer := conftamer.New(*initial_bp_file, *initial_bp_line, *initial_watchexpr, *module, *move_wps)
	conftamer.Run()
}
