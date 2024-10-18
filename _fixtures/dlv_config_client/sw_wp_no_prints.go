package main

import (
	_ "syscall"
)

// Lots of accesses to mprotected page, but no prints

func main() {
	x := 1
	// get an instr where x is in-scope but doesn't access memory (so can set bp here)
	for i := 0; i < 1; i++ {
		_ = x
	}
	y := 2
	for i := 0; i < 2; i++ {
		if x == 1 {
			y = x
		}
		_ = y
	}
}
