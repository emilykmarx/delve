package main

import (
	_ "syscall"
)

// Lots of accesses to mprotected page, but no prints

func main() {
	x := 1 // initially tainted
	y := 2
	// Should hit twice per loop
	for i := 0; i < 1; i++ {
		if x == 1 {
			y = x
		}
		_ = y
	}
}
