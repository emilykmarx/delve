package main

import (
	"fmt"
	_ "syscall"
)

func main() {
	// vars[0] initially tainted, bp_addr = range stmt
	vars := []int{0, 1, 2, 3, 4, 5}
	for i := range vars {
		if i > 0 {
			// hit for vars[i-1] => prop to vars[i]
			vars[i] = vars[i-1]
			// put off properly finding when var is in scope (should likely be next TODO...)
			fmt.Println()
		}
	}
}
