package main

import "fmt"

func main() {
	// vars[0] initially tainted, bp_addr = range stmt
	vars := []int{0, 1, 2, 3, 4, 5}
	for i := range vars {
		if i > 0 {
			// hit for vars[i-1] => prop to vars[i]
			// Round 1: set wp for vars[1,2,3], 4 and 5 are pending
			// Round 2: set wp for vars[4,5]
			vars[i] = vars[i-1]
			// put off properly finding when var is in scope (should likely be next TODO...)
			fmt.Println()
		}
	}
}
