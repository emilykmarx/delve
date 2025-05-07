package main

import (
	"fmt"
	_ "syscall"
)

// Append with non-reference elems
func main() {
	old := []int{1, 2}
	new := make([]int, 1)
	new = append(new, old[0]) // Hit for old[0] (copied into new) => new[1] is tainted by old[0], new[0] is untainted
	fmt.Println()
}
