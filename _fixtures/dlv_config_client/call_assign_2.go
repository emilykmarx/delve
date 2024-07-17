package main

import (
	"fmt"
	"runtime"
)

func ret_tainted(tainted_param_2 int) int {
	runtime.KeepAlive(tainted_param_2)
	fmt.Printf("Reading tainted_param_2 %v\n", tainted_param_2)
	return tainted_param_2
}

// Expect 11 hits
func main() {
	var stack int // Stack is initially tainted
	// Hit for stack x 2, tainted_param_2 x 2
	runtime.KeepAlive(stack)
	a := ret_tainted(stack) + stack // Call+assign, hit in both => propagate to tainted_param_2 and a
	// Hit for a x 2
	fmt.Printf("Using a%v\n", a)
	runtime.KeepAlive(a)
}
