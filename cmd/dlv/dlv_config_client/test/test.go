package main

import (
	"fmt"
	"runtime"
)

func ret_untainted(tainted_param int) int {
	runtime.KeepAlive(tainted_param)
	fmt.Printf("Reading tainted_param %v\n", tainted_param)
	return 2
}

func ret_tainted(tainted_param_2 int) int {
	runtime.KeepAlive(tainted_param_2)
	fmt.Printf("Reading tainted_param_2 %v\n", tainted_param_2)
	return tainted_param_2
}

func main() {
	var stack int // Stack is initially tainted
	var spacer int
	stack = 1 // Write stack
	// Force compiler to read variable from memory, not register
	runtime.KeepAlive(stack)         // Not a read (copies from rax to its own stack location)
	spacer = stack                   // Assign => propagate to spacer
	runtime.KeepAlive(spacer)        // Need for param passing to read spacer
	y := ret_untainted(spacer+1) + 3 // Call+assign, hit in call, untainted ret => propagate to tainted_param
	runtime.KeepAlive(y)
	y = ret_tainted(spacer+1) + 3 // Call+assign, hit in call, tainted ret => propagate to tainted_param and y
	fmt.Printf("Using y%v\n", y)
	z := ret_untainted(3) + spacer // Call+assign, hit in assign rhs => propagate to z
	fmt.Printf("Using z%v\n", z)
	runtime.KeepAlive(z) // (wp hits for KeepAlive, not printf)
}
