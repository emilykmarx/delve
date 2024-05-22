package main

import (
	"fmt"
	"runtime"
)

func f(tainted_param int) int {
	runtime.KeepAlive(tainted_param)
	fmt.Printf("Reading tainted_param %v\n", tainted_param)
	return 2
}

func main() {
	var stack int // Stack is initially tainted
	var spacer int
	stack = 1 // Write stack
	// Force compiler to read variable from memory, not register
	runtime.KeepAlive(stack)  // Not a read (copies from rax to its own stack location)
	spacer = stack            // Assign => propagate to spacer
	runtime.KeepAlive(spacer) // Need for param passing to read spacer
	y := f(spacer+1) + 3      // Call+assign, hit in call => propagate to tainted_param
	runtime.KeepAlive(y)
	y = f(3) + spacer         // Call+assign, hit in assign rhs => propagate to y
	runtime.KeepAlive(spacer) // Need for param passing to read spacer
	fmt.Printf("Using y%v\n", y)
}
