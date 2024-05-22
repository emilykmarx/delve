package main

import (
	"fmt"
	"runtime"
)

func f(tainted_param int) {
	runtime.KeepAlive(tainted_param)
	fmt.Printf("Reading tainted_param %v\n", tainted_param)
}

func main() {
	var stack int // Stack is initially tainted
	var spacer int
	stack = 1 // Write stack
	// Force compiler to read variable from memory, not register
	runtime.KeepAlive(stack)  // Not a read (copies from rax to its own stack location)
	spacer = stack            // Assign => propagate to spacer
	runtime.KeepAlive(spacer) // Need for param passing to read spacer
	f(spacer)                 // Call => propagate to tainted_param
}
