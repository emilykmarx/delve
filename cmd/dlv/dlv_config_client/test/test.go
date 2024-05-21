package main

import (
	"fmt"
	"runtime"
)

var Global int

func main() {
	var stack int // Stack is initially tainted
	var spacer int
	stack = 1 // Write stack
	// Force compiler to read variable from memory, not register
	runtime.KeepAlive(stack)                    // Not a read (copies from rax to its own stack location)
	spacer = stack                              // Read => propagate to spacer
	fmt.Printf("I'm using spacer %v\n", spacer) // Read spacer
}
