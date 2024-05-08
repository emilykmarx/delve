package main

import (
	"fmt"
	"runtime"
)

var Global int

func main() {
	var stack, spacer string
	stack = "hi"
	// Force compiler to read variable from memory, not register
	runtime.KeepAlive(stack) // Not a read (copies from rax to its own stack location)
	// More stuff to make it more obvious it's hitting bc of the spacer = stack, not KeepAlive
	Global = 1
	Global = 2
	spacer = stack // Read
	fmt.Printf("I'm using spacer %v\n", spacer)
}
