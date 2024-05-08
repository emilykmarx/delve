package main

import (
	"fmt"
	"math/rand"
	"runtime"
)

var Global int

// Two ways to force compiler to read variable from memory, not register

// With break at stack write line, hits at (i.e. "Thread at" print) spacer write (expected) and if (would've expected Printf instead)
func overwrite_rax() {
	var stack, spacer int
	stack = rand.Int()  // Force read of branch condition
	spacer = rand.Int() // Overwrite rax so stack must be read
	if stack == 1 {     // Read
		fmt.Printf("I'm using spacer %v\n", spacer)
	}
}

func main() {
	var stack int
	var spacer int
	stack = 1
	runtime.KeepAlive(stack) // Not a read (copies from rax to its own stack location)
	// More stuff to make it more obvious it's hitting bc of the spacer = stack, not KeepAlive
	Global = 1
	Global = 2
	spacer = stack // Read
	fmt.Printf("I'm using spacer %v\n", spacer)
}
