package main

import (
	"fmt"
	"math/rand"
	"slices"
	"strings"
	_ "syscall"
)

func main() {
	b := byte(rand.Intn(1)) // always 0 - just tricks compiler so watchpoint hits
	arr := []string{string([]byte{b})}
	fmt.Printf("ARR: %v\n", arr[0][0])
	if slices.Contains(arr, string(0)) {
		x := 4 // propagate to x
		y := 5 // propagate to y
		fmt.Println(x)
		fmt.Println(y)
	}

	// hit in internal (bytealg.IndexByteString) - within the function, not setting up to call it
	// treat its retval as tainted instead of propagating to its args
	i := strings.IndexByte(arr[0], 0)
	strings.IndexByte("hi", 0) // Re-enter bytealg.IndexByteString, to confirm we didn't set a pending wp there
	fmt.Println(i)
}
