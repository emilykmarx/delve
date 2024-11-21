package main

import (
	"fmt"
	"runtime"
	_ "syscall"
)

func main() {
	x := 1 // initially tainted
	runtime.KeepAlive(x)
	y := int(x) // assign to casted x => propagate to y
	fmt.Printf("using y %v\n", y)
}
