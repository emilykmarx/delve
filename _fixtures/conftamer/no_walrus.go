package main

import (
	"fmt"
	"runtime"
	_ "syscall"
)

// XXX can remove this test - will need to update others
func main() {
	x := 4
	y := 5
	runtime.KeepAlive(x)
	y = x
	fmt.Println(y)
	fmt.Println(x)
}
