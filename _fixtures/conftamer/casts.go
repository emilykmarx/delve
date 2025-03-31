package main

import (
	"fmt"
	"runtime"
	_ "syscall"
)

type MyType int

func main() {
	x := 1 // initially tainted
	runtime.KeepAlive(x)
	y := int(x) // assign to casted x => propagate to y
	fmt.Printf("using y %v\n", y)
	z := MyType(x) // propagate to z
	fmt.Println(z)
}
