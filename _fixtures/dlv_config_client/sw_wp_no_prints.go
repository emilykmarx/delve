package main

import (
	"fmt"
	"runtime"
	_ "syscall"
)

var (
	x = 1
)

func f() {
	y := 2
	runtime.KeepAlive(x)
	if x == 1 {
		y = x
	}
	_ = y
	fmt.Println(y)
}

func main() {
	for i := 0; i < 100; i++ {
		f()
	}
}
