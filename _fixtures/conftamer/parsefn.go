package main

import (
	"fmt"
	_ "net/http/pprof"
	"runtime"
)

func Index[S comparable](s_caller S) int {
	fmt.Println(s_caller)
	return -1
}

func main() {
	s := 1
	runtime.KeepAlive(s)
	found := Index(s)
	fmt.Printf("found: %v\n", found)
}
