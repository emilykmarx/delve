package main

import (
	"fmt"
	"os"
	"runtime"
	_ "syscall"
)

// Note Open involves multiple syscalls: openat, epollctl
func main() {
	_, err := os.Open("proc_test.go")
	if err != nil {
		fmt.Printf("Open err: %v\n", err.Error())
		runtime.Breakpoint()
	} else {
		fmt.Printf("Open succeeded\n")
		runtime.Breakpoint()
	}
}
