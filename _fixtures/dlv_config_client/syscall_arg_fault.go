package main

import (
	"fmt"
	"log"
	"syscall"
	_ "syscall"
	"unsafe"
)

// Call Syscall6 directly so can easily set wp on arg, and access arg after
func main() {
	var _p0 *byte
	_p0, err := syscall.BytePtrFromString("proc_test.go")
	if err != nil {
		log.Panicf("BytePtrFromString err: %v\n", err.Error())
	}
	_, _, e1 := syscall.Syscall6(syscall.SYS_OPEN, uintptr(unsafe.Pointer(_p0)), uintptr(0), uintptr(0), 0, 0, 0)
	if e1 != 0 {
		log.Panicf("Open err: %v\n", e1)
	} else {
		fmt.Printf("Open succeeded\n")
	}

	_ = *_p0
}
