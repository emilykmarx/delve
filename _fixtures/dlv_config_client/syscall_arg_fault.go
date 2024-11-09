package main

import (
	"fmt"
	"log"
	"os"
	_ "syscall"
)

// Open involves multiple syscalls: openat (non-spuriously faults in the test),
// write (spuriously faults), others (no fault)
func main() {
	_, err := os.Open("proc_test.go")
	if err != nil {
		log.Panicf("Open err: %v\n", err.Error())
	} else {
		fmt.Printf("Open succeeded\n")
	}
}
