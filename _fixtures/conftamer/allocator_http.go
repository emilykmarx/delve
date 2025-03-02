package main

import (
	"fmt"
	"log"
	"net/http"
	_ "net/http/pprof"
	"time"
)

// End-to-end test for moving tainted heap objects:
// Make HTTP request, update pointers, watchpoint hits for new location

func f() *int {
	y := 2
	res := y * 2
	return &res
}

func main() {
	go func() {
		log.Println(http.ListenAndServe("localhost:6060", nil))
	}()
	// let server start (for debugging - so can find its thread easily)
	time.Sleep(100 * time.Millisecond) // w/ regular bp on server at l27: conn refused if 100ms, hangs if 1s
	ptr := f()                         // *ptr is on heap
	fmt.Printf("old addr: %#x\n", ptr) // set wp on *ptr => will move *ptr and update ptr
	time.Sleep(1 * time.Second)        // do the move (don't want to access in meantime)
	fmt.Println("target about to access")
	x := *ptr // wp hit (for moved *ptr) => propagate to x
	fmt.Println("target exit; %v", x)
}
