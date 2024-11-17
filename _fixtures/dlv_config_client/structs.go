package main

import (
	"fmt"
	"runtime"
	_ "syscall"
)

// When a struct is copied, propagate taint of members
type Name struct {
	Data [2]int
	fake int
}

type Nested struct {
	name Name
}

func (q *Nested) f() {
	q.name.ptr_recvr()    // hit for q.name.Data, even tho pointer recvr => don't propagate to recvr.Data
	q.name.nonptr_recvr() // hit for q.name.Data, non-pointer recvr => propagate to callee's copy of recvr.Data
}

func (recvr_callee *Name) ptr_recvr() {
	fmt.Printf("using recvr %v\n", recvr_callee)
}

func (recvr_callee Name) nonptr_recvr() {
	fmt.Printf("using recvr %v\n", recvr_callee)
}

func struct_member(s_callee Name) Name {
	fmt.Printf("%v\n", s_callee)
	return s_callee // return struct => propagate to caller's copy of struct member
}

func main() {
	arr := [2]int{0, 1}                    // arr initially tainted
	struct_lit := Name{Data: arr, fake: 2} // assign to struct (via literal) => propagate to struct's copy of member
	runtime.KeepAlive(struct_lit)
	s := struct_lit // assign to struct (via copy) => propagate to struct's copy of member
	runtime.KeepAlive(s)
	s_caller := struct_member(s) // pass struct as arg => propagate to callee's copy of member
	fmt.Printf("%v\n", s_caller)
	multiline_lit := Name{ // assign to struct (via multiline literal) => propagate to struct's copy of member
		Data: arr,
		fake: 2,
	}
	fmt.Printf("%v\n", multiline_lit)
	// assign to nested struct (via literal) => propagate to inner struct's copy of member
	nested := Nested{
		name: multiline_lit,
	}
	fmt.Printf("%v\n", nested)
	// assign to nested struct (via copy) => propagate to inner struct's copy of member
	nested2 := nested
	nested2.f()
}
