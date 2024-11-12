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
}
