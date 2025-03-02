package main

import (
	"fmt"
)

type Name struct {
	Data [2]int
	fake int
}

type Nested struct {
	name Name
}

// (CallAssign1 also has a methods-related test: tainting non-receiver args to ptr/non-ptr method)
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

func main() {
	arr := [2]int{0, 1}
	multiline_lit := Name{
		Data: arr,
		fake: 2,
	}
	nested := Nested{ // nested.name.Data initially tainted
		name: multiline_lit,
	}
	nested.f()
}
