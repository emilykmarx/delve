package main

import (
	"fmt"
	"log"
	"runtime"
	"unsafe"
)

var alwaysFalse bool
var escapeSink any

func Escape[T any](x T) T {
	if alwaysFalse {
		escapeSink = x
	}
	return x
}

func assertNoError(err error, s string) {
	if err != nil {
		log.Fatalf("err %v", err)
	}
}

func assertPointerUpdated(expected unsafe.Pointer, actual unsafe.Pointer, pname string) {
	if expected != actual {
		log.Fatalf("Pointer %v not updated; should be %p, is %p", pname, expected, actual)
	}
}

func main() {
	x := Escape(new(byte))
	*x = 0xa
	p := (uintptr)(unsafe.Pointer(x))

	fmt.Printf("&x: %p\n", &x) // same behavior if hv this or not
	new, err := runtime.MoveObject(p, 1)
	//fmt.Printf("&x: %p\n", &x)
	assertNoError(err, "moveobject")

	// XXX things to check:
	// New location is different span, with expected spanclass
	// Data was copied
	// Old location was freed
	// Pointer was updated

	// If hv this assert, x is updated per logging - else not
	//assertPointerUpdated(unsafe.Pointer(new), unsafe.Pointer(x), "x")
	//assertPointerUpdated(unsafe.Pointer(new), unsafe.Pointer(y), "y")
	assertPointerUpdated(unsafe.Pointer(new), unsafe.Pointer(p), "p")
	// Q3: x is updated, but not p - are unsafe ptrs not roots??

}
