package main

import (
	"log"
	"runtime"
	"unsafe"
)

func Escape[T any](x T) T {
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
	y := x
	p := (uintptr)(unsafe.Pointer(x))

	//fmt.Printf("&x: %p\n", &x)
	new, err := runtime.MoveObject(p, 1)
	//fmt.Printf("&x: %p\n", &x)
	assertNoError(err, "moveobject")

	// XXX things to check:
	// New location is different span, with expected spanclass
	// Data was copied
	// Old location was freed
	// Pointer was updated
	// LEFT OFF y is correct but only 1 update logged. Trying to find out if problem is p being unsafe...
	assertPointerUpdated(unsafe.Pointer(new), unsafe.Pointer(x), "x")
	assertPointerUpdated(unsafe.Pointer(new), unsafe.Pointer(y), "y")
	assertPointerUpdated(unsafe.Pointer(new), unsafe.Pointer(p), "p")
	// Q3: x is updated, but not p - are unsafe ptrs not roots??

}
