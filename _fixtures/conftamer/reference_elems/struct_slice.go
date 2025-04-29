package main

import (
	_ "syscall"
)

type Aah struct {
	NonReference int
	Reference    []int // slice, not arr
}

func main() {
	struct_slice := Aah{1, []int{1, 2}}
	_ = struct_slice
}
