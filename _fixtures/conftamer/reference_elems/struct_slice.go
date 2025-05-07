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
	slice_struct_slice := []Aah{struct_slice}
	_ = slice_struct_slice
}
