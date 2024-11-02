package main

import (
	_ "syscall"
)

func main() {
	slice1 := []string{"hi", "hello"}
	slice2 := []string{"aah", "aaah"}
	slice_slices := [][]string{slice1, slice2}
	_ = slice_slices
}
