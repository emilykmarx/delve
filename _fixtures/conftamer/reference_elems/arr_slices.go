package main

import (
	_ "syscall"
)

func main() {
	slice1 := []string{"hi", "hello"}
	slice2 := []string{"aah", "aaah"}
	arr_slices := [2][]string{slice1, slice2}
	_ = arr_slices
}
