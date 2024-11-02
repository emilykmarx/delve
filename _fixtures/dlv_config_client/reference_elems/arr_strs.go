package main

import (
	_ "syscall"
)

func main() {
	arr_strs := [2]string{"hi", "hello"} // array, not slice - initially tainted
	_ = arr_strs
}
