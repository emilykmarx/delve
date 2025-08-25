package main

import (
	"fmt"
)

type Name struct {
	buf []byte
}

func (recvr_callee *Name) tainted_ret() []byte {
	fmt.Printf("using recvr %v\n", recvr_callee)
	return recvr_callee.buf
}

func main() {
	// recvr.buf[2:] is tainted, ptr_recvr returns pointer to recvr.buf => propagate to the portion of the lhs whose content matches the watch region
	recvr := Name{
		buf: []byte{0, 2, 254, 255},
	}

	buf := append([]byte(nil), recvr.tainted_ret()...)
	_ = buf
}
