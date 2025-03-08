package main

import (
	"fmt"
	"log"
	"net"
	_ "net/http/pprof"

	"time"
)

// Avoid using HTTP server here, since receive path there is likely more complex
func main() {
	server_endpoint := "localhost:6060"

	l, err := net.Listen("tcp", server_endpoint)
	if err != nil {
		log.Panicf("Listen: %v\n", err.Error())
	}
	conn, err := l.Accept()
	if err != nil {
		log.Panicf("Accept: %v\n", err.Error())
	}

	var recvd_msg [3]byte            // untainted (and nothing else is tainted, so won't fault)
	time.Sleep(1 * time.Second)      // wait for client to write
	_, err = conn.Read(recvd_msg[:]) // recvd_msg passed to `read` syscall => return to client, set wp on it
	if err != nil {
		log.Panicf("Read: %v\n", err.Error())
	}

	msg_copy := recvd_msg[1] // wp hits for recvd_msg => propagate to msg_copy (on stack), m-c map should hv {&msg_copy} => 0x1
	fmt.Printf("msg_copy: %v\n", string(msg_copy))

	fmt.Println("behavior server exit")
}
