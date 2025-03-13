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
		log.Panicf("Server listen: %v\n", err.Error())
	}
	conn, err := l.Accept()
	if err != nil {
		log.Panicf("Server accept: %v\n", err.Error())
	}

	var msg_A [7]byte                  // untainted (and nothing else is tainted, so won't fault)
	time.Sleep(100 * time.Millisecond) // wait for client to write (else will EAGAIN and do 2 read syscalls, which is fine but makes logs messier)
	_, err = conn.Read(msg_A[:])       // msg_A passed to `read` syscall => return to client, set wp on it
	if err != nil {
		log.Panicf("Server read: %v\n", err.Error())
	}

	// wp hits, m-c map should hv &msg_B[1] => msg_A[0], &msg_B[2] => msg_A[1]
	// behavior map should hv msg_B[0x1] => msg_A[0x0], msg_B[0x2] => msg_A[0x1]
	// sender didn't taint msg_A[0], but we'll only find out when we assemble the graph
	// graph should only have msg_B[0x2] => msg_A[0x1]
	var msg_B [3]byte
	msg_B[0] = 'a'
	msg_B[1] = msg_A[0]
	msg_B[2] = msg_A[1]
	_, err = conn.Write(msg_B[:])
	if err != nil {
		log.Panicf("Server write: %v", err)
	}

	fmt.Println("behavior server exit")
}
