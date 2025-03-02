package main

import (
	"fmt"
	"log"
	"net"
	_ "net/http/pprof"

	"time"
)

func server(endpoint string) {
	l, err := net.Listen("tcp", endpoint)
	if err != nil {
		log.Panicf("Listen: %v\n", err.Error())
	}
	conn, err := l.Accept()
	if err != nil {
		log.Panicf("Accept: %v\n", err.Error())
	}

	var recvd_msg [3]byte            // untainted (and nothing else is tainted, so won't fault)
	_, err = conn.Read(recvd_msg[:]) // recvd_msg passed to `read` syscall => return to client, set wp on it
	if err != nil {
		log.Panicf("Read: %v\n", err.Error())
	}

	msg_copy := recvd_msg[1] // wp hits for recvd_msg => propagate to msg_copy (on stack), m-c map should hv {&msg_copy} => 0x1
	fmt.Printf("msg_copy: %v\n", string(msg_copy))
}

// On network receive, watch whole recv buf.
// Avoid using HTTP server here, since receive path there is likely more complex
func main() {
	endpoint := "localhost:6060"
	go server(endpoint)

	// wait for listener to start (so Dial will succeed)
	time.Sleep(1 * time.Second)

	nd := net.Dialer{
		//Timeout: 5 * time.Second, # makes manual debugging annoying, but likely want for automated test
	}
	conn, err := nd.Dial("tcp", endpoint)
	if err != nil {
		log.Panicf("Dial: %v", err)
	}
	_, err = conn.Write([]byte("hi")) // taint doesn't matter for recv
	if err != nil {
		log.Panicf("Write: %v", err)
	}
	time.Sleep(1 * time.Second) // wait for server to read
	fmt.Println("target exit")
}
