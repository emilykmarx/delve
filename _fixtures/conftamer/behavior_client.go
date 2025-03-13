package main

import (
	"fmt"
	"log"
	"net"
	_ "net/http/pprof"

	"time"
)

func main() {
	server_endpoint := "localhost:6060"

	// wait for server to start (so Dial will succeed)
	time.Sleep(100 * time.Millisecond)
	client_endpoint, err := net.ResolveTCPAddr("tcp", "localhost:5050")
	if err != nil {
		log.Panicf("Client resolve client endpoint: %v", err.Error())
	}

	nd := net.Dialer{
		Timeout:   1 * time.Second,
		LocalAddr: client_endpoint,
	}
	conn, err := nd.Dial("tcp", server_endpoint)
	if err != nil {
		log.Panicf("Client dial: %v", err)
	}

	config := []byte("config") // config[1] initially tainted
	// behavior map should record message offset 1 is tainted by config[1]
	// (when dial tcp, msgs are raw tcp not http)
	_, err = conn.Write(config)
	if err != nil {
		log.Panicf("Client write: %v", err)
	}

	fmt.Println("behavior client exit")
}
