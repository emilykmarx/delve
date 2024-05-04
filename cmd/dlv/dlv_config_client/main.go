package main

import (
	"fmt"

	"github.com/go-delve/delve/service/rpc2"
)

func main() {
	fmt.Println("Hello from dlv client")
	listenAddr := "localhost:4040"
	client := rpc2.NewClient(listenAddr)
	client.Detach(false)
}
