package main

import (
	"encoding/json"
	"fmt"
	"log"
	"reflect"
	_ "syscall"
)

func main() {
	var unmarshaled any

	// caddy's "hello world" config, as passed into json.Unmarshal (note modifies it slightly from the raw caddy.json)
	body := []byte{123, 34, 97, 112, 112, 115, 34, 58, 32, 123, 32, 32, 32, 32, 34, 104, 116, 116, 112, 34, 58, 32, 123, 9, 34, 115, 101, 114, 118, 101, 114, 115, 34, 58, 32, 123, 9, 32, 32, 32, 32, 34, 104, 101, 108, 108, 111, 34, 58, 32, 123, 9, 9, 34, 108, 105, 115, 116, 101, 110, 34, 58, 32, 91,
		34, 58, 50, 48, 49, 53, 34, 93, 44, 9, 9, 34, 114, 111, 117, 116, 101, 115, 34, 58, 32, 91, 9, 9, 32, 32, 32, 32, 123, 9, 9, 9, 34, 104, 97, 110, 100, 108, 101, 34, 58, 32, 91, 123, 9, 9, 9, 32, 32, 32, 32, 34, 104, 97, 110, 100, 108, 101, 114, 34, 58, 32, 34, 115,
		116, 97, 116, 105, 99, 95, 114, 101, 115, 112, 111, 110, 115, 101, 34, 44, 9, 9, 9, 32, 32, 32, 32, 34, 98, 111, 100, 121, 34, 58, 32, 34, 72, 101, 108, 108, 111, 44, 32, 119, 111, 114, 108, 100, 33, 34, 9, 9, 9, 125, 93, 9, 9, 32, 32, 32, 32, 125, 9, 9, 93, 9, 32, 32,
		32, 32, 125, 9, 125, 32, 32, 32, 32, 125, 125, 125}

	err := json.Unmarshal(body, &unmarshaled)
	if err != nil {
		log.Panicf("decoding request body: %v", err)
	}
	fmt.Printf("type of unmarshaled: %v\n", reflect.TypeOf(unmarshaled))
	fmt.Printf("unmarshaled: %+v\n", unmarshaled)
}

/*
Expected output:
map[
  apps:map[
    http:map[
      servers:map[
        hello:map[
          listen:
          [
            :2015
          ]
          routes:
          [
            map[
            handle:
            [
              map[
              body:Hello, world!
              handler:static_response]
            ]
          ]
        ]]]]]]


// Vals (3)
apps[http][servers][hello][listen][0]: ":2015" (len 5)
apps[http][servers][hello][routes][0][handle][0][body]: "Hello, world!" (len 0xd)
apps[http][servers][hello][routes][0][handle][0][handler]: "static_response" (len 0xf)

// Keys (9)
apps
http
servers
hello
listen
routes
handle
body
handler
*/
