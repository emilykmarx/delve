package main

import (
	"flag"
	"log"

	"github.com/go-delve/delve/conftamer"
)

func main() {
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds | log.Lshortfile)

	config_file := flag.String("config", "client_config.yml", "Config filename (yml)")
	flag.Parse()
	config, err := conftamer.LoadConfig(*config_file)
	if err != nil {
		log.Panicf("conftamer.LoadConfig: %v\n", err.Error())
	}

	conftamer, err := conftamer.New(config)
	if err != nil {
		log.Panicf("conftamer.New: %v\n", err.Error())
	}
	conftamer.Run()
}
