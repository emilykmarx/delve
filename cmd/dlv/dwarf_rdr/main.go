package main

import (
	"debug/elf"
	"fmt"
	"log"
)

func main() {
	elfFile, err := elf.Open("./fail_fake_xv")
	if err != nil {
		log.Fatal(err)
	}

	dwarfData, err := elfFile.DWARF()
	if err != nil {
		log.Fatal(err)
	}

	entryReader := dwarfData.Reader()

	e, err := entryReader.SeekPC(0x4655c0)
	if err != nil {
		log.Panicf("SeekPC: %v\n", err.Error())
	} else {
		fmt.Printf("First entry: %+v\n", e)
	}

	//	entryReader.Seek(0xdbc)

	for i := 0; i < 10000; i++ {
		entry, err := entryReader.Next()
		if err != nil {
			//log.Panicf("next: %v\n", err.Error())
			fmt.Printf("next at %v: %v\n", i, err.Error())
		} else {
			fmt.Printf("entry: %+v\n", *entry)
		}
	}
}
