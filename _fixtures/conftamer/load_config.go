package main

import (
	"fmt"
	"log"
	_ "net/http/pprof"
	"os"
	"strings"
)

func main() {
	config_file := "config_file.txt"
	/*
		f, err := os.Open(config_file)
		if err != nil {
			log.Panicf("open: %v", err)
		}
		fmt.Printf("fd: %v\n", f.Fd())
		time.Sleep(1 * time.Hour)
	*/
	bytes, err := os.ReadFile(config_file)
	if err != nil {
		log.Panicf("ReadFile: %v", err)
	}
	lines := strings.Split(string(bytes), "\n")
	fmt.Printf("lines: %v\n", lines)
}

/*

0  0x00000000004c248f in syscall.read
   at /home/emily/projects/wtf_project/go1.20.1/src/syscall/zsyscall_linux_amd64.go:704
1  0x00000000004c0c0c in syscall.Read
   at /home/emily/projects/wtf_project/go1.20.1/src/syscall/syscall_unix.go:178
2  0x00000000004e1358 in internal/poll.ignoringEINTRIO
   at /home/emily/projects/wtf_project/go1.20.1/src/internal/poll/fd_unix.go:794
3  0x00000000004e00b0 in internal/poll.(*FD).Read
   at /home/emily/projects/wtf_project/go1.20.1/src/internal/poll/fd_unix.go:163
4  0x00000000004e5f7e in os.(*File).read
   at /home/emily/projects/wtf_project/go1.20.1/src/os/file_posix.go:31
5  0x00000000004e423d in os.(*File).Read
   at /home/emily/projects/wtf_project/go1.20.1/src/os/file.go:118
6  0x00000000004e5c26 in os.ReadFile
   at /home/emily/projects/wtf_project/go1.20.1/src/os/file.go:704

*/
