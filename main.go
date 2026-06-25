//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target amd64 trace ./bpf/trace.c -- -I./bpf

package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
)

func main() {
	// Allow the process to lock memory for eBPF maps
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// Load pre-compiled eBPF program
	objs := traceObjects{}
	if err := loadTraceObjects(&objs, nil); err != nil {
		log.Fatal(err)
	}
	defer objs.Close()

	// Attach to the openat tracepoint
	tp, err := link.Tracepoint("syscalls", "sys_enter_openat",
		objs.TraceOpenat, nil)
	if err != nil {
		log.Fatal(err)
	}
	defer tp.Close()

	// Open perf reader
	reader, err := perf.NewReader(objs.Events, 4096)
	if err != nil {
		log.Fatal(err)
	}
	defer reader.Close()

	fmt.Println("Observing file opens... Press Ctrl+C to exit.")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		for {
			record, err := reader.Read()
			if err != nil {
				continue
			}

			var event struct {
				PID       uint32
				Timestamp uint64
				Comm      [16]byte
			}
			if err := binary.Read(bytes.NewReader(record.RawSample),
				binary.LittleEndian, &event); err != nil {
				continue
			}

			fmt.Printf("PID %d (%s) opened a file\n",
				event.PID, string(event.Comm[:]))
		}
	}()

	<-sig
}
