package main

import (
	"bytes"
	"encoding/binary"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"
)

type ipv4Key struct {
	pid uint32
}
type ipv4Val struct {
	Value uint64
	Saddr uint64
	Daddr uint64
	Lport uint32
	Dport uint32
}

func IntToBytes(n int) []byte {
	x := int32(n)

	bytesBuffer := bytes.NewBuffer([]byte{})
	binary.Write(bytesBuffer, binary.BigEndian, x)
	return bytesBuffer.Bytes()
}

func main() {
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// Load pre-compiled programs and maps into the kernel.
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %s", err)
	}
	defer objs.Close()

	//// init the map element
	//var key [64]byte
	//copy(key[:], []byte("execve_counter"))
	//var val int64 = 0
	//if err := objs.bpfMaps.Ipv4RecvBytes.Put(key, val); err != nil {
	//	log.Fatalf("init map key error: %s", err)
	//}

	// attach to xxx
	kp, err := link.Kprobe("tcp_sendmsg", objs.KprobeTcpSendmsg, nil)
	if err != nil {
		log.Fatalf("opening tracepoint: %s", err)
	}
	defer kp.Close()
	key := ipv4Key{
		pid: 69324,
	}
	var val ipv4Val
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			err = objs.Ipv4SendBytes.Lookup(&key, &val)
			if err != nil {
				log.Printf("execve_counter err: %v\n", err)
			}
			//for _, v := range val {
			//	log.Printf("execve_counter: %v\n", v.value)
			//
			//}

			//for objs.Ipv4SendBytes.Iterate().Next(&key, &val) {
			//	log.Printf("execve_counter: %d\n", val.value)
			//}
			//if err := objs.Ipv4SendBytes.Iterate().Err(); err != nil {
			//	panic(fmt.Sprint("Iterator encountered an error:", err))
			//}

			//if err := objs.bpfMaps.Ipv4SendBytes.(key, &val); err != nil {
			//	log.Fatalf("reading map error: %s", err)
			//}
			log.Printf("execve_counter: %d\n", val.Value)

		case <-stopper:
			// Wait for a signal and close the perf reader,
			// which will interrupt rd.Read() and make the program exit.
			log.Println("Received signal, exiting program..")
			return
		}
	}
}
