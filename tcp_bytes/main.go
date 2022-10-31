package main

import (
	"bytes"
	"encoding/binary"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"
)

//GOPACKAGE=main bpf2go -cc clang -cflags '-O2 -g -Wall -Werror -D__TARGET_ARCH_x86' -target bpfel,bpfeb bpf pid.bpf.c -- -I /root/bpftool/src/libbpf/include -idirafter /usr/lib/llvm-15/lib/clang/15.0.2/include -idirafter /usr/local/include -idirafter /usr/include/x86_64-linux-gnu -idirafter /usr/include
//GOPACKAGE=main bpf2go -cc clang -cflags '-O2 -g -Wall -Werror -D__TARGET_ARCH_x86' -target bpfel,bpfeb bpf pid.bpf.c -- -I /root/bpftool/src/libbpf/include -idirafter /usr/lib/llvm-15/lib/clang/15.0.2/include -idirafter /usr/local/include -idirafter /usr/include/x86_64-linux-gnu -idirafter /usr/include
//go:generate bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS -target bpfel,bpfeb bpf pid.bpf.c -- -I /root/bpftool/src/libbpf/include $BPF_HEADERS

type ipv4Key struct {
	Pid uint32
}
type ipv4Val struct {
	Value uint64
	Saddr uint32
	Daddr uint32
	Lport uint32
	Dport uint32
}

func inet_ntoa(ipnr uint32) net.IP {
	var bytes [4]byte
	bytes[0] = byte(ipnr & 0xFF)
	bytes[1] = byte((ipnr >> 8) & 0xFF)
	bytes[2] = byte((ipnr >> 16) & 0xFF)
	bytes[3] = byte((ipnr >> 24) & 0xFF)

	return net.IPv4(bytes[0], bytes[1], bytes[2], bytes[3])
}
func IntToBytes(n int) []byte {
	x := int32(n)

	bytesBuffer := bytes.NewBuffer([]byte{})
	binary.Write(bytesBuffer, binary.BigEndian, x)
	return bytesBuffer.Bytes()
}

func int2ip(nn uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, nn)
	return ip
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
	key := ipv4Key{}
	var val ipv4Val
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	log.Printf("%-15s %-6s -> %-15s %-6s %-6s",
		"Src addr",
		"Port",
		"Dest addr",
		"Port",
		"RTT")
	for {
		select {
		case <-ticker.C:
			iter := objs.bpfMaps.Ipv4SendBytes.Iterate()
			for iter.Next(&key, &val) {
				log.Printf("%-15s %-6d -> %-15s %-6d %-6d",
					inet_ntoa(val.Saddr),
					val.Lport,
					inet_ntoa(val.Daddr),
					val.Dport, val.Value)
			}
			if iter.Err() != nil {
				log.Printf("err: %v\n", err)
				continue
			}

		case <-stopper:
			// Wait for a signal and close the perf reader,
			// which will interrupt rd.Read() and make the program exit.
			log.Println("Received signal, exiting program..")
			return
		}
	}
}
