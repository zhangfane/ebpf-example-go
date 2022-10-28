// Code generated by bpf2go; DO NOT EDIT.
//go:build arm64be || armbe || mips || mips64 || mips64p32 || ppc64 || s390 || s390x || sparc || sparc64
// +build arm64be armbe mips mips64 mips64p32 ppc64 s390 s390x sparc sparc64

package main

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

type bpfIpv4KeyT struct{ Pid int32 }

type bpfIpv4ValueT struct {
	Value uint64
	Saddr uint64
	Daddr uint64
	Lport uint32
	Dport uint32
}

// loadBpf returns the embedded CollectionSpec for bpf.
func loadBpf() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_BpfBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load bpf: %w", err)
	}

	return spec, err
}

// loadBpfObjects loads bpf and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*bpfObjects
//	*bpfPrograms
//	*bpfMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadBpfObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadBpf()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// bpfSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type bpfSpecs struct {
	bpfProgramSpecs
	bpfMapSpecs
}

// bpfSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type bpfProgramSpecs struct {
	KprobeTcpCleanupRbuf *ebpf.ProgramSpec `ebpf:"kprobe__tcp_cleanup_rbuf"`
	KprobeTcpSendmsg     *ebpf.ProgramSpec `ebpf:"kprobe__tcp_sendmsg"`
}

// bpfMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type bpfMapSpecs struct {
	Ipv4RecvBytes *ebpf.MapSpec `ebpf:"ipv4_recv_bytes"`
	Ipv4SendBytes *ebpf.MapSpec `ebpf:"ipv4_send_bytes"`
}

// bpfObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadBpfObjects or ebpf.CollectionSpec.LoadAndAssign.
type bpfObjects struct {
	bpfPrograms
	bpfMaps
}

func (o *bpfObjects) Close() error {
	return _BpfClose(
		&o.bpfPrograms,
		&o.bpfMaps,
	)
}

// bpfMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadBpfObjects or ebpf.CollectionSpec.LoadAndAssign.
type bpfMaps struct {
	Ipv4RecvBytes *ebpf.Map `ebpf:"ipv4_recv_bytes"`
	Ipv4SendBytes *ebpf.Map `ebpf:"ipv4_send_bytes"`
}

func (m *bpfMaps) Close() error {
	return _BpfClose(
		m.Ipv4RecvBytes,
		m.Ipv4SendBytes,
	)
}

// bpfPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadBpfObjects or ebpf.CollectionSpec.LoadAndAssign.
type bpfPrograms struct {
	KprobeTcpCleanupRbuf *ebpf.Program `ebpf:"kprobe__tcp_cleanup_rbuf"`
	KprobeTcpSendmsg     *ebpf.Program `ebpf:"kprobe__tcp_sendmsg"`
}

func (p *bpfPrograms) Close() error {
	return _BpfClose(
		p.KprobeTcpCleanupRbuf,
		p.KprobeTcpSendmsg,
	)
}

func _BpfClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed bpf_bpfeb.o
var _BpfBytes []byte
