CLANG ?= clang
CFLAGS ?= -O2 -g -Wall -Werror -D__TARGET_ARCH_x86


LINUX_HEADERS=-I /usr/lib/llvm-15/lib/clang/15.0.2/include -I /usr/local/include -I /usr/include/x86_64-linux-gnu -I /usr/include
#BPF_HEADERS= /root/bpftool/src/libbpf/include $(LINUX_HEADERS)

all: generate

generate: export BPF_CLANG=$(CLANG)
generate: export BPF_CFLAGS=$(CFLAGS)
generate: export BPF_HEADERS=$(LINUX_HEADERS)
generate: export GOPACKAGE=main
generate:
	go generate -x -v ./


run:
	go run -exec sudo main.go bpf_bpfel.go