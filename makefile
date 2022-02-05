LOCAL_KERNEL = "/home/tomato/Documents/linux-5.11"

.PHONY: build
build: collect
	/usr/local/go/bin/go generate ./daemon/bpf/go/bpf.go
	/usr/local/go/bin/go build -o watch-dog daemon/main.go
.PHONY: collect
collect:
	clang -nostdinc -isystem \
	/usr/lib/gcc/x86_64-linux-gnu/10/include \
	-I$(LOCAL_KERNEL)/arch/x86/include \
	-I$(LOCAL_KERNEL)/arch/x86/include/generated \
	-I$(LOCAL_KERNEL)/include \
	-I$(LOCAL_KERNEL)/arch/x86/include/uapi \
	-I$(LOCAL_KERNEL)/arch/x86/include/generated/uapi \
	-I$(LOCAL_KERNEL)/include/uapi \
	-I./include/generated/uapi \
	-include $(LOCAL_KERNEL)/include/linux/kconfig.h \
	-fno-stack-protector \
	-g -O2 \
	-I$(LOCAL_KERNEL)/samples/bpf \
	-I$(LOCAL_KERNEL)/tools/testing/selftests/bpf/ \
	-I$(LOCAL_KERNEL)/tools/lib/ \
	-D__KERNEL__ -D__BPF_TRACING__ \
	-Wno-unused-value -Wno-pointer-sign \
	-D__TARGET_ARCH_x86 \
	-Wno-compare-distinct-pointer-types \
	-Wno-gnu-variable-sized-type-not-at-end \
	-Wno-address-of-packed-member \
	-Wno-tautological-compare \
	-Wno-unknown-warning-option \
	-I$(LOCAL_KERNEL)/samples/bpf/ \
	-include asm_goto_workaround.h \
	-O2 -emit-llvm -Xclang -disable-llvm-passes \
	-c ./daemon/bpf/c/collect/collect.c -o - | \
	opt -O2 -mtriple=bpf-pc-linux | \
	llvm-dis | \
	llc -march=bpf  -filetype=obj -o ./daemon/bpf/go/collect_bpfel.o