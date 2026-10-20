# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#
# Check that the patched libbpf headers leave C BPF programs unchanged:
#
#   make CLANG=... BPFTOOL=... LIBBPF_INC=... CORPUS=path/to/libbpf-tools
#
# CORPUS is a directory of *.bpf.c files, such as bcc's libbpf-tools,
# with vmlinux.h in CORPUS/$(BPF_ARCH) or CORPUS_INC.

OUT := build

all: check

include ../mk/cppbpf.mk

CORPUS ?=
CORPUS_INC ?= $(CORPUS)/$(BPF_ARCH)

check: $(HELPERS_STAMP)
	@test -n "$(CORPUS)" || { echo "set CORPUS"; exit 1; }
	../scripts/c-compat.sh "$(CLANG)" "$(BPFTOOL)" "$(LIBBPF_INC)" "$(OUT)/include" \
		"$(CORPUS)" "$(OUT)/objs" "$(BPF_ARCH)" "$(CORPUS_INC)"

clean:
	rm -rf $(OUT)

.PHONY: all check clean
