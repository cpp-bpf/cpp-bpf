# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#
# Rules for building C++ BPF programs and their userspace loaders with
# cppbpf. Include it from a Makefile that sets OUT, after its first target
# (the default goal), and optionally:
#
#   CLANG          clang with llvm/llvm-project#233715 (C++ records in BTF)
#   BPFTOOL        bpftool, for skeletons
#   LIBBPF_INC     directory with bpf/bpf_helpers.h and bpf/bpf_helper_defs.h
#   UAPI_INC       directory with linux/bpf.h, if not the system one
#   VMLINUX_BTF    kernel BTF for vmlinux.h (default: /sys/kernel/btf/vmlinux),
#                  or empty for none
#   PYTHON         python3, for vmlinux.h
#   BPF_SRC_DIR    directory of the *.bpf.cpp sources (default: .)
#   USER_CFLAGS    flags for the userspace part, e.g. -isystem for libbpf
#   USER_LDLIBS    libraries for the userspace part (default: -lbpf)
#
# It provides:
#   $(OUT)/%.bpf.o   from $(BPF_SRC_DIR)/%.bpf.cpp
#   $(OUT)/%.skel.h  from $(OUT)/%.bpf.o
#   $(OUT)/include/vmlinux.h, the kernel types as C++, from VMLINUX_BTF
#   BPF_CXXFLAGS and USER_CXXFLAGS, which write dependency files to $(OUT);
#   CPPBPF_FLAGS_STAMP, which changes when the build flags change.

CPPBPF_DIR := $(abspath $(dir $(lastword $(MAKEFILE_LIST)))/..)

CLANG ?= clang
BPFTOOL ?= bpftool
CXX ?= c++
LIBBPF_INC ?= /usr/include
UAPI_INC ?=
BPF_SRC_DIR ?= .
VMLINUX_BTF ?= /sys/kernel/btf/vmlinux
PYTHON ?= python3
USER_CFLAGS ?=
USER_LDLIBS ?= -lbpf

ifeq ($(wildcard $(LIBBPF_INC)/bpf/bpf_helpers.h),)
$(error LIBBPF_INC=$(LIBBPF_INC) has no bpf/bpf_helpers.h; set it to the directory with the libbpf headers)
endif

# The __TARGET_ARCH_ name used by bpf_tracing.h, from the host architecture.
BPF_ARCH := $(shell uname -m | sed -e 's/x86_64/x86/' -e 's/aarch64/arm64/' \
	-e 's/^arm.*/arm/' -e 's/s390x/s390/' -e 's/ppc64.*/powerpc/' \
	-e 's/riscv64/riscv/' -e 's/loongarch64/loongarch/')
# Directory with asm/types.h for <linux/types.h>, e.g. on Debian and Ubuntu.
MULTIARCH_INC := $(shell m=$$(gcc -print-multiarch 2>/dev/null); \
	[ -n "$$m" ] && [ -d "/usr/include/$$m" ] && echo "/usr/include/$$m")

# -gsimple-template-names keeps template arguments out of BTF type names,
# which the kernel rejects.
BPF_CXXFLAGS := -g -gsimple-template-names -O2 --target=bpf -std=gnu++20 \
	-fno-exceptions -fno-asynchronous-unwind-tables \
	-D__TARGET_ARCH_$(BPF_ARCH) -I$(OUT)/include -I$(LIBBPF_INC) \
	-I$(CPPBPF_DIR)/include $(if $(UAPI_INC),-I$(UAPI_INC)) \
	$(if $(MULTIARCH_INC),-I$(MULTIARCH_INC)) \
	-Wall -Werror -Wno-ignored-attributes -MMD -MP $(EXTRA_BPF_CXXFLAGS)

USER_CXXFLAGS := -std=c++20 -O2 -Wall -Wextra -Werror -I$(OUT) \
	-I$(CPPBPF_DIR)/include $(USER_CFLAGS) -MMD -MP

# Rebuild everything when the toolchain, headers or flags change.
CPPBPF_FLAGS_STAMP := $(OUT)/flags
CPPBPF_FLAGS := $(CLANG) $(BPFTOOL) $(CXX) $(LIBBPF_INC) $(VMLINUX_BTF) \
	$(BPF_CXXFLAGS) $(USER_CXXFLAGS) $(USER_LDLIBS)

$(CPPBPF_FLAGS_STAMP): FORCE
	@mkdir -p $(OUT)
	@echo '$(CPPBPF_FLAGS)' | cmp -s - $@ || echo '$(CPPBPF_FLAGS)' > $@

# Until bpf_helper_defs.h compiles as C++ upstream (cpp-bpf#4), use a
# fixed copy of the libbpf BPF-side headers.
HELPER_HEADERS := bpf_helpers.h bpf_helper_defs.h bpf_core_read.h bpf_tracing.h
HELPERS_STAMP := $(OUT)/include/bpf/.stamp

$(HELPERS_STAMP): $(CPPBPF_FLAGS_STAMP) $(CPPBPF_DIR)/mk/cppbpf.mk \
		$(addprefix $(LIBBPF_INC)/bpf/,$(HELPER_HEADERS))
	mkdir -p $(OUT)/include/bpf
	cp $(addprefix $(LIBBPF_INC)/bpf/,$(HELPER_HEADERS)) $(OUT)/include/bpf/
	sed -i -E 's/\(\* const ([a-z0-9_]+)\)(.*) = \(void \*\) ([0-9]+);/(* const \1)\2 = (__typeof__(\1)) \3;/' \
		$(OUT)/include/bpf/bpf_helper_defs.h
	! grep -q '= (void \*) [0-9]*;' $(OUT)/include/bpf/bpf_helper_defs.h
	touch $@

# Programs can include it as "vmlinux.h"; see scripts/gen-vmlinux.py.
# Set VMLINUX_BTF empty to build without it.
ifneq ($(VMLINUX_BTF),)
ifeq ($(wildcard $(VMLINUX_BTF)),)
$(error VMLINUX_BTF=$(VMLINUX_BTF) doesn't exist; set it to the kernel BTF for vmlinux.h, or empty to build without vmlinux.h)
endif
VMLINUX_H := $(OUT)/include/vmlinux.h
endif

$(OUT)/include/vmlinux.h: $(VMLINUX_BTF) $(CPPBPF_DIR)/scripts/gen-vmlinux.py \
		$(CPPBPF_FLAGS_STAMP)
	mkdir -p $(OUT)/include
	$(PYTHON) $(CPPBPF_DIR)/scripts/gen-vmlinux.py --bpftool $(BPFTOOL) \
		$(VMLINUX_BTF) > $@.tmp
	mv $@.tmp $@

$(OUT)/%.bpf.o: $(BPF_SRC_DIR)/%.bpf.cpp $(HELPERS_STAMP) $(VMLINUX_H)
	$(CLANG) $(BPF_CXXFLAGS) -c $< -o $@

$(OUT)/%.skel.h: $(OUT)/%.bpf.o
	$(BPFTOOL) gen skeleton $< name $(notdir $*) > $@

-include $(wildcard $(OUT)/*.d)

.PHONY: FORCE
.SECONDARY:
