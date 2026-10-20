# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#
# Build the tests:
#   make CLANG=/path/to/clang LIBBPF_INC=/path/to/libbpf/include
#
# CLANG must include llvm/llvm-project#233715 (C++ records in BTF).
# LIBBPF_INC is a directory with bpf/bpf_helpers.h and the generated
# bpf/bpf_helper_defs.h. Until the helper definitions compile as C++
# upstream, a fixed copy is made in the build directory.

CLANG ?= clang
BPFTOOL ?= bpftool
CXX ?= c++
LIBBPF_INC ?= /usr/include
UAPI_INC ?=
ARCH ?= $(shell uname -m | sed -e 's/x86_64/x86/' -e 's/aarch64/arm64/')
# Directory with asm/types.h for <linux/types.h>, e.g. on Debian.
MULTIARCH_INC ?= $(shell d=/usr/include/$$(gcc -print-multiarch 2>/dev/null); \
		   [ -d "$$d" ] && echo "$$d")
# Userspace libbpf: headers and libraries for the test programs. They
# should match the libbpf version of LIBBPF_INC and BPFTOOL.
USER_CFLAGS ?=
USER_LDLIBS ?= -lbpf

OUT := build
BPF_CXXFLAGS := -g -O2 --target=bpf -std=gnu++20 -fno-exceptions \
	-fno-asynchronous-unwind-tables -D__TARGET_ARCH_$(ARCH) \
	-I$(OUT)/include -I$(LIBBPF_INC) -I../include -Iprogs \
	$(if $(UAPI_INC),-I$(UAPI_INC)) $(if $(MULTIARCH_INC),-I$(MULTIARCH_INC)) \
	-Wall -Werror -Wno-ignored-attributes

TESTS := basic args

all: $(addprefix $(OUT)/,$(addsuffix _test,$(TESTS)))

# Rebuilt when LIBBPF_INC changes.
$(OUT)/libbpf-inc: FORCE
	@mkdir -p $(OUT)
	@echo '$(LIBBPF_INC)' | cmp -s - $@ || echo '$(LIBBPF_INC)' > $@

HELPER_HEADERS := bpf_helpers.h bpf_helper_defs.h bpf_core_read.h bpf_tracing.h

$(OUT)/include/bpf/.stamp: $(OUT)/libbpf-inc Makefile \
		$(addprefix $(LIBBPF_INC)/bpf/,$(HELPER_HEADERS))
	mkdir -p $(OUT)/include/bpf
	cp $(addprefix $(LIBBPF_INC)/bpf/,$(HELPER_HEADERS)) $(OUT)/include/bpf/
	sed -i -E 's/\(\* const ([a-z0-9_]+)\)(.*) = \(void \*\) ([0-9]+);/(* const \1)\2 = (__typeof__(\1)) \3;/' \
		$(OUT)/include/bpf/bpf_helper_defs.h
	! grep -q '= (void \*) [0-9]*;' $(OUT)/include/bpf/bpf_helper_defs.h
	touch $@

$(OUT)/%.bpf.o: progs/%.bpf.cpp progs/*.h ../include/cppbpf/*.hpp $(OUT)/include/bpf/.stamp
	$(CLANG) $(BPF_CXXFLAGS) -c $< -o $@

$(OUT)/%.skel.h: $(OUT)/%.bpf.o
	$(BPFTOOL) gen skeleton $< name $* > $@

$(OUT)/%_test: %_test.cpp test.h $(OUT)/%.skel.h progs/*.h
	$(CXX) -std=c++20 -O2 -Wall -I$(OUT) -Iprogs $(USER_CFLAGS) $< -o $@ $(USER_LDLIBS)

clean:
	rm -rf $(OUT)

.PHONY: all clean FORCE
.SECONDARY:
