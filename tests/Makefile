# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#
#   make CLANG=... BPFTOOL=... LIBBPF_INC=... [UAPI_INC=...]
#
# See ../mk/cppbpf.mk for the variables.

OUT := build
TESTS := basic args

all: $(addprefix $(OUT)/,$(addsuffix _test,$(TESTS)))

BPF_SRC_DIR := progs
EXTRA_BPF_CXXFLAGS := -Iprogs
include ../mk/cppbpf.mk

$(OUT)/%_test: %_test.cpp $(OUT)/%.skel.h $(CPPBPF_FLAGS_STAMP)
	$(CXX) $(USER_CXXFLAGS) -Iprogs $< -o $@ $(USER_LDLIBS)

clean:
	rm -rf $(OUT)

.PHONY: all clean
