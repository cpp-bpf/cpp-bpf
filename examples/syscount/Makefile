# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#
#   make CLANG=... BPFTOOL=... LIBBPF_INC=... [UAPI_INC=...]
#   sudo build/syscount 5
#
# See ../../mk/cppbpf.mk for the variables.

OUT := build

all: $(OUT)/syscount

include ../../mk/cppbpf.mk

$(OUT)/syscount: syscount.cpp $(OUT)/syscount.skel.h $(CPPBPF_FLAGS_STAMP)
	$(CXX) $(USER_CXXFLAGS) $< -o $@ $(USER_LDLIBS)

clean:
	rm -rf $(OUT)

.PHONY: all clean
