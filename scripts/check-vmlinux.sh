#!/bin/bash
# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#
# Check that vmlinux.h from gen-vmlinux.py compiles as C and C++, and that
# C++ sees the same type layout as C: the static_asserts on sizes and
# offsets from BTF that fail in C++ must be the ones that fail in C, which
# are bpftool's own mistakes.
#
#   check-vmlinux.sh CLANG BPFTOOL OUT [BTF]

set -eu
clang=$1 bpftool=$2 out=$3 btf=${4:-/sys/kernel/btf/vmlinux}
gen=$(dirname "$0")/gen-vmlinux.py
mkdir -p "$out"

python3 "$gen" --bpftool "$bpftool" "$btf" > "$out/vmlinux.h"
python3 "$gen" --bpftool "$bpftool" --layout-asserts "$btf" > "$out/layout.c"

flags=(--target=bpf -fsyntax-only -ferror-limit=0 -I"$out")
"$clang" "${flags[@]}" -x c -std=gnu11 "$out/vmlinux.h"
"$clang" "${flags[@]}" -x c++ -std=gnu++20 -Wall -Wextra \
	-Werror -Wno-ignored-attributes "$out/vmlinux.h"

# Lines of layout.c with errors, which are failed asserts unless the
# header is broken; C++ must have the same ones as C.
failures() {
	"$clang" "${flags[@]}" -Wno-invalid-offsetof "$@" "$out/layout.c" 2>&1 |
		sed -n 's/^\(.*:[0-9]*\):[0-9]*: error: .*/\1/p' | sort -u
}
failures -x c -std=c23 > "$out/layout-c.txt"
failures -x c++ -std=gnu++20 -Wno-ignored-attributes > "$out/layout-cxx.txt"
echo "$(grep -c static_assert "$out/layout.c") layout checks," \
	"$(wc -l < "$out/layout-c.txt") fail in C too"
diff -u "$out/layout-c.txt" "$out/layout-cxx.txt"
