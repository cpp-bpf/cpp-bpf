#!/bin/bash
# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#
# Check that the libbpf headers patched for C++ don't change C programs:
# build every *.bpf.c of a corpus with the original headers and with the
# patched ones, and compare the objects byte for byte.
#
#   c-compat.sh CLANG BPFTOOL LIBBPF_INC PATCHED_INC CORPUS OUT ARCH [EXTRA_INC]

set -u
clang=$1 bpftool=$2 libbpf_inc=$(realpath "$3") patched_inc=$(realpath "$4")
corpus=$5 out=$6 arch=$7 extra=${8:-}
mkdir -p "$out/orig" "$out/patched"

# Both header directories are recorded under the same name, so that the
# include paths in BTF and debug info don't differ.
flags=(-g -O2 -w --target=bpf "-D__TARGET_ARCH_$arch" -I"$corpus"
	-ffile-prefix-map="$patched_inc=/libbpf" -ffile-prefix-map="$libbpf_inc=/libbpf")
[ -n "$extra" ] && flags+=(-I"$extra")

here=$(dirname "$0")

# Identical code and data, and BTF with the same types: clang may emit the
# BTF types in a different order when the header text differs.
same_object() {
	cmp -s "$1" "$2" && return 0
	cmp -s <(python3 "$here/elf-sections.py" "$1") \
		<(python3 "$here/elf-sections.py" "$2") || return 1
	cmp -s <("$bpftool" btf dump file "$1" format c | sort) \
		<("$bpftool" btf dump file "$2" format c | sort)
}

same=0 skipped=0 failed=0
for src in "$corpus"/*.bpf.c; do
	name=$(basename "$src" .c)
	if ! "$clang" "${flags[@]}" -I"$libbpf_inc" -c "$src" \
			-o "$out/orig/$name.o" 2>/dev/null; then
		skipped=$((skipped + 1))
		continue
	fi
	if ! "$clang" "${flags[@]}" -I"$patched_inc" -I"$libbpf_inc" \
			-c "$src" -o "$out/patched/$name.o"; then
		echo "FAIL: $name builds with the original headers only"
		failed=$((failed + 1))
	elif ! same_object "$out/orig/$name.o" "$out/patched/$name.o"; then
		echo "FAIL: $name differs with the patched headers"
		failed=$((failed + 1))
	else
		same=$((same + 1))
	fi
done

echo "identical: $same, failed: $failed, not built: $skipped"
[ "$same" -gt 0 ] && [ "$failed" -eq 0 ]
