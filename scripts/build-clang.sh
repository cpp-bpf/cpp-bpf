#!/bin/bash
# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#
# Build clang with C++ records in BTF (llvm/llvm-project#233715), until the
# fix is in an LLVM release. CI builds its clang with this script too.
#
#   build-clang.sh PREFIX [WORKDIR]
#
# Installs clang, its resource headers and clang-format into PREFIX, using
# WORKDIR (default: ./llvm-build) for the sources and the build. Needs git,
# cmake, ninja and a C++ compiler, and a few GB of disk space. Only the BPF
# target is built, which takes 20-40 minutes on a recent machine.

set -eu

# The fork keeps this commit reachable on the branch bpf-btf-cxx-records.
LLVM_REPO=https://github.com/maxskokov/llvm-project
LLVM_SHA=5b41c481dec56b73f856713824f0a2de6836e0ed

if [ $# -lt 1 ] || [ $# -gt 2 ]; then
	echo "usage: $0 PREFIX [WORKDIR]" >&2
	exit 1
fi
prefix=$(realpath -m "$1")
work=$(realpath -m "${2:-llvm-build}")

if [ ! -d "$work/src/.git" ]; then
	git init -q "$work/src"
fi
git -C "$work/src" fetch -q --depth 1 "$LLVM_REPO" "$LLVM_SHA"
git -C "$work/src" checkout -q FETCH_HEAD

cmake -S "$work/src/llvm" -B "$work/build" -G Ninja \
	-DCMAKE_BUILD_TYPE=Release \
	-DLLVM_ENABLE_PROJECTS=clang \
	-DLLVM_TARGETS_TO_BUILD=BPF \
	-DLLVM_ENABLE_ASSERTIONS=ON \
	-DLLVM_INCLUDE_TESTS=OFF \
	-DLLVM_INCLUDE_BENCHMARKS=OFF \
	-DLLVM_INCLUDE_EXAMPLES=OFF \
	-DCLANG_ENABLE_ARCMT=OFF \
	-DCLANG_ENABLE_STATIC_ANALYZER=OFF \
	-DCMAKE_INSTALL_PREFIX="$prefix"
ninja -C "$work/build" install-clang install-clang-resource-headers \
	install-clang-format

echo "clang installed: $prefix/bin/clang"
