/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef CPPBPF_COMMON_HPP
#define CPPBPF_COMMON_HPP

#ifndef __cplusplus
#error "cppbpf headers are for C++ BPF programs"
#endif

/*
 * Like the libbpf headers, cppbpf needs the kernel types first: include
 * vmlinux.h or <linux/bpf.h> before any cppbpf header.
 */
#include <bpf/bpf_helpers.h>

/* Program license, e.g. CPPBPF_LICENSE("GPL"). */
#define CPPBPF_LICENSE(lic) \
	extern "C" char LICENSE[] SEC("license") = lic

#define CPPBPF_INLINE inline __attribute__((always_inline))

#endif /* CPPBPF_COMMON_HPP */
