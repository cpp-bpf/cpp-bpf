/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef CPPBPF_TEST_BASIC_H
#define CPPBPF_TEST_BASIC_H
struct event {
	__u32 tgid;
	__u32 pid;
};

struct core_result {
	__u32 class_exists;
	__u32 class_size;
};

/* The userspace view of the per_pid values in basic.bpf.cpp. */
struct stats_view {
	__u64 switches;
	__u32 lock;
};
#endif
