/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef CPPBPF_TEST_BASIC_H
#define CPPBPF_TEST_BASIC_H
struct event {
	__u32 tgid;
	__u32 pid;
};
#endif
