/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Minimal kernel types until vmlinux.h is usable from C++ (cpp-bpf#2). */
#ifndef CPPBPF_TEST_TYPES_H
#define CPPBPF_TEST_TYPES_H
#include <linux/types.h>
#include <linux/bpf.h>

struct task_struct {
	int pid;
	int tgid;
};
#endif
