/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Types shared by the BPF program and the userspace loader. */
#ifndef SYSCOUNT_H
#define SYSCOUNT_H

struct proc_stats {
	__u64 syscalls;
	char comm[16];
};

#endif
