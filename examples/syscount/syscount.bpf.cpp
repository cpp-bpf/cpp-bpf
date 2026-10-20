// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Count system calls per process.
#include <linux/types.h>
#include <linux/bpf.h>
#include <cppbpf/bpf.hpp>
#include "syscount.h"

CPPBPF_LICENSE("GPL");

cppbpf::hash_map<__u32, proc_stats, 10240> procs SEC(".maps");

struct pt_regs;

CPPBPF_PROG("tp_btf/sys_enter", on_sys_enter, struct pt_regs *regs, long id)
{
	__u32 tgid = bpf_get_current_pid_tgid() >> 32;

	proc_stats *s = procs.lookup_or_init(tgid).get();
	if (!s)
		return 0;
	if (!s->syscalls)
		bpf_get_current_comm(s->comm, sizeof(s->comm));
	__sync_fetch_and_add(&s->syscalls, 1);
	return 0;
}
