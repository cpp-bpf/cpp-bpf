// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "types.h"
#include <cppbpf/bpf.hpp>
#include <bpf/bpf_core_read.h>
#include "basic.h"

CPPBPF_LICENSE("GPL");

struct stats {
	__u64 switches;
	struct bpf_spin_lock lock;
};

cppbpf::hash_map<__u32, stats, 1024> per_pid SEC(".maps");
cppbpf::ringbuf<64 * 1024> events SEC(".maps");

const volatile __u32 target_tgid = 0;

CPPBPF_PROG("tp_btf/sched_switch", on_switch, bool preempt,
	    struct task_struct *prev, struct task_struct *next)
{
	__u32 tgid = BPF_CORE_READ(next, tgid);
	if (tgid != target_tgid)
		return 0;

	stats *s = per_pid.lookup_or_init(tgid).get();
	if (!s)
		return 0;
	{
		cppbpf::spin_guard guard(s->lock);
		s->switches++;
	}

	auto e = events.reserve<event>();
	event *ev = e.get();
	if (!ev)
		return 0;
	ev->tgid = tgid;
	ev->pid = BPF_CORE_READ(next, pid);
	if (ev->pid == ev->tgid)
		return 0; /* discarded by the destructor */
	e.submit();
	return 0;
}
