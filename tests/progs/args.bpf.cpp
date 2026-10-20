// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// The kernel calls bpf_fentry_test*() with known arguments from
// BPF_PROG_TEST_RUN of a tracing program (net/bpf/test_run.c).
#include "types.h"
#include <cppbpf/bpf.hpp>
#include "args.h"

CPPBPF_LICENSE("GPL");

struct args_result res;

/* bpf_fentry_test3(4, 5, 6) */
CPPBPF_PROG("fentry/bpf_fentry_test3", on_test3, char a, int b, __u64 c)
{
	res.t3[0] = a;
	res.t3[1] = b;
	res.t3[2] = c;
	res.t3_calls++;
	return 0;
}

/* bpf_fentry_test6(16, (void *)17, 18, 19, (void *)20, 21) */
CPPBPF_PROG("fentry/bpf_fentry_test6", on_test6, __u64 a, void *b, short c,
	    int d, void *e, __u64 f)
{
	res.t6[0] = a;
	res.t6[1] = (unsigned long)b;
	res.t6[2] = c;
	res.t6[3] = d;
	res.t6[4] = (unsigned long)e;
	res.t6[5] = f;
	res.t6_calls++;
	return 0;
}

/* bpf_fentry_test2(2, 3) returns 5; fexit gets the return value last. */
CPPBPF_PROG("fexit/bpf_fentry_test2", on_test2_exit, int a, __u64 b, int ret)
{
	res.t2[0] = a;
	res.t2[1] = b;
	res.t2[2] = ret;
	res.t2_calls++;
	return 0;
}
