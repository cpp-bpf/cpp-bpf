/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef CPPBPF_TEST_ARGS_H
#define CPPBPF_TEST_ARGS_H
struct args_result {
	__u64 t2[3], t3[3], t6[6];
	__u32 t2_calls, t3_calls, t6_calls;
};
#endif
