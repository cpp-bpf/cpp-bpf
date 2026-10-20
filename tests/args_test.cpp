// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Checks that CPPBPF_PROG maps arguments to the right context slots.
#include <bpf/bpf.h>
#include <linux/types.h>
#include <cppbpf/user.hpp>
#include "progs/args.h"
#include "args.skel.h"
#include "test.h"

static void check(const char *what, const __u64 *got, const __u64 *want, int n)
{
	for (int i = 0; i < n; i++)
		CHECK(got[i] == want[i], "%s arg %d: got %llu, want %llu", what,
		      i, (unsigned long long)got[i],
		      (unsigned long long)want[i]);
}

int main()
{
	auto obj = cppbpf::user::object<args>::open_and_load();
	REQUIRE(obj, "open and load");
	REQUIRE(obj.attach() == 0, "attach");

	LIBBPF_OPTS(bpf_test_run_opts, opts);
	int err = bpf_prog_test_run_opts(bpf_program__fd(obj->progs.on_test3),
					 &opts);
	REQUIRE(err == 0, "test run: %d", err);

	const args_result &r = obj->bss->res;
	CHECK(r.t2_calls == 1 && r.t3_calls == 1 && r.t6_calls == 1,
	      "calls: t2 %u, t3 %u, t6 %u", r.t2_calls, r.t3_calls, r.t6_calls);
	const __u64 t2[] = { 2, 3, 5 }, t3[] = { 4, 5, 6 },
		    t6[] = { 16, 17, 18, 19, 20, 21 };
	check("test2", r.t2, t2, 3);
	check("test3", r.t3, t3, 3);
	check("test6", r.t6, t6, 6);

	return test_result();
}
