// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#ifndef CPPBPF_TEST_H
#define CPPBPF_TEST_H
#include <cstdio>

static int fails;

#define CHECK(cond, ...)						\
	do {								\
		if (!(cond)) {						\
			fails++;					\
			std::printf("FAIL: " __VA_ARGS__);		\
			std::printf("\n");				\
		}							\
	} while (0)

/* Stop the test: later checks depend on this one. */
#define REQUIRE(cond, ...)						\
	do {								\
		bool ok_ = (cond);					\
		CHECK(ok_, __VA_ARGS__);				\
		if (!ok_) {						\
			std::printf("FAIL\n");				\
			return 1;					\
		}							\
	} while (0)

static int test_result()
{
	std::printf(fails ? "FAIL\n" : "PASS\n");
	return fails ? 1 : 0;
}
#endif
