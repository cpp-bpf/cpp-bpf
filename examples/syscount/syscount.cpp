// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Count system calls per process for a few seconds and print the top ones.
#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <vector>
#include <linux/types.h>
#include <cppbpf/user.hpp>
#include "syscount.h"
#include "syscount.skel.h"

int main(int argc, char **argv)
{
	int seconds = argc > 1 ? std::atoi(argv[1]) : 5;

	auto obj = cppbpf::user::object<syscount>::open_and_load();
	if (!obj) {
		std::fprintf(stderr, "failed to load: %s\n",
			     std::strerror(errno));
		return 1;
	}
	if (int err = obj.attach()) {
		std::fprintf(stderr, "failed to attach: %s\n",
			     std::strerror(-err));
		return 1;
	}

	std::printf("Counting system calls for %d seconds...\n", seconds);
	sleep(seconds);

	cppbpf::user::map_ref<__u32, proc_stats> procs(obj->maps.procs);
	std::vector<std::pair<__u32, proc_stats>> top;
	for (const auto &entry : procs)
		top.push_back(entry);
	if (int err = procs.error()) {
		std::fprintf(stderr, "failed to read the map: %s\n",
			     std::strerror(-err));
		return 1;
	}
	std::sort(top.begin(), top.end(), [](const auto &a, const auto &b) {
		return a.second.syscalls > b.second.syscalls;
	});
	if (top.size() > 10)
		top.resize(10);

	std::printf("%-8s %-16s %s\n", "PID", "COMM", "SYSCALLS");
	for (const auto &[pid, s] : top)
		std::printf("%-8u %-16.16s %llu\n", pid, s.comm,
			    (unsigned long long)s.syscalls);
	return 0;
}
