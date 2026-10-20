// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Loads progs/basic.bpf.cpp and checks its maps and ring buffer.
#include <ranges>
#include <thread>
#include <unistd.h>
#include <linux/types.h>
#include <cppbpf/user.hpp>
#include "progs/basic.h"
#include "basic.skel.h"
#include "test.h"

int main()
{
	__u32 tgid = getpid();
	auto obj = cppbpf::user::object<basic>::open();
	REQUIRE(obj, "open");
	obj->rodata->target_tgid = tgid;
	REQUIRE(obj.load() == 0, "load");
	REQUIRE(obj.attach() == 0, "attach");

	int events = 0, main_thread = 0, other_tgid = 0;
	cppbpf::user::ring_reader reader;
	int err = reader.add<event>(obj->maps.events, [&](const event &e) {
		events++;
		if (e.pid == e.tgid)
			main_thread++;
		if (e.tgid != tgid)
			other_tgid++;
	});
	REQUIRE(err == 0, "ring_reader add: %d", err);

	std::thread worker([] {
		for (int i = 0; i < 50; i++)
			usleep(1000);
	});
	for (int i = 0; i < 50; i++)
		usleep(1000);
	worker.join();

	cppbpf::user::map_ref<__u32, stats_view> per_pid(obj->maps.per_pid);
	auto st = per_pid.lookup(tgid);
	REQUIRE(st, "per_pid lookup");
	CHECK(st->switches >= 100, "switches %llu, want >= 100",
	      (unsigned long long)st->switches);

	int entries = 0;
	for (auto [pid, s] : per_pid) {
		entries++;
		CHECK(pid == tgid, "unexpected key %u", pid);
	}
	CHECK(entries == 1, "%d entries, want 1", entries);
	CHECK(per_pid.error() == 0, "iteration error %d", per_pid.error());
	static_assert(std::input_iterator<decltype(per_pid.begin())>);
	static_assert(std::ranges::input_range<decltype(per_pid)>);

	reader.consume();
	CHECK(events > 0, "no events from the worker thread");
	CHECK(main_thread == 0,
	      "%d events from the main thread were not discarded", main_thread);
	CHECK(other_tgid == 0, "%d events from other processes", other_tgid);

	std::printf("switches %llu, events %d\n",
		    (unsigned long long)st->switches, events);
	return test_result();
}
