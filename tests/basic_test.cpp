// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Loads progs/basic.bpf.cpp and checks its maps and ring buffer.
#include <thread>
#include <unistd.h>
#include <sys/syscall.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <linux/types.h>
#include "progs/basic.h"
#include "basic.skel.h"
#include "test.h"

struct seen { int events, main_thread, other_tgid; __u32 tgid; };

static int on_event(void *ctx, void *data, size_t)
{
	auto *s = static_cast<seen *>(ctx);
	auto *e = static_cast<event *>(data);
	s->events++;
	if (e->pid == e->tgid)
		s->main_thread++;
	if (e->tgid != s->tgid)
		s->other_tgid++;
	return 0;
}

int main()
{
	__u32 tgid = getpid();
	basic *skel = basic::open();
	REQUIRE(skel, "open");
	skel->rodata->target_tgid = tgid;
	REQUIRE(basic::load(skel) == 0, "load");
	REQUIRE(basic::attach(skel) == 0, "attach");

	seen s{0, 0, 0, tgid};
	ring_buffer *rb = ring_buffer__new(bpf_map__fd(skel->maps.events), on_event, &s, nullptr);
	REQUIRE(rb, "ring_buffer__new");

	std::thread worker([] { for (int i = 0; i < 50; i++) usleep(1000); });
	for (int i = 0; i < 50; i++)
		usleep(1000);
	worker.join();

	struct { __u64 switches; __u32 lock; } st{};
	int err = bpf_map__lookup_elem(skel->maps.per_pid, &tgid, sizeof(tgid), &st, sizeof(st), 0);
	CHECK(err == 0, "per_pid lookup: %d", err);
	CHECK(st.switches >= 100, "switches %llu, want >= 100", (unsigned long long)st.switches);

	ring_buffer__consume(rb);
	CHECK(s.events > 0, "no events from the worker thread");
	CHECK(s.main_thread == 0, "%d events from the main thread were not discarded", s.main_thread);
	CHECK(s.other_tgid == 0, "%d events from other processes", s.other_tgid);

	std::printf("switches %llu, events %d\n", (unsigned long long)st.switches, s.events);
	ring_buffer__free(rb);
	basic::destroy(skel);
	return test_result();
}
