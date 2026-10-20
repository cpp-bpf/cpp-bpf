/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef CPPBPF_RINGBUF_HPP
#define CPPBPF_RINGBUF_HPP

#include "common.hpp"

namespace cppbpf {

/*
 * A ring buffer reservation. It is discarded when it goes out of scope
 * unless it was submitted, so a reservation can't leak on an early return.
 * It can be moved, e.g. returned from a helper function, but not copied:
 *
 *   auto e = events.reserve<event>();
 *   event *ev = e.get();
 *   if (!ev)
 *           return 0;
 *   ev->pid = pid;
 *   e.submit();
 */
template <unsigned Size>
struct ringbuf;

template <class T>
class ringbuf_entry {
public:
	CPPBPF_INLINE ~ringbuf_entry()
	{
		if (p_)
			bpf_ringbuf_discard(p_, 0);
	}

	CPPBPF_INLINE ringbuf_entry(ringbuf_entry &&other) : p_(other.p_)
	{
		other.p_ = nullptr;
	}
	ringbuf_entry(const ringbuf_entry &) = delete;
	ringbuf_entry &operator=(const ringbuf_entry &) = delete;
	ringbuf_entry &operator=(ringbuf_entry &&) = delete;

	/*
	 * The reserved record, or NULL if the reservation failed. As with
	 * maybe, there is no operator->: take the pointer out and check it.
	 */
	CPPBPF_INLINE T *get() const
	{
		return p_;
	}

	CPPBPF_INLINE explicit operator bool() const
	{
		return p_;
	}

	/* Submit the record; does nothing if the reservation failed. */
	CPPBPF_INLINE void submit(__u64 flags = 0)
	{
		if (p_)
			bpf_ringbuf_submit(p_, flags);
		p_ = nullptr;
	}
	/* Discard the record; does nothing if the reservation failed. */
	CPPBPF_INLINE void discard(__u64 flags = 0)
	{
		if (p_)
			bpf_ringbuf_discard(p_, flags);
		p_ = nullptr;
	}

private:
	template <unsigned Size>
	friend struct ringbuf;

	CPPBPF_INLINE explicit ringbuf_entry(T *p) : p_(p)
	{
	}

	T *p_;
};

/*
 * A ring buffer map:
 *
 *   cppbpf::ringbuf<256 * 1024> events SEC(".maps");
 */
template <unsigned Size>
struct ringbuf {
	int (*type)[BPF_MAP_TYPE_RINGBUF];
	int (*max_entries)[Size];

	template <class T>
	[[nodiscard]] CPPBPF_INLINE ringbuf_entry<T> reserve()
	{
		return ringbuf_entry<T>(static_cast<T *>(
			bpf_ringbuf_reserve(this, sizeof(T), 0)));
	}
};

} /* namespace cppbpf */

#endif /* CPPBPF_RINGBUF_HPP */
