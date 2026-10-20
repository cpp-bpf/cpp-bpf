/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef CPPBPF_RINGBUF_HPP
#define CPPBPF_RINGBUF_HPP

#include "common.hpp"

namespace cppbpf {

/*
 * A ring buffer reservation. It is discarded when it goes out of scope
 * unless it was submitted, so a reservation can't leak on an early return.
 * It can be moved, e.g. returned from a helper function, but not copied.
 */
template <class T>
class ringbuf_entry {
public:
	CPPBPF_INLINE explicit ringbuf_entry(T *p) : p_(p) {}
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

	CPPBPF_INLINE explicit operator bool() const { return p_; }
	CPPBPF_INLINE T *operator->() const { return p_; }
	CPPBPF_INLINE T &operator*() const { return *p_; }

	CPPBPF_INLINE void submit(__u64 flags = 0)
	{
		bpf_ringbuf_submit(p_, flags);
		p_ = nullptr;
	}
	CPPBPF_INLINE void discard(__u64 flags = 0)
	{
		bpf_ringbuf_discard(p_, flags);
		p_ = nullptr;
	}

private:
	T *p_;
};

} /* namespace cppbpf */

/* A ring buffer map: CPPBPF_RINGBUF(events, 256 * 1024). */
#define CPPBPF_RINGBUF(name, size)					\
	struct name##__cppbpf_ringbuf {					\
		int (*type)[BPF_MAP_TYPE_RINGBUF];			\
		int (*max_entries)[size];				\
									\
		template <class T>					\
		[[nodiscard]] CPPBPF_INLINE				\
		::cppbpf::ringbuf_entry<T> reserve()			\
		{							\
			return ::cppbpf::ringbuf_entry<T>(static_cast<T *>( \
				bpf_ringbuf_reserve(this, sizeof(T), 0))); \
		}							\
	} name SEC(".maps")

#endif /* CPPBPF_RINGBUF_HPP */
