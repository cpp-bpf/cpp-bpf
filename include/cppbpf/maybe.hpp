/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef CPPBPF_MAYBE_HPP
#define CPPBPF_MAYBE_HPP

#include "common.hpp"

namespace cppbpf {

/*
 * A pointer that may be NULL, such as the result of a map lookup. It has
 * no operator-> or operator*, so the result can't be dereferenced directly:
 * the pointer has to be taken out with get(), which makes the NULL check
 * the natural next step. The verifier still rejects a dereference without
 * the check, as in C:
 *
 *   if (stats *s = per_pid.lookup(pid).get())
 *           s->count++;
 */
template <class T>
class [[nodiscard]] maybe {
public:
	CPPBPF_INLINE explicit maybe(T *p) : p_(p)
	{
	}

	/* The pointer, or NULL; check it before use. */
	CPPBPF_INLINE T *get() const
	{
		return p_;
	}

	CPPBPF_INLINE explicit operator bool() const
	{
		return p_;
	}

private:
	T *p_;
};

} /* namespace cppbpf */

#endif /* CPPBPF_MAYBE_HPP */
