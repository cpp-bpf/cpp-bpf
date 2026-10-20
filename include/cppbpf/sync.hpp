/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef CPPBPF_SYNC_HPP
#define CPPBPF_SYNC_HPP

#include "common.hpp"

namespace cppbpf {

/*
 * Holds a bpf_spin_lock until the guard goes out of scope or unlock() is
 * called, so the lock is released on every path out of the scope.
 *
 * Everything in the guarded scope runs with the lock held, including the
 * destructors of objects declared later in the scope, and the verifier
 * rejects most helper calls while a lock is held. Keep the scope small:
 *
 *   {
 *           cppbpf::spin_guard guard(v->lock);
 *           v->count++;
 *   }
 */
class spin_guard {
public:
	[[nodiscard]] CPPBPF_INLINE explicit spin_guard(
		struct bpf_spin_lock &lock) :
		lock_(lock),
		locked_(true)
	{
		bpf_spin_lock(&lock_);
	}
	CPPBPF_INLINE ~spin_guard()
	{
		if (locked_)
			bpf_spin_unlock(&lock_);
	}

	spin_guard(const spin_guard &) = delete;
	spin_guard &operator=(const spin_guard &) = delete;

	/* Release the lock before the end of the scope. */
	CPPBPF_INLINE void unlock()
	{
		bpf_spin_unlock(&lock_);
		locked_ = false;
	}

private:
	struct bpf_spin_lock &lock_;
	bool locked_;
};

} /* namespace cppbpf */

#endif /* CPPBPF_SYNC_HPP */
