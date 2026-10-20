/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef CPPBPF_USER_MAP_HPP
#define CPPBPF_USER_MAP_HPP

#include <bpf/libbpf.h>
#include <cerrno>
#include <cstddef>
#include <iterator>
#include <optional>
#include <utility>

namespace cppbpf::user {

/*
 * Typed access to a map of a loaded object. It does not own the map and,
 * like std::span, all operations are const:
 *
 *   cppbpf::user::map_ref<__u32, stats> per_pid(obj->maps.per_pid);
 *   for (auto [pid, s] : per_pid)
 *           ...
 *   if (per_pid.error())
 *           ...
 *
 * K and V must match the map's key and value; libbpf checks their sizes
 * and fails the operation with -EINVAL if they don't. Per-CPU maps are not
 * supported yet: their operations fail with -EINVAL.
 */
template <class K, class V>
class map_ref {
public:
	map_ref() = default;

	explicit map_ref(struct bpf_map *map) : map_(map)
	{
	}

	/* The value for k, or nothing if k is missing or on an error. */
	std::optional<V> lookup(const K &k, __u64 flags = 0) const
	{
		V v;
		if (lookup(k, v, flags))
			return std::nullopt;
		return v;
	}

	/* Look up k into v; returns 0, -ENOENT or another negative errno. */
	int lookup(const K &k, V &v, __u64 flags = 0) const
	{
		return bpf_map__lookup_elem(map_, &k, sizeof(K), &v, sizeof(V),
					    flags);
	}

	int update(const K &k, const V &v, __u64 flags = BPF_ANY) const
	{
		return bpf_map__update_elem(map_, &k, sizeof(K), &v, sizeof(V),
					    flags);
	}

	int erase(const K &k) const
	{
		return bpf_map__delete_elem(map_, &k, sizeof(K), 0);
	}

	/*
	 * Iterates over (key, value) pairs. Elements added or deleted
	 * concurrently may or may not be visited, and deleting the current
	 * element from a hash map can make the iteration start over, as with
	 * bpf_map_get_next_key(). An error ends the iteration and is
	 * returned by error() of the map_ref; so is -EAGAIN if the iteration
	 * took more steps than the map can hold, which happens when it keeps
	 * starting over.
	 */
	class iterator {
	public:
		using iterator_category = std::input_iterator_tag;
		using value_type = std::pair<K, V>;
		using difference_type = std::ptrdiff_t;
		using pointer = const value_type *;
		using reference = const value_type &;

		iterator() = default;

		reference operator*() const
		{
			return cur_;
		}

		pointer operator->() const
		{
			return &cur_;
		}

		iterator &operator++()
		{
			advance(true);
			return *this;
		}

		void operator++(int)
		{
			++*this;
		}

		bool operator==(std::default_sentinel_t) const
		{
			return !owner_;
		}

	private:
		friend class map_ref;

		explicit iterator(const map_ref *owner) : owner_(owner)
		{
			owner_->err_ = 0;
			limit_ = bpf_map__max_entries(owner_->map_) + 1;
			advance(false);
		}

		void finish(int err)
		{
			owner_->err_ = err;
			owner_ = nullptr;
		}

		/*
		 * Find the next element after the current one (or the first).
		 * If an element is deleted between reading its key and its
		 * value, continue from the last element read instead of from
		 * the deleted key, which would start over.
		 */
		void advance(bool have_cur)
		{
			struct bpf_map *map = owner_->map_;
			const K *prev = have_cur ? &cur_.first : nullptr;
			K next;

			while (owner_) {
				if (!limit_--)
					return finish(-EAGAIN);
				int err = bpf_map__get_next_key(
					map, prev, &next, sizeof(K));
				if (err)
					return finish(err == -ENOENT ? 0 : err);
				err = bpf_map__lookup_elem(
					map, &next, sizeof(K), &cur_.second,
					sizeof(V), 0);
				if (!err) {
					cur_.first = next;
					return;
				}
				if (err != -ENOENT)
					return finish(err);
			}
		}

		const map_ref *owner_ = nullptr;
		unsigned long limit_ = 0;
		value_type cur_{};
	};

	iterator begin() const
	{
		return iterator(this);
	}

	std::default_sentinel_t end() const
	{
		return {};
	}

	/* The error that ended the last iteration, or 0. */
	int error() const
	{
		return err_;
	}

	struct bpf_map *get() const
	{
		return map_;
	}

private:
	struct bpf_map *map_ = nullptr;
	mutable int err_ = 0;
};

} /* namespace cppbpf::user */

#endif /* CPPBPF_USER_MAP_HPP */
