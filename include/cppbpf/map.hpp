/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef CPPBPF_MAP_HPP
#define CPPBPF_MAP_HPP

#include "common.hpp"
#include "maybe.hpp"

/*
 * BTF-defined maps with typed accessors:
 *
 *   cppbpf::hash_map<__u32, stats, 1024> per_pid SEC(".maps");
 *
 * libbpf reads the definition from the members type, max_entries,
 * map_flags, key and value; member functions are not emitted into BTF.
 *
 * Build with -gsimple-template-names, so that the type is named "hash_map"
 * in BTF rather than "hash_map<unsigned int, ...>", which the kernel
 * rejects. For the same reason the map types are class templates, not
 * alias templates: an alias keeps its full name in BTF.
 *
 * Declare maps in the global namespace: inside a namespace the map name is
 * mangled, and libbpf and the skeleton use the mangled name. Key and value
 * types must be named types with external linkage: a type in an anonymous
 * namespace gives the map internal linkage, which libbpf rejects, and an
 * unnamed struct behind a typedef makes the BTF name fall back to
 * "hash_map<...>".
 *
 * Hash map keys can't have padding, whose bytes would be uninitialized and
 * make lookups miss, and must be passed as the key type itself, so that a
 * __u64 isn't silently truncated to a __u32 key.
 */

namespace cppbpf::detail {

/* Operations shared by the map types; Map is the map definition. */
template <class Map, class K, class V>
struct map_ops {
	CPPBPF_INLINE static maybe<V> lookup(Map *m, const K &k)
	{
		return maybe<V>(static_cast<V *>(bpf_map_lookup_elem(m, &k)));
	}

	CPPBPF_INLINE static long update(Map *m, const K &k, const V &v,
					 __u64 flags)
	{
		return bpf_map_update_elem(m, &k, &v, flags);
	}

	CPPBPF_INLINE static long erase(Map *m, const K &k)
	{
		return bpf_map_delete_elem(m, &k);
	}

	CPPBPF_INLINE static maybe<V> lookup_or_init(Map *m, const K &k,
						     const V &init)
	{
		if (maybe<V> v = lookup(m, k))
			return v;
		update(m, k, init, BPF_NOEXIST);
		return lookup(m, k);
	}
};

} /* namespace cppbpf::detail */

/* map_flags is int (*)[0] when Flags is 0, as with __uint(map_flags, 0). */
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wzero-length-array"

namespace cppbpf {

/* BPF_MAP_TYPE_HASH */
template <class K, class V, unsigned N, unsigned Flags = 0>
struct hash_map {
	int (*type)[BPF_MAP_TYPE_HASH];
	int (*max_entries)[N];
	int (*map_flags)[Flags];
	K *key;
	V *value;

	static_assert(N > 0, "max_entries must be positive");
	static_assert(__has_unique_object_representations(K),
		      "map keys can't have padding bytes");
	using ops = detail::map_ops<hash_map, K, V>;

	/* Keys must have the key type; see above. */
	template <class T>
	maybe<V> lookup(const T &) = delete;
	template <class T>
	long update(const T &, const V &, __u64 = BPF_ANY) = delete;
	template <class T>
	long erase(const T &) = delete;
	template <class T>
	maybe<V> lookup_or_init(const T &, const V & = V{}) = delete;

	CPPBPF_INLINE maybe<V> lookup(const K &k)
	{
		return ops::lookup(this, k);
	}

	CPPBPF_INLINE long update(const K &k, const V &v, __u64 flags = BPF_ANY)
	{
		return ops::update(this, k, v, flags);
	}

	CPPBPF_INLINE long erase(const K &k)
	{
		return ops::erase(this, k);
	}

	/*
	 * Look up k, inserting init first if it is missing. The initial
	 * value is built on the BPF stack, which is limited to 512 bytes.
	 * To only make sure the element exists, cast the result to void.
	 */
	CPPBPF_INLINE maybe<V> lookup_or_init(const K &k, const V &init = V{})
	{
		return ops::lookup_or_init(this, k, init);
	}
};

/* BPF_MAP_TYPE_LRU_HASH */
template <class K, class V, unsigned N, unsigned Flags = 0>
struct lru_hash_map {
	int (*type)[BPF_MAP_TYPE_LRU_HASH];
	int (*max_entries)[N];
	int (*map_flags)[Flags];
	K *key;
	V *value;

	static_assert(N > 0, "max_entries must be positive");
	static_assert(__has_unique_object_representations(K),
		      "map keys can't have padding bytes");
	using ops = detail::map_ops<lru_hash_map, K, V>;

	/* Keys must have the key type; see above. */
	template <class T>
	maybe<V> lookup(const T &) = delete;
	template <class T>
	long update(const T &, const V &, __u64 = BPF_ANY) = delete;
	template <class T>
	long erase(const T &) = delete;
	template <class T>
	maybe<V> lookup_or_init(const T &, const V & = V{}) = delete;

	CPPBPF_INLINE maybe<V> lookup(const K &k)
	{
		return ops::lookup(this, k);
	}

	CPPBPF_INLINE long update(const K &k, const V &v, __u64 flags = BPF_ANY)
	{
		return ops::update(this, k, v, flags);
	}

	CPPBPF_INLINE long erase(const K &k)
	{
		return ops::erase(this, k);
	}

	/* See hash_map::lookup_or_init(). */
	CPPBPF_INLINE maybe<V> lookup_or_init(const K &k, const V &init = V{})
	{
		return ops::lookup_or_init(this, k, init);
	}
};

/* BPF_MAP_TYPE_ARRAY; elements always exist and can't be deleted. */
template <class V, unsigned N, unsigned Flags = 0>
struct array_map {
	int (*type)[BPF_MAP_TYPE_ARRAY];
	int (*max_entries)[N];
	int (*map_flags)[Flags];
	__u32 *key;
	V *value;

	static_assert(N > 0, "max_entries must be positive");
	using ops = detail::map_ops<array_map, __u32, V>;

	/* NULL only if i is out of range. */
	CPPBPF_INLINE maybe<V> lookup(__u32 i)
	{
		return ops::lookup(this, i);
	}

	CPPBPF_INLINE long update(__u32 i, const V &v, __u64 flags = BPF_ANY)
	{
		return ops::update(this, i, v, flags);
	}
};

} /* namespace cppbpf */

#pragma clang diagnostic pop

#endif /* CPPBPF_MAP_HPP */
