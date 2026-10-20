/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef CPPBPF_MAP_HPP
#define CPPBPF_MAP_HPP

#include "common.hpp"

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
 * mangled, and libbpf and the skeleton use the mangled name.
 */

namespace cppbpf::detail {

template <class K, class V>
CPPBPF_INLINE V *map_lookup(void *map, const K &k)
{
	return static_cast<V *>(bpf_map_lookup_elem(map, &k));
}

template <class K, class V>
CPPBPF_INLINE long map_update(void *map, const K &k, const V &v, __u64 flags)
{
	return bpf_map_update_elem(map, &k, &v, flags);
}

template <class K>
CPPBPF_INLINE long map_erase(void *map, const K &k)
{
	return bpf_map_delete_elem(map, &k);
}

/*
 * Look up k, inserting init first if it is missing. The initial value is
 * built on the BPF stack, which is limited to 512 bytes.
 */
template <class K, class V>
CPPBPF_INLINE V *map_lookup_or_init(void *map, const K &k, const V &init)
{
	V *v = map_lookup<K, V>(map, k);
	if (v)
		return v;
	map_update(map, k, init, BPF_NOEXIST);
	return map_lookup<K, V>(map, k);
}

} /* namespace cppbpf::detail */

namespace cppbpf {

template <class K, class V, unsigned N, unsigned Flags = 0>
struct hash_map {
	int (*type)[BPF_MAP_TYPE_HASH];
	int (*max_entries)[N];
	int (*map_flags)[Flags];
	K *key;
	V *value;

	CPPBPF_INLINE V *lookup(const K &k) { return detail::map_lookup<K, V>(this, k); }
	CPPBPF_INLINE long update(const K &k, const V &v, __u64 flags = BPF_ANY) { return detail::map_update(this, k, v, flags); }
	CPPBPF_INLINE long erase(const K &k) { return detail::map_erase(this, k); }
	CPPBPF_INLINE V *lookup_or_init(const K &k, const V &init = V{}) { return detail::map_lookup_or_init(this, k, init); }
};

template <class K, class V, unsigned N, unsigned Flags = 0>
struct lru_hash_map {
	int (*type)[BPF_MAP_TYPE_LRU_HASH];
	int (*max_entries)[N];
	int (*map_flags)[Flags];
	K *key;
	V *value;

	CPPBPF_INLINE V *lookup(const K &k) { return detail::map_lookup<K, V>(this, k); }
	CPPBPF_INLINE long update(const K &k, const V &v, __u64 flags = BPF_ANY) { return detail::map_update(this, k, v, flags); }
	CPPBPF_INLINE long erase(const K &k) { return detail::map_erase(this, k); }
	CPPBPF_INLINE V *lookup_or_init(const K &k, const V &init = V{}) { return detail::map_lookup_or_init(this, k, init); }
};

template <class V, unsigned N, unsigned Flags = 0>
struct array_map {
	int (*type)[BPF_MAP_TYPE_ARRAY];
	int (*max_entries)[N];
	int (*map_flags)[Flags];
	__u32 *key;
	V *value;

	CPPBPF_INLINE V *lookup(__u32 i) { return detail::map_lookup<__u32, V>(this, i); }
	CPPBPF_INLINE long update(__u32 i, const V &v, __u64 flags = BPF_ANY) { return detail::map_update(this, i, v, flags); }
};

} /* namespace cppbpf */

#endif /* CPPBPF_MAP_HPP */
