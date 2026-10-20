/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef CPPBPF_MAP_HPP
#define CPPBPF_MAP_HPP

#include "common.hpp"

/*
 * Typed maps.
 *
 * libbpf reads a map definition from the BTF of a global variable in
 * ".maps" whose type has the members type, max_entries, key and value.
 * The macros below define such a type with typed accessors.
 *
 * The type is a named, non-template struct: in C++ a variable of an
 * unnamed type has internal linkage, which libbpf rejects, and the kernel
 * rejects BTF names such as "hash_map<unsigned int, ...>". Member
 * functions are not emitted into BTF.
 *
 * Limitations:
 * - Declare maps in the global namespace; inside a namespace the map name
 *   is mangled, and libbpf and the skeleton use the mangled name.
 * - A key or value type with a comma, such as a template with two
 *   arguments, needs a type alias.
 * - Extra map definition members, such as map_flags or pinning, go after
 *   the size: CPPBPF_HASH_MAP(m, K, V, 1024, __uint(map_flags, F_NO_PREALLOC);)
 * - lookup_or_init() builds its initial value on the BPF stack, which is
 *   limited to 512 bytes.
 */

#define CPPBPF_MAP_DEF(name, map_type, K, V, N, ...)			\
	struct name##__cppbpf_map {					\
		int (*type)[map_type];					\
		int (*max_entries)[N];					\
		K *key;							\
		V *value;						\
		__VA_ARGS__						\
									\
		CPPBPF_INLINE V *lookup(const K &k)			\
		{							\
			return static_cast<V *>(			\
				bpf_map_lookup_elem(this, &k));		\
		}							\
		CPPBPF_INLINE long update(const K &k, const V &v,	\
					  __u64 flags = BPF_ANY)	\
		{							\
			return bpf_map_update_elem(this, &k, &v, flags); \
		}							\
		CPPBPF_INLINE long erase(const K &k)			\
		{							\
			return bpf_map_delete_elem(this, &k);		\
		}							\
		/* Look up k, inserting init first if it is missing. */	\
		CPPBPF_INLINE V *lookup_or_init(const K &k,		\
						const V &init = V{})	\
		{							\
			V *v = lookup(k);				\
			if (v)						\
				return v;				\
			update(k, init, BPF_NOEXIST);			\
			return lookup(k);				\
		}							\
	} name SEC(".maps")

#define CPPBPF_HASH_MAP(name, K, V, N, ...) \
	CPPBPF_MAP_DEF(name, BPF_MAP_TYPE_HASH, K, V, N, __VA_ARGS__)
#define CPPBPF_LRU_HASH_MAP(name, K, V, N, ...) \
	CPPBPF_MAP_DEF(name, BPF_MAP_TYPE_LRU_HASH, K, V, N, __VA_ARGS__)
#define CPPBPF_ARRAY_MAP(name, V, N, ...) \
	CPPBPF_MAP_DEF(name, BPF_MAP_TYPE_ARRAY, __u32, V, N, __VA_ARGS__)

#endif /* CPPBPF_MAP_HPP */
