/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef CPPBPF_PROG_HPP
#define CPPBPF_PROG_HPP

#include "common.hpp"

namespace cppbpf::detail {

template <class T, T... I>
struct index_seq {};

template <unsigned long N> struct uint_of;
template <> struct uint_of<1> { using type = unsigned char; };
template <> struct uint_of<2> { using type = unsigned short; };
template <> struct uint_of<4> { using type = unsigned int; };
template <> struct uint_of<8> { using type = unsigned long long; };

/* Context slots taken by an argument: structs up to 16 bytes take two. */
template <class T>
constexpr unsigned long slots_of()
{
	if constexpr (__is_class(T) || __is_union(T))
		return (sizeof(T) + 7) / 8;
	else
		return 1;
}

template <class... A>
struct arg_layout {
	static constexpr unsigned long slots[] = { slots_of<A>()..., 0 };

	static constexpr unsigned long offset(unsigned long i)
	{
		unsigned long off = 0;
		for (unsigned long j = 0; j < i; j++)
			off += slots[j];
		return off;
	}
};

/*
 * Convert context slots to a parameter of type T. Integers narrower than
 * 64 bits use only their low bits: for fentry and similar programs the
 * upper bits of a slot are not guaranteed to be zero.
 */
template <class T, unsigned long Off>
CPPBPF_INLINE T ctx_arg(unsigned long long *ctx)
{
	static_assert(!__is_reference(T),
		      "CPPBPF_PROG parameters can't be references");
	if constexpr (__is_class(T) || __is_union(T)) {
		static_assert(sizeof(T) <= 16,
			      "structs passed by value can be at most 16 bytes");
		static_assert(__is_trivially_copyable(T),
			      "structs passed by value must be trivially copyable");
		unsigned long long raw[slots_of<T>()];
		for (unsigned long i = 0; i < slots_of<T>(); i++)
			raw[i] = ctx[Off + i];
		alignas(T) unsigned char buf[sizeof(T)];
		__builtin_memcpy(buf, raw, sizeof(T));
		return __builtin_bit_cast(T, buf);
	} else if constexpr (__is_pointer(T)) {
		return (T)ctx[Off];
	} else if constexpr (__is_enum(T)) {
		using U = __underlying_type(T);
		return (T)(U)(typename uint_of<sizeof(U)>::type)ctx[Off];
	} else {
		static_assert(__is_integral(T),
			      "unsupported CPPBPF_PROG parameter type");
		return (T)(typename uint_of<sizeof(T)>::type)ctx[Off];
	}
}

template <class F> struct fn_traits;
template <class R, class... A>
struct fn_traits<R (*)(A...)> {
	static constexpr unsigned long arity = sizeof...(A);
};

template <auto F, class R, class... A, unsigned long... I>
CPPBPF_INLINE R call_impl(unsigned long long *ctx, R (*)(A...),
			  index_seq<unsigned long, I...>)
{
	using layout = arg_layout<A...>;
	return F(ctx_arg<A, layout::offset(I)>(ctx)...);
}

/* Call F, a direct call, with its arguments taken from ctx. */
template <auto F>
CPPBPF_INLINE auto call_with_ctx(unsigned long long *ctx)
{
	return call_impl<F>(ctx, F,
			    __make_integer_seq<index_seq, unsigned long,
					       fn_traits<decltype(F)>::arity>{});
}

} /* namespace cppbpf::detail */

/*
 * A BTF-enabled program (tp_btf, fentry, fexit, fmod_ret, lsm, ...) with
 * typed arguments:
 *
 *   CPPBPF_PROG("tp_btf/sched_switch", on_switch,
 *               bool preempt, struct task_struct *prev,
 *               struct task_struct *next)
 *   {
 *           ...
 *   }
 *
 * Parameters can be integers, enums, pointers, and trivially copyable
 * structs of up to 16 bytes passed by value. The program symbol is
 * extern "C", so libbpf sees its plain name.
 */
#define CPPBPF_PROG(sec, name, ...)					\
	static CPPBPF_INLINE int ____##name(__VA_ARGS__);		\
	SEC(sec) extern "C" int name(unsigned long long *ctx)		\
	{								\
		return ::cppbpf::detail::call_with_ctx<____##name>(ctx); \
	}								\
	static CPPBPF_INLINE int ____##name(__VA_ARGS__)

#endif /* CPPBPF_PROG_HPP */
