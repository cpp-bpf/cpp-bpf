# cpp-bpf

[![License](https://img.shields.io/static/v1?label=License&message=LGPL-2.1%20OR%20BSD-2-Clause&color=blue)](LICENSE)
[![Status](https://img.shields.io/static/v1?label=Status&message=early%20development&color=orange)](#status)
[![Vision](https://img.shields.io/static/v1?label=Vision&message=and%20Scope&color=blue)](https://github.com/cpp-bpf/.github/blob/main/VISION.md)
[![Contributing](https://img.shields.io/static/v1?label=Contributing&message=Guide&color=brightgreen)](https://github.com/cpp-bpf/.github/blob/main/CONTRIBUTING.md)

cpp-bpf is a C++ library for writing BPF programs. It builds on clang and
libbpf rather than replacing them: C++ BPF programs use the same libbpf
headers, the same loader and the same skeletons as C programs.

## Why cpp-bpf

Its wrappers inline to the same helper calls a C program makes, and it
catches more mistakes at compile time instead of at load time:

- RAII releases locks and ring buffer reservations on every path
- maps are typed: keys with padding or of the wrong type don't compile,
  and a lookup result has to be taken out explicitly before it is checked
  and used
- program arguments are typed, without casts from the context
- templates replace macros, and types are shared with C++ userspace code

```cpp
cppbpf::hash_map<__u32, proc_stats, 10240> procs SEC(".maps");

CPPBPF_PROG("tp_btf/sys_enter", on_sys_enter, struct pt_regs *regs, long id)
{
	__u32 tgid = bpf_get_current_pid_tgid() >> 32;

	proc_stats *s = procs.lookup_or_init(tgid).get();
	if (!s)
		return 0;
	__sync_fetch_and_add(&s->syscalls, 1);
	return 0;
}
```

The userspace side reads the same map with the same types:

```cpp
auto obj = cppbpf::user::object<syscount>::open_and_load();
obj.attach();
cppbpf::user::map_ref<__u32, proc_stats> procs(obj->maps.procs);
for (auto [pid, s] : procs)
	std::printf("%u %llu\n", pid, (unsigned long long)s.syscalls);
```

## Status

cpp-bpf is in early development and has no release yet. It needs fixes
that are not in released toolchains: the
[tracking issue](https://github.com/cpp-bpf/cpp-bpf/issues/4) lists them.
In particular, `vmlinux.h` does not compile as C++ yet, so programs declare
the kernel types they use.

## Getting started

You need:

- clang built with
  [llvm/llvm-project#233715](https://github.com/llvm/llvm-project/pull/233715)
  (C++ records in BTF), until it is in an LLVM release
- libbpf with its BPF-side headers, and bpftool; tested with libbpf 1.5
  and 1.8 (on Debian: `libbpf-dev`, `bpftool`, `linux-libc-dev`; older
  distributions may need libbpf built from source)
- Linux 6.1 or newer with BTF

Build and run the example, which counts system calls per process:

```
cd examples/syscount
make CLANG=/path/to/clang BPFTOOL=bpftool LIBBPF_INC=/usr/include
sudo build/syscount 5
```

`mk/cppbpf.mk` has the build rules and flags for your own programs. C++
BPF programs need `-std=gnu++20 -fno-exceptions
-fno-asynchronous-unwind-tables -gsimple-template-names`, and programs and
kfunc declarations must be `extern "C"` (`CPPBPF_PROG` does this).

## Layout

- `include/cppbpf/bpf.hpp`: the BPF side (maps, ring buffer, locks,
  programs)
- `include/cppbpf/user.hpp`: the userspace side (objects, maps, ring
  buffer)
- `mk/cppbpf.mk`: build rules
- `examples/`, `tests/`

## Users

If you write BPF programs in C++, with or without cpp-bpf, please add
yourself to [USERS.md](USERS.md).

## License

cpp-bpf is dual-licensed under the
[GNU Lesser General Public License v2.1](LICENSE.LGPL-2.1-only) or the
[BSD 2-Clause License](LICENSE.BSD-2-Clause), at your option, the same as
libbpf.
