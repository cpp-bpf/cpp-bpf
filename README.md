# cpp-bpf

[![License](https://img.shields.io/static/v1?label=License&message=LGPL-2.1%20OR%20BSD-2-Clause&color=blue)](LICENSE)
[![Status](https://img.shields.io/static/v1?label=Status&message=early%20development&color=orange)](#status)
[![Vision](https://img.shields.io/static/v1?label=Vision&message=and%20Scope&color=blue)](https://github.com/cpp-bpf/.github/blob/main/VISION.md)
[![Contributing](https://img.shields.io/static/v1?label=Contributing&message=Guide&color=brightgreen)](https://github.com/cpp-bpf/.github/blob/main/CONTRIBUTING.md)

cpp-bpf is a C++ library for writing BPF programs. It builds on clang and
libbpf rather than replacing them: C++ BPF programs use the same `vmlinux.h`,
the same libbpf headers and the same loader as C programs, and add
templates, RAII and stronger compile-time checks on top.

## Status

cpp-bpf is in early development and has no release yet. The current work is
upstream compiler support for C++ records in LLVM's BPF backend, which the
library depends on. See the
[roadmap](https://github.com/cpp-bpf/.github/blob/main/VISION.md#roadmap).

## Users

If you write BPF programs in C++, with or without cpp-bpf, please add
yourself to [USERS.md](USERS.md).

## Requirements

- C++20
- clang
- Linux 6.1 or newer
- libbpf

## License

cpp-bpf is dual-licensed under the
[GNU Lesser General Public License v2.1](LICENSE.LGPL-2.1-only) or the
[BSD 2-Clause License](LICENSE.BSD-2-Clause), at your option, the same as
libbpf.
