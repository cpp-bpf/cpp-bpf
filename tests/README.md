# Tests

Each test is a BPF program in `progs/` and a userspace program that loads
it with libbpf and checks the result. They need root and a kernel with BTF.

Until the fixes tracked in #4 are upstream, building needs:

- clang with llvm/llvm-project#233715
- the libbpf BPF-side headers from bpf-next (`LIBBPF_INC`); the Makefile
  makes a copy of `bpf_helper_defs.h` that compiles as C++
- bpftool and libbpf for the userspace part

```
make CLANG=... BPFTOOL=... LIBBPF_INC=... UAPI_INC=...
sudo build/basic_test && sudo build/args_test
```

- `basic`: typed hash maps, `spin_guard`, and ring buffer reservations
  that are discarded unless submitted.
- `args`: `CPPBPF_PROG` argument mapping for fentry and fexit, using the
  `bpf_fentry_test*()` functions that the kernel calls with known values
  on `BPF_PROG_TEST_RUN`.

Tested on bpf-next 7.3-rc5.
