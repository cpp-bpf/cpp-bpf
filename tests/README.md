# Tests

Each test is a BPF program in `progs/` and a userspace program that loads
it with libbpf and checks the result. They need root and a kernel with BTF.

Until the fixes tracked in #4 are upstream, building needs:

- clang with llvm/llvm-project#233715
- the libbpf BPF-side headers (`LIBBPF_INC`); the build makes a copy of
  `bpf_helper_defs.h` that compiles as C++
- bpftool and libbpf for the userspace part

The build rules are in `../mk/cppbpf.mk`, which lists the variables:

```
make CLANG=... BPFTOOL=... LIBBPF_INC=... UAPI_INC=...
sudo build/basic_test && sudo build/args_test
```

- `basic`: typed hash maps, `spin_guard`, and ring buffer reservations
  that are discarded unless submitted.
- `args`: `CPPBPF_PROG` argument mapping for fentry and fexit, using the
  `bpf_fentry_test*()` functions that the kernel calls with known values
  on `BPF_PROG_TEST_RUN`.

CI runs them on the GitHub runner kernel; they were also tested on
bpf-next 7.3-rc5.
