#!/usr/bin/env python3
# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
"""Generate a vmlinux.h that compiles as C++, and still as C.

    gen-vmlinux.py [--bpftool BPFTOOL] [--layout-asserts] [BTF] > vmlinux.h

BTF is a raw BTF file, by default /sys/kernel/btf/vmlinux. The types are
changed in BTF where C++ needs it, then dumped by bpftool as C:

- names that are C++ keywords get a ___cpp suffix, e.g. struct class___cpp
  and the field page::private___cpp;
- so do a struct, union or enum with the name of a typedef of another type,
  and a class with the name of a member of one of its anonymous members;
- _Bool is called bool, which C++ has built in;
- an anonymous member of a named struct type becomes an unnamed copy;
- in a class with a member named like a typedef, the typedef is renamed;
- members of an empty struct type become zero-length arrays, because an
  empty struct has size 1 in C++, e.g. struct lock_class_key key[0];
- a declaration of an enum without values gets its underlying type in C++.

The declarations are wrapped in extern "C", which keeps kfuncs unmangled.

libbpf ignores a ___ suffix in the names of types and enum values, so CO-RE
relocations against renamed types still work. It compares field names
exactly, so CO-RE relocations against renamed fields don't match: reads
fail to load and bpf_core_field_exists() is 0. The same goes for members
that became arrays, where the kernel type isn't empty.

With --layout-asserts, print static_asserts on the type layout from BTF
instead, which scripts/check-vmlinux.sh compiles as C and C++.
"""

import argparse
import struct
import subprocess
import sys
import tempfile

CXX_KEYWORDS = frozenset("""
    alignas alignof and and_eq asm bitand bitor bool catch char8_t char16_t
    char32_t class compl concept consteval constexpr constinit const_cast
    co_await co_return co_yield decltype delete dynamic_cast explicit export
    false friend mutable namespace new noexcept not not_eq nullptr operator
    or or_eq private protected public reinterpret_cast requires static_assert
    static_cast template this thread_local throw true try typeid typename
    using virtual wchar_t xor xor_eq
""".split())

SUFFIX = "___cpp"

# _Bool is renamed to bool, so C before C23 needs the macro from stdbool.h.
PROLOGUE = """
#ifdef __cplusplus
#pragma clang diagnostic push
/* The layout is C's, which is what the kernel uses. */
#pragma clang diagnostic ignored "-Wextern-c-compat"
extern "C" {
#elif !defined(bool) && \\
	(!defined(__STDC_VERSION__) || __STDC_VERSION__ < 202311L)
#define bool _Bool
#endif
"""

EPILOGUE = """#ifdef __cplusplus
}
#pragma clang diagnostic pop
#endif

"""

(INT, PTR, ARRAY, STRUCT, UNION, ENUM, FWD, TYPEDEF, VOLATILE, CONST,
 RESTRICT, FUNC, FUNC_PROTO, VAR, DATASEC, FLOAT, DECL_TAG, TYPE_TAG,
 ENUM64) = range(1, 20)

# Size of the data after struct btf_type, and of each of its vlen
# elements, for BTF without a layout section.
LAYOUT = {
    INT: (4, 0), PTR: (0, 0), ARRAY: (12, 0), STRUCT: (0, 12),
    UNION: (0, 12), ENUM: (0, 8), FWD: (0, 0), TYPEDEF: (0, 0),
    VOLATILE: (0, 0), CONST: (0, 0), RESTRICT: (0, 0), FUNC: (0, 0),
    FUNC_PROTO: (0, 8), VAR: (4, 0), DATASEC: (0, 12), FLOAT: (0, 0),
    DECL_TAG: (4, 0), TYPE_TAG: (0, 0), ENUM64: (0, 12),
}

# Kinds whose elements start with a name_off: members, enum values and
# function parameters.
NAMED_ELEMS = (STRUCT, UNION, ENUM, ENUM64, FUNC_PROTO)


class BTF:
    def __init__(self, data):
        # The byte order is the kernel's, e.g. big endian on s390x.
        self.e = {b"\x9f\xeb": "<", b"\xeb\x9f": ">"}.get(data[:2])
        if not self.e:
            sys.exit("not a raw BTF file")
        hdr_len, = struct.unpack_from(self.e + "I", data, 4)
        fields = struct.unpack_from(self.e + "I" * ((hdr_len - 8) // 4),
                                    data, 8)
        type_off, type_len, str_off, str_len = fields[:4]
        self.hdr = bytearray(data[:hdr_len])
        self.tdata = bytearray(data[hdr_len + type_off:
                                    hdr_len + type_off + type_len])
        self.strs = bytearray(data[hdr_len + str_off:
                                   hdr_len + str_off + str_len])
        self.layout_data = b""
        self.layout = dict(LAYOUT)
        if len(fields) >= 6 and fields[5]:
            layout_off, layout_len = fields[4:6]
            self.layout_data = data[hdr_len + layout_off:
                                    hdr_len + layout_off + layout_len]
            for kind in range(layout_len // 4):
                info_sz, elem_sz, _ = struct.unpack_from(
                    self.e + "BBH", self.layout_data, kind * 4)
                self.layout[kind] = (info_sz, elem_sz)
        # (offset in tdata, kind, vlen) by type id; id 0 is void.
        self.types = [None]
        off = 0
        while off < len(self.tdata):
            off += self._index(off)

    def _index(self, off):
        """Add the type at off to self.types and return its size."""
        _, info, _ = struct.unpack_from(self.e + "III", self.tdata, off)
        kind = (info >> 24) & 0x7F
        vlen = info & 0xFFFFFF
        if kind not in self.layout:
            sys.exit(f"unknown BTF kind {kind}")
        info_sz, elem_sz = self.layout[kind]
        self.types.append((off, kind, vlen))
        return 12 + info_sz + vlen * elem_sz

    def add_type(self, raw):
        """Append a type and return its id."""
        off = len(self.tdata)
        self.tdata += raw
        self._index(off)
        return len(self.types) - 1

    def type_raw(self, tid):
        off, kind, vlen = self.types[tid]
        info_sz, elem_sz = self.layout[kind]
        return self.tdata[off:off + 12 + info_sz + vlen * elem_sz]

    def str_at(self, off):
        return self.strs[off:self.strs.index(0, off)].decode()

    def add_str(self, s):
        off = len(self.strs)
        self.strs += s.encode() + b"\0"
        return off

    def u32(self, off):
        return struct.unpack_from(self.e + "I", self.tdata, off)[0]

    def set_u32(self, off, val):
        struct.pack_into(self.e + "I", self.tdata, off, val)

    def name(self, tid):
        return self.str_at(self.u32(self.types[tid][0]))

    def rename(self, name_pos, new):
        self.set_u32(name_pos, self.add_str(new))

    def elems(self, tid):
        """Offsets of each member, enum value or parameter, which all
        start with a name_off; a member continues with its type."""
        off, kind, vlen = self.types[tid]
        info_sz, elem_sz = self.layout[kind]
        base = off + 12 + info_sz
        return [base + i * elem_sz for i in range(vlen)]

    def raw(self):
        """The BTF as header, types, layout and strings, the order libbpf
        requires."""
        hdr = bytearray(self.hdr)
        types, layout = len(self.tdata), len(self.layout_data)
        struct.pack_into(self.e + "IIII", hdr, 8, 0, types, types + layout,
                         len(self.strs))
        if len(hdr) >= 32:
            struct.pack_into(self.e + "II", hdr, 24,
                             types if layout else 0, layout)
        return bytes(hdr + self.tdata + self.layout_data + self.strs)

def refs(btf, tid):
    """Positions of the type ids that a type refers to."""
    off, kind, _ = btf.types[tid]
    if kind in (PTR, TYPEDEF, VOLATILE, CONST, RESTRICT, FUNC, FUNC_PROTO,
                VAR, DECL_TAG, TYPE_TAG):
        yield off + 8
    if kind == ARRAY:
        yield off + 12
    if kind in (STRUCT, UNION, FUNC_PROTO):
        for pos in btf.elems(tid):
            yield pos + 4
    if kind == DATASEC:
        for pos in btf.elems(tid):
            yield pos


def target(btf, tid):
    """The type a typedef refers to, without modifiers."""
    while tid and btf.types[tid][1] in (TYPEDEF, VOLATILE, CONST,
                                       RESTRICT, TYPE_TAG):
        tid = btf.u32(btf.types[tid][0] + 8)
    return tid


def fix_names(btf):
    tags = {}
    typedefs = {}
    for tid in range(1, len(btf.types)):
        off, kind, _ = btf.types[tid]
        name = btf.name(tid)
        if kind in (STRUCT, UNION, ENUM, ENUM64, FWD) and name:
            tags.setdefault(name, []).append(tid)
        elif kind == TYPEDEF:
            typedefs.setdefault(name, []).append(tid)
        elif kind == INT and name == "_Bool":
            btf.rename(off, "bool")

    # Use the built-in bool for the typedef of _Bool to bool.
    for td in typedefs.get("bool", []):
        to = btf.u32(btf.types[td][0] + 8)
        for tid in range(1, len(btf.types)):
            for pos in refs(btf, tid):
                if btf.u32(pos) == td:
                    btf.set_u32(pos, to)

    for tid in range(1, len(btf.types)):
        off, kind, _ = btf.types[tid]
        name = btf.name(tid)
        if kind in (STRUCT, UNION, ENUM, ENUM64, FWD, TYPEDEF) and \
                name in CXX_KEYWORDS:
            btf.rename(off, name + SUFFIX)
        if kind in NAMED_ELEMS:
            for pos in btf.elems(tid):
                elem = btf.str_at(btf.u32(pos))
                if elem in CXX_KEYWORDS:
                    btf.rename(pos, elem + SUFFIX)

    # In C++, a typedef and a tag with the same name must be the same type.
    for name, tids in tags.items():
        if name in CXX_KEYWORDS:
            continue
        if any(target(btf, td) not in tids for td in typedefs.get(name, [])):
            for tid in tids:
                btf.rename(btf.types[tid][0], name + SUFFIX)


def anon_members(btf, tid):
    """Members of a struct or union with an unnamed struct or union type,
    as (position, type id)."""
    for pos in btf.elems(tid):
        mtid = btf.u32(pos + 4)
        if not btf.u32(pos) and btf.types[mtid][1] in (STRUCT, UNION):
            yield pos, mtid


def member_names(btf, tid):
    """Names of the members of a struct or union, including those of its
    anonymous members."""
    for pos in btf.elems(tid):
        if btf.u32(pos):
            yield btf.str_at(btf.u32(pos))
    for _, mtid in anon_members(btf, tid):
        yield from member_names(btf, mtid)


def fix_anon_members(btf):
    # An anonymous member of a named struct type (-fms-extensions) isn't
    # valid C++: make it an unnamed copy of the type, which bpftool
    # defines inline. CO-RE looks into anonymous members by field name.
    copies = {}
    tid = 1
    while tid < len(btf.types):
        if btf.types[tid][1] in (STRUCT, UNION):
            for pos, mtid in anon_members(btf, tid):
                if not btf.name(mtid):
                    continue
                if mtid not in copies:
                    raw = bytearray(btf.type_raw(mtid))
                    struct.pack_into(btf.e + "I", raw, 0, 0)
                    copies[mtid] = btf.add_type(raw)
                btf.set_u32(pos + 4, copies[mtid])
        tid += 1

    # Members of anonymous unions and structs can't have the name of the
    # class they are in.
    for tid in range(1, len(btf.types)):
        if btf.types[tid][1] in (STRUCT, UNION) and btf.name(tid):
            name = btf.name(tid)
            if any(name in member_names(btf, mtid)
                   for _, mtid in anon_members(btf, tid)):
                btf.rename(btf.types[tid][0], name + SUFFIX)


def member_positions(btf, tid):
    """Positions of the member types of a struct or union, including those
    of its anonymous members."""
    for pos in btf.elems(tid):
        yield pos + 4
    for _, mtid in anon_members(btf, tid):
        yield from member_positions(btf, mtid)


def renamed_typedef(btf, tid, names, copies):
    """tid, or a copy of it in which a typedef with a name from names is
    replaced with a renamed copy, through pointers and arrays."""
    off, kind, _ = btf.types[tid] if tid else (0, 0, 0)
    if kind == TYPEDEF:
        if btf.name(tid) not in names:
            return tid
        if tid not in copies:
            raw = bytearray(btf.type_raw(tid))
            struct.pack_into(btf.e + "I", raw, 0,
                             btf.add_str(btf.name(tid) + SUFFIX))
            copies[tid] = btf.add_type(raw)
        return copies[tid]
    if kind not in (ARRAY, PTR, VOLATILE, CONST, RESTRICT, TYPE_TAG):
        return tid
    pos = off + (12 if kind == ARRAY else 8)
    inner = btf.u32(pos)
    new = renamed_typedef(btf, inner, names, copies)
    if new == inner:
        return tid
    raw = bytearray(btf.type_raw(tid))
    struct.pack_into(btf.e + "I", raw, pos - off, new)
    return btf.add_type(raw)


def fix_hidden_typedefs(btf):
    # In C++, a member hides a typedef with the same name for the rest of
    # the class, as in "port_id port_id; port_id designated_port;". Use a
    # renamed copy of the typedef in that class.
    copies = {}
    for tid in range(1, len(btf.types)):
        if btf.types[tid][1] not in (STRUCT, UNION):
            continue
        names = set(member_names(btf, tid))
        for pos in list(member_positions(btf, tid)):
            mtid = btf.u32(pos)
            new = renamed_typedef(btf, mtid, names, copies)
            if new != mtid:
                btf.set_u32(pos, new)


def fix_empty_members(btf):
    # An empty struct has size 0 in C but 1 in C++, as in
    # "struct lock_class_key key;" without lockdep. Make such members and
    # arrays of them zero-length arrays, which have size 0 in both.
    index = next(tid for tid in range(1, len(btf.types))
                 if btf.types[tid][1] == INT)
    arrays = {}
    for tid in range(1, len(btf.types)):
        if btf.types[tid][1] not in (STRUCT, UNION):
            continue
        for pos in btf.elems(tid):
            # An anonymous member is defined inline, with its members.
            if not btf.u32(pos):
                continue
            mtid = btf.u32(pos + 4)
            elem = mtid
            if btf.types[target(btf, mtid)][1] == ARRAY:
                elem = btf.u32(btf.types[target(btf, mtid)][0] + 12)
            off, kind, _ = btf.types[target(btf, elem)]
            if kind not in (STRUCT, UNION) or btf.u32(off + 8):
                continue
            if elem not in arrays:
                arrays[elem] = btf.add_type(struct.pack(
                    btf.e + "IIIIII", 0, ARRAY << 24, 0, elem, index, 0))
            btf.set_u32(pos + 4, arrays[elem])


def fwd_enums(btf):
    """Underlying types of enums without values, by name."""
    types = {1: "char", 2: "short", 4: "int", 8: "long long"}
    for tid in range(1, len(btf.types)):
        off, kind, vlen = btf.types[tid]
        if kind in (ENUM, ENUM64) and not vlen:
            signed = btf.u32(off + 4) >> 31
            yield btf.name(tid), ("" if signed else "unsigned ") + \
                types[btf.u32(off + 8)]


def member_offsets(orig, btf, tid, base=0):
    """Names and byte offsets of the members of a struct or union,
    including those of its anonymous members, with the new names."""
    off, _, _ = orig.types[tid]
    bitfields = orig.u32(off + 4) >> 31
    for opos, npos in zip(orig.elems(tid), btf.elems(tid)):
        bits = orig.u32(opos + 8)
        if bitfields:
            if bits >> 24:
                continue
            bits &= 0xFFFFFF
        if bits % 8:
            continue
        name = btf.str_at(btf.u32(npos))
        mtid = orig.u32(opos + 4)
        if name:
            yield name, base + bits // 8
        elif orig.types[mtid][1] in (STRUCT, UNION):
            yield from member_offsets(orig, btf, mtid, base + bits // 8)


def layout_asserts(orig, btf):
    """static_asserts on the size and member offsets of each struct and
    union from the original BTF, with the new names, except for empty
    types, which have size 1 in C++, and names bpftool makes unique."""
    count = {}
    for tid in range(1, len(orig.types)):
        if orig.types[tid][1] in (STRUCT, UNION, ENUM, ENUM64) and \
                orig.name(tid):
            count[orig.name(tid)] = count.get(orig.name(tid), 0) + 1
    yield '#include "vmlinux.h"\n'
    for tid in range(1, len(orig.types)):
        off, kind, _ = orig.types[tid]
        size = orig.u32(off + 8)
        if kind not in (STRUCT, UNION) or count.get(orig.name(tid)) != 1 \
                or not size:
            continue
        t = ("struct " if kind == STRUCT else "union ") + btf.name(tid)
        yield f'static_assert(sizeof({t}) == {size}, "{t}");\n'
        for name, moff in member_offsets(orig, btf, tid):
            yield (f"static_assert(__builtin_offsetof({t}, {name}) == "
                   f'{moff}, "{t}.{name}");\n')

def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--bpftool", default="bpftool")
    ap.add_argument("--layout-asserts", action="store_true",
                    help="print static_asserts on the layout of the types "
                    "in vmlinux.h instead, to compare C and C++")
    ap.add_argument("btf", nargs="?", default="/sys/kernel/btf/vmlinux")
    args = ap.parse_args()

    data = open(args.btf, "rb").read()
    btf = BTF(data)
    fix_names(btf)
    fix_anon_members(btf)
    fix_hidden_typedefs(btf)
    fix_empty_members(btf)
    if args.layout_asserts:
        sys.stdout.writelines(layout_asserts(BTF(data), btf))
        return
    with tempfile.NamedTemporaryFile(suffix=".btf") as f:
        f.write(btf.raw())
        f.flush()
        out = subprocess.run([args.bpftool, "btf", "dump", "file", f.name,
                              "format", "c"], check=True,
                             stdout=subprocess.PIPE, text=True).stdout

    # C++ needs the underlying type in a declaration of an enum without a
    # definition.
    for name, underlying in fwd_enums(btf):
        out = out.replace(f"\nenum {name};\n",
                          f"\n#ifdef __cplusplus\nenum {name} : {underlying};"
                          f"\n#else\nenum {name};\n#endif\n")
    # Keep the kfunc declarations unmangled, and let C use bool.
    guard = "#define __VMLINUX_H__\n"
    end = "#endif /* __VMLINUX_H__ */\n"
    if guard not in out or not out.endswith(end):
        sys.exit("unexpected bpftool output")
    out = out.replace(guard, guard + PROLOGUE, 1)
    out = out[:-len(end)] + EPILOGUE + end
    sys.stdout.write(out)


main()
