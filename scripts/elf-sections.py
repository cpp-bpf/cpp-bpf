#!/usr/bin/env python3
# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
"""Print the SHA-256 of each section of a 64-bit little-endian ELF file,
except BTF and debug info, whose type order and paths may differ between
otherwise identical builds."""

import hashlib
import struct
import sys

SKIP = (".BTF", ".debug_", ".rel.debug_", ".rela.debug_", ".rel.BTF")


def sections(path):
    data = open(path, "rb").read()
    if data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
        sys.exit(f"{path}: not a 64-bit little-endian ELF file")
    shoff, = struct.unpack_from("<Q", data, 0x28)
    shentsize, shnum, shstrndx = struct.unpack_from("<HHH", data, 0x3A)

    def header(i):
        return struct.unpack_from("<IIQQQQIIQQ", data, shoff + i * shentsize)

    stroff = header(shstrndx)[4]
    for i in range(1, shnum):
        name_off, sh_type, _, _, off, size = header(i)[:6]
        end = data.index(b"\0", stroff + name_off)
        name = data[stroff + name_off:end].decode()
        if name == ".BTF" or name.startswith(SKIP):
            continue
        body = b"" if sh_type == 8 else data[off:off + size]  # SHT_NOBITS
        yield name, hashlib.sha256(body).hexdigest()


for name, digest in sections(sys.argv[1]):
    print(name, digest)
