#!/usr/bin/env python3
"""Дамп структуры COFF-объекта: наш payload vs эталон от zig."""
import struct, sys

def dump(path):
    d = open(path, "rb").read()
    mach, nsec, ts, symptr, nsyms, opt, chars = struct.unpack("<HHIIIHH", d[0:20])
    print(f"{path}: mach={mach:#x} nsec={nsec} symptr={symptr} nsyms={nsyms} opt={opt} chars={chars:#x} size={len(d)}")
    for i in range(nsec):
        off = 20 + i * 40
        nm = d[off:off+8].rstrip(b"\x00")
        vsz, va, rawsz, rawptr, relptr, lnptr, nrel, nln, ch = struct.unpack("<IIIIIIHHI", d[off+8:off+40])
        print(f"  sec {nm.decode(errors='replace'):10s} rawsz={rawsz} rawptr={rawptr} nrel={nrel} chars={ch:#x}")
    off = symptr
    for i in range(nsyms):
        nm = d[off:off+8]
        (val,) = struct.unpack("<I", d[off+8:off+12])
        sec, typ = struct.unpack("<hH", d[off+12:off+16])
        cls, aux = d[off+16], d[off+17]
        print(f"  sym[{i}] name={nm!r} val={val} sec={sec} type={typ} class={cls} aux={aux}")
        off += 18 * (1 + aux)
    (stsz,) = struct.unpack("<I", d[off:off+4])
    print(f"  strtab size={stsz} first={d[off+4:off+4+min(stsz,40)]!r}")

for p in sys.argv[1:]:
    dump(p)
