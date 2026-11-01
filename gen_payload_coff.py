#!/usr/bin/env python3
"""Generate a valid x86-64 COFF object embedding a raw binary blob.

Symbols: _xray_payload_start (section offset 0), _xray_payload_end (offset N).
Zig/lld (mingw COFF) links this object directly.
"""
import struct, sys

blob_path, out_path = sys.argv[1], sys.argv[2]
blob = open(blob_path, "rb").read()
N = len(blob)

sec_name = b".rdata\x00\x00"
sym_names = [b"_xray_payload_start", b"_xray_payload_end"]

# string table offsets
offs = {}
acc = 4
for nm in sym_names:
    offs[nm] = acc
    acc += len(nm) + 1
STRINGS = b"".join(nm + b"\x00" for nm in sym_names)
n_syms = len(sym_names)

header_size = 20
sec_hdr_size = 40
data_off = header_size + sec_hdr_size
symtab_off = data_off + N
strtab = struct.pack("<I", 4 + len(STRINGS)) + STRINGS

out = bytearray()
out += struct.pack("<HHIIIHH",
    0x8664,            # Machine = x86-64
    1,                 # NumberOfSections
    0,                 # TimeDateStamp
    symtab_off,        # PointerToSymbolTable
    n_syms,            # NumberOfSymbols
    0,                 # SizeOfOptionalHeader
    0x0000)            # Characteristics (object)
out += sec_name + struct.pack("<IIIIIIHHI",
    0, 0,              # VirtualSize, VirtualAddress
    N, data_off,       # SizeOfRawData, PointerToRawData
    0, 0,              # relocs, linenums pointers
    0, 0,              # relocations, linenums counts
    0x40000040)        # INITIALIZED_DATA | MEM_READ
out += blob                      # section raw data at data_off = 60
for nm in sym_names:
    ent = bytearray(18)
    # llvm-конвенция длинного имени: первые 4 байта = 0, вторые 4 = бинарный offset в strtab
    ent[0:4] = b"\x00\x00\x00\x00"
    ent[4:8] = struct.pack("<I", offs[nm])
    ent[8:12] = struct.pack("<I", 0 if nm == b"_xray_payload_start" else N)  # Value
    ent[12:14] = struct.pack("<h", 1)        # SectionNumber
    ent[14:16] = struct.pack("<H", 0)        # Type
    ent[16] = 2                              # IMAGE_SYM_CLASS_EXTERNAL
    ent[17] = 0                              # NumberOfAuxSymbols
    out += bytes(ent)
out += strtab

open(out_path, "wb").write(bytes(out))
print(f"OK: {out_path}, blob {N} bytes, symbols {[n.decode() for n in sym_names]}")
