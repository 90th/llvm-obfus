#!/usr/bin/env python3

import struct
import sys
from pathlib import Path

MAGIC = 0x4353424F
RECORD_SIZE = 96
OFF_FLAGS = 0x08
OFF_FORMAT = 0x10
OFF_SITE = 0x18
OFF_DELTA = 0x20
OFF_TARGET_KIND = 0x28
OFF_SAMPLE_SIZE = 0x30
OFF_SEED = 0x38
OFF_EXPECTED = 0x40
FORMAT_PE = 2
TARGET_REL32 = 2


def u16(data, off):
    return struct.unpack_from("<H", data, off)[0]


def u32(data, off):
    return struct.unpack_from("<I", data, off)[0]


def u64(data, off):
    return struct.unpack_from("<Q", data, off)[0]


def parse(path):
    data = bytearray(Path(path).read_bytes())
    if data[:2] != b"MZ":
        raise SystemExit("not PE")
    pe = u32(data, 0x3C)
    if data[pe:pe + 4] != b"PE\0\0":
        raise SystemExit("bad PE signature")
    sections = u16(data, pe + 6)
    opt_size = u16(data, pe + 20)
    opt = pe + 24
    if u16(data, opt) != 0x20B:
        raise SystemExit("not PE32+")
    sec_off = opt + opt_size
    parsed = []
    for i in range(sections):
        off = sec_off + 40 * i
        name = bytes(data[off:off + 8]).split(b"\0", 1)[0].decode("ascii", "replace")
        virtual_size, rva, raw_size, raw_off = struct.unpack_from("<IIII", data, off + 8)
        characteristics = u32(data, off + 36)
        parsed.append((name, virtual_size, rva, raw_size, raw_off, characteristics))
    record_sections = [s for s in parsed if s[0] == ".obfsc"]
    if not record_sections:
        raise SystemExit("no self-checksum records")
    return data, parsed, record_sections


def map_exec(data, sections, rva, size):
    found = []
    for name, virtual_size, section_rva, raw_size, raw_off, characteristics in sections:
        if characteristics & 0x60000000 != 0x60000000:
            continue
        rel = rva - section_rva
        if rel < 0 or rel + size > virtual_size or rel + size > raw_size:
            continue
        found.append(raw_off + rel)
    if len(found) != 1:
        raise SystemExit("sample does not map uniquely to executable raw bytes")
    return found[0]


def checksum(raw, seed):
    h = seed ^ 0x9E3779B97F4A7C15
    for byte in raw:
        h = ((h ^ byte) * 1099511628211) & 0xFFFFFFFFFFFFFFFF
        h ^= h >> 27
    return h


def first_record(path):
    data, sections, record_sections = parse(path)
    name, virtual_size, record_rva, raw_size, raw_off, _ = record_sections[0]
    if virtual_size < RECORD_SIZE or u32(data, raw_off) != MAGIC:
        raise SystemExit("malformed self-checksum record")
    if u32(data, raw_off + OFF_FORMAT) != FORMAT_PE:
        raise SystemExit("unexpected record object format")
    if u32(data, raw_off + OFF_TARGET_KIND) != TARGET_REL32:
        raise SystemExit("unexpected record target kind")
    encoded = u64(data, raw_off + OFF_DELTA)
    if encoded >> 32:
        raise SystemExit("unexpected PE REL32 upper bits")
    delta = struct.unpack("<i", struct.pack("<I", encoded & 0xFFFFFFFF))[0]
    target_rva = record_rva + delta
    sample_size = u32(data, raw_off + OFF_SAMPLE_SIZE)
    sample_file = map_exec(data, sections, target_rva, sample_size)
    return data, raw_off, target_rva, sample_file, sample_size, name


def inspect(path):
    data, record, target_rva, sample_file, sample_size, name = first_record(path)
    expected = u64(data, record + OFF_EXPECTED)
    actual = checksum(data[sample_file:sample_file + sample_size], u64(data, record + OFF_SEED))
    print(
        "SELF_CHECKSUM_PE_RECORD"
        f" site={u64(data, record + OFF_SITE)}"
        f" flags=0x{u32(data, record + OFF_FLAGS):x}"
        f" expected=0x{expected:016x}"
        f" actual=0x{actual:016x}"
        f" target_rva=0x{target_rva:x}"
        f" file_offset=0x{sample_file:x}"
        f" section={name}"
    )


def tamper(path):
    data, record, target_rva, sample_file, sample_size, _ = first_record(path)
    expected = u64(data, record + OFF_EXPECTED)
    tamper_off = sample_file + min(4, sample_size - 1)
    before = data[tamper_off]
    data[tamper_off] ^= 1
    Path(path).write_bytes(data)
    actual = checksum(data[sample_file:sample_file + sample_size], u64(data, record + OFF_SEED))
    print(
        "SELF_CHECKSUM_PE_TAMPER"
        f" target_rva=0x{target_rva:x}"
        f" file_offset=0x{tamper_off:x}"
        f" before=0x{before:02x}"
        f" after=0x{data[tamper_off]:02x}"
        f" expected=0x{expected:016x}"
        f" tampered=0x{actual:016x}"
    )




def overlap_record_mapping(path):
    data = bytearray(Path(path).read_bytes())
    if data[:2] != b"MZ":
        raise SystemExit("not PE")
    pe = u32(data, 0x3C)
    sections = u16(data, pe + 6)
    opt_size = u16(data, pe + 20)
    sec_off = pe + 24 + opt_size

    record_header = None
    overlap_rva = None
    for i in range(sections):
        off = sec_off + 40 * i
        name = bytes(data[off:off + 8]).split(b"\0", 1)[0].decode("ascii", "replace")
        virtual_size = u32(data, off + 8)
        rva = u32(data, off + 12)
        if name == ".obfsc":
            record_header = off
        elif overlap_rva is None and virtual_size >= RECORD_SIZE:
            overlap_rva = rva

    if record_header is None or overlap_rva is None:
        raise SystemExit("cannot construct overlapping PE section mapping")
    struct.pack_into("<I", data, record_header + 12, overlap_rva)
    Path(path).write_bytes(data)
    print("SELF_CHECKSUM_PE_OVERLAPPED_RECORD_MAPPING")

def mark_header_checksum(path):
    data = bytearray(Path(path).read_bytes())
    pe = u32(data, 0x3C)
    opt = pe + 24
    struct.pack_into("<I", data, opt + 64, 1)
    Path(path).write_bytes(data)
    print("SELF_CHECKSUM_PE_MARKED_HEADER_CHECKSUM")


def mark_signed(path):
    data = bytearray(Path(path).read_bytes())
    pe = u32(data, 0x3C)
    opt = pe + 24
    number_of_dirs = u32(data, opt + 108)
    if number_of_dirs <= 4:
        raise SystemExit("PE security directory is unavailable")
    security = opt + 112 + 4 * 8
    struct.pack_into("<II", data, security, len(data), 8)
    Path(path).write_bytes(data)
    print("SELF_CHECKSUM_PE_MARKED_SECURITY_DIRECTORY")

def main():
    if len(sys.argv) != 3 or sys.argv[1] not in {
        "inspect", "tamper", "overlap-record", "mark-checksum", "mark-signed"
    }:
        raise SystemExit(
            "usage: self_checksum_pe_tool.py "
            "<inspect|tamper|overlap-record|mark-checksum|mark-signed> <pe>"
        )
    if sys.argv[1] == "inspect":
        inspect(sys.argv[2])
    elif sys.argv[1] == "tamper":
        tamper(sys.argv[2])
    elif sys.argv[1] == "overlap-record":
        overlap_record_mapping(sys.argv[2])
    elif sys.argv[1] == "mark-checksum":
        mark_header_checksum(sys.argv[2])
    else:
        mark_signed(sys.argv[2])


if __name__ == "__main__":
    main()
