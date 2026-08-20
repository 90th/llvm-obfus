#!/usr/bin/env python3
import argparse
import struct
from pathlib import Path

MAGIC = 0x4353424F
VERSION = 1
RECORD_SIZE = 96
FLAG_REQUIRED = 1
FLAG_BOUND = 2
SECTION_PREFIX = ".obfsc"


def u16(data, off):
    return struct.unpack_from("<H", data, off)[0]


def u32(data, off):
    return struct.unpack_from("<I", data, off)[0]


def u64(data, off):
    return struct.unpack_from("<Q", data, off)[0]


def i64(data, off):
    return struct.unpack_from("<q", data, off)[0]


def checksum(blob, seed):
    h = (seed ^ 0x9E3779B97F4A7C15) & 0xFFFFFFFFFFFFFFFF
    for byte in blob:
        h = ((h ^ byte) * 1099511628211) & 0xFFFFFFFFFFFFFFFF
        h ^= h >> 27
    return h & 0xFFFFFFFFFFFFFFFF


def parse_elf(data):
    if data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
        raise SystemExit("expected little-endian ELF64")
    e_type, e_machine = struct.unpack_from("<HH", data, 16)
    if e_type not in (2, 3) or e_machine != 62:
        raise SystemExit("expected final x86-64 ELF")
    e_phoff = u64(data, 32)
    e_shoff = u64(data, 40)
    e_phentsize, e_phnum = struct.unpack_from("<HH", data, 54)
    e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", data, 58)
    if e_phentsize != 56 or e_shentsize != 64 or not e_phnum or not e_shnum:
        raise SystemExit("unsupported ELF tables")

    sections = []
    for index in range(e_shnum):
        off = e_shoff + index * e_shentsize
        fields = struct.unpack_from("<IIQQQQIIQQ", data, off)
        sections.append(fields)
    shstr = sections[e_shstrndx]
    names = data[shstr[4] : shstr[4] + shstr[5]]

    def section_name(name_off):
        end = names.find(b"\0", name_off)
        if end < 0:
            raise SystemExit("bad section name")
        return names[name_off:end].decode("ascii", "strict")

    record_sections = []
    for section in sections:
        name = section_name(section[0])
        if name == SECTION_PREFIX or name.startswith(SECTION_PREFIX + "."):
            record_sections.append((name, section))

    segments = []
    for index in range(e_phnum):
        off = e_phoff + index * e_phentsize
        segments.append(struct.unpack_from("<IIQQQQQQ", data, off))
    return record_sections, segments


def map_file(segments, va, size):
    matches = []
    for p_type, p_flags, p_offset, p_vaddr, _p_paddr, p_filesz, _p_memsz, _align in segments:
        if p_type != 1 or not (p_flags & 1):
            continue
        if p_vaddr <= va and va + size <= p_vaddr + p_filesz:
            matches.append(p_offset + (va - p_vaddr))
    if len(matches) != 1:
        raise SystemExit(f"target maps to {len(matches)} executable segments")
    return matches[0]


def records(data):
    record_sections, segments = parse_elf(data)
    result = []
    for section_name, section in record_sections:
        sh_addr, sh_offset, sh_size = section[3], section[4], section[5]
        if not sh_size or sh_size % RECORD_SIZE:
            raise SystemExit("bad self-checksum section size")
        for rel in range(0, sh_size, RECORD_SIZE):
            off = sh_offset + rel
            if u32(data, off) != MAGIC or u16(data, off + 4) != VERSION or u16(data, off + 6) != RECORD_SIZE:
                raise SystemExit("bad self-checksum record header")
            flags = u32(data, off + 8)
            site = u64(data, off + 24)
            target = sh_addr + rel + i64(data, off + 32)
            sample_offset = u32(data, off + 44)
            sample_size = u32(data, off + 48)
            seed = u64(data, off + 56)
            expected = u64(data, off + 64)
            file_off = map_file(segments, target + sample_offset, sample_size)
            result.append(
                dict(
                    section=section_name,
                    offset=off,
                    flags=flags,
                    site=site,
                    target=target,
                    sample_size=sample_size,
                    seed=seed,
                    expected=expected,
                    file_offset=file_off,
                )
            )
    if not result:
        raise SystemExit("no self-checksum records")
    return result


def inspect(path):
    data = path.read_bytes()
    for record in records(data):
        print(
            "SELF_CHECKSUM_TEST_RECORD "
            f"site={record['site']} flags=0x{record['flags']:x} "
            f"expected=0x{record['expected']:016x} target_va=0x{record['target']:x} "
            f"file_offset=0x{record['file_offset']:x} section={record['section']}"
        )


def tamper(path):
    data = bytearray(path.read_bytes())
    record = records(data)[0]
    if record["flags"] != (FLAG_REQUIRED | FLAG_BOUND):
        raise SystemExit("record must be bound before tampering")
    start = record["file_offset"]
    size = record["sample_size"]
    expected = record["expected"]
    original_sample = bytes(data[start : start + size])
    if checksum(original_sample, record["seed"]) != expected:
        raise SystemExit("bound file does not match its expected checksum before tamper")

    for index in range(size):
        original = data[start + index]
        for mask in (1, 2, 4, 8, 16, 32, 64, 128):
            data[start + index] = original ^ mask
            actual = checksum(bytes(data[start : start + size]), record["seed"])
            if actual != expected and ((actual ^ expected) & 0xFFFFFFFF) != 0:
                path.write_bytes(data)
                print(
                    "SELF_CHECKSUM_TEST_TAMPER "
                    f"file_offset=0x{start + index:x} old=0x{original:02x} "
                    f"new=0x{data[start + index]:02x} expected=0x{expected:016x} "
                    f"tampered=0x{actual:016x}"
                )
                return
            data[start + index] = original
    raise SystemExit("could not find a deterministic low-32-bit-changing tamper")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("inspect", "tamper"))
    parser.add_argument("path", type=Path)
    args = parser.parse_args()
    if args.command == "inspect":
        inspect(args.path)
    else:
        tamper(args.path)


if __name__ == "__main__":
    main()
