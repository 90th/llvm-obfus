#!/usr/bin/env python3
import argparse
import shutil
import struct
import subprocess
from pathlib import Path

from self_checksum_elf_tool import checksum, i64, parse_elf, records, u16, u64

UINT64_MAX = (1 << 64) - 1
TIMEOUT_SECONDS = 30


def state(path):
    stat = path.stat()
    return path.read_bytes(), stat.st_mode, stat.st_ino, stat.st_mtime_ns


def run(command, expected=0):
    result = subprocess.run(
        command, capture_output=True, text=True, timeout=TIMEOUT_SECONDS
    )
    if result.returncode != expected:
        raise RuntimeError(f"unexpected exit status for {command}: {result}")


def unchanged(command, image, expected=0):
    before = state(image)
    run(command, expected)
    if state(image) != before:
        raise RuntimeError(f"command modified the image: {command}")


def copy_image(image, suffix, data):
    copy = image.with_name(image.name + suffix)
    shutil.copy2(image, copy)
    copy.write_bytes(data)
    return copy


def inspect_records(data, reference, flags):
    observed = records(data)
    if len(observed) != len(reference):
        raise RuntimeError("record count changed")
    for record, control in zip(observed, reference):
        for key in ("site", "target", "sample_size", "seed", "file_offset"):
            if record[key] != control[key]:
                raise RuntimeError(f"record {key} changed")
        expected = control["expected"] if flags == 3 else 0
        if record["flags"] != flags or record["expected"] != expected:
            raise RuntimeError("record binding state changed")
        start, size = record["file_offset"], record["sample_size"]
        sample = data[start:start + size]
        if len(sample) != size or checksum(sample, record["seed"]) != control["expected"]:
            raise RuntimeError("record sample no longer matches the bound control")


def record_segment(segments, section):
    end = section[3] + section[5]
    if end > UINT64_MAX:
        raise RuntimeError("record virtual range overflows")
    matches = []
    for index, segment in enumerate(segments):
        if segment[0] != 1:
            continue
        segment_end = segment[3] + segment[5]
        if segment_end > UINT64_MAX:
            raise RuntimeError("PT_LOAD virtual range overflows")
        if segment[3] <= section[3] and end <= segment_end:
            matches.append((index, segment))
    if len(matches) != 1:
        raise RuntimeError("records must have one file-backed PT_LOAD")
    index, segment = matches[0]
    if not (segment[1] & 4) or segment[1] & 2:
        raise RuntimeError("record PT_LOAD must be readable and non-writable")
    return index, segment


def inspect_mapping(data, kind):
    record_sections, segments = parse_elf(data)
    for _, section in record_sections:
        _, segment = record_segment(segments, section)
        offset, size = section[4], section[5]
        mapped = segment[2] + section[3] - segment[3]
        if kind == "overflow":
            if mapped <= UINT64_MAX or (mapped & UINT64_MAX) != offset:
                raise RuntimeError("unchecked mapping must wrap to the section offset")
            continue
        if mapped + size > len(data) or offset + size > len(data):
            raise RuntimeError("record bytes must remain inside the file")
        if kind == "valid":
            if mapped != offset:
                raise RuntimeError("valid records disagree with their load mapping")
        else:
            if mapped == offset or data[mapped:mapped + size] != data[offset:offset + size]:
                raise RuntimeError("detached records must duplicate distinct loaded bytes")
            for load in segments:
                if load[0] == 1 and offset < load[2] + load[5] and load[2] < offset + size:
                    raise RuntimeError("detached records must not be loaded")


def detached_records(source):
    data = bytearray(source)
    record_sections, _ = parse_elf(data)
    section_table, section_count = u64(data, 40), u16(data, 60)
    for _, section in record_sections:
        index = next(
            index for index in range(section_count)
            if struct.unpack_from("<IIQQQQIIQQ", data, section_table + index * 64) == section
        )
        duplicate_offset = len(data)
        data.extend(data[section[4]:section[4] + section[5]])
        struct.pack_into("<Q", data, section_table + index * 64 + 24, duplicate_offset)
    return data


def overflowing_records(source):
    data = bytearray(source)
    record_sections, segments = parse_elf(data)
    if len(record_sections) != 1:
        raise RuntimeError("overflow control requires one record section")
    _, section = record_sections[0]
    segment_index, segment = record_segment(segments, section)
    if segment[1] & 1:
        raise RuntimeError("overflow control must not change the sample's executable mapping")

    # Make unchecked p_offset + VA delta wrap to the correct section offset.
    # Shift PIE record addresses only when necessary, preserving alignment and targets.
    alignment = max(1, section[8])
    minimum_shift = max(0, section[4] + 1 - section[3])
    shift = (minimum_shift + alignment - 1) // alignment * alignment
    address = section[3] + shift
    virtual_base = address - section[4] - 1
    section_table, section_count = u64(data, 40), u16(data, 60)
    section_index = next(
        index for index in range(section_count)
        if struct.unpack_from("<IIQQQQIIQQ", data, section_table + index * 64) == section
    )
    for record in records(source):
        delta = i64(source, record["offset"] + 32)
        struct.pack_into("<q", data, record["offset"] + 32, delta - shift)
    struct.pack_into("<Q", data, section_table + section_index * 64 + 16, address)
    struct.pack_into(
        "<IIQQQQQQ", data, u64(data, 32) + segment_index * 56,
        segment[0], segment[1], UINT64_MAX, virtual_base, virtual_base,
        segment[3] + segment[5] + shift - virtual_base,
        segment[3] + segment[6] + shift - virtual_base, 1,
    )
    return data


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binder", required=True)
    parser.add_argument("--image", required=True, type=Path)
    args = parser.parse_args()
    image = args.image
    original = state(image)
    bound = records(original[0])
    inspect_records(original[0], bound, 3)
    inspect_mapping(original[0], "valid")
    unchanged([args.binder, "--probe", str(image)], image)
    unchanged([args.binder, str(image)], image)
    run([str(image)])

    unbound = bytearray(original[0])
    for record in bound:
        struct.pack_into("<I", unbound, record["offset"] + 8, 1)
        struct.pack_into("<Q", unbound, record["offset"] + 64, 0)
    inspect_records(unbound, bound, 1)
    inspect_mapping(unbound, "valid")
    control = copy_image(image, ".unbound-control", unbound)
    unchanged([args.binder, "--probe", str(control)], control)
    run([args.binder, str(control)])
    if control.read_bytes() != original[0] or control.stat().st_mode != original[1]:
        raise RuntimeError("initial binding did not restore the bound control")
    inspect_records(control.read_bytes(), bound, 3)
    unchanged([args.binder, str(control)], control)
    run([str(control)])

    for flags, source in ((1, unbound), (3, original[0])):
        detached = detached_records(source)
        inspect_records(detached, bound, flags)
        inspect_mapping(detached, "detached")
        malformed = copy_image(image, f".detached-{flags}", detached)
        unchanged([args.binder, "--probe", str(malformed)], malformed, 1)
        unchanged([args.binder, str(malformed)], malformed, 1)

    overflow = overflowing_records(original[0])
    inspect_records(overflow, bound, 3)
    inspect_mapping(overflow, "overflow")
    malformed = copy_image(image, ".mapping-overflow", overflow)
    unchanged([args.binder, "--probe", str(malformed)], malformed, 1)
    unchanged([args.binder, str(malformed)], malformed, 1)


if __name__ == "__main__":
    main()
