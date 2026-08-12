#!/usr/bin/env python3
"""produce a conservative binary-only structural recovery report for elf64 x86-64 artifacts."""

from __future__ import annotations

import argparse
import collections
import dataclasses
import errno
import hashlib
import json
import os
import pathlib
import re
import selectors
import stat
import struct
import subprocess
import sys
import time
from typing import Any, Iterable, Sequence


SCHEMA_VERSION = 1
ELF_HEADER_SIZE = 64
PROGRAM_HEADER_SIZE = 56
SECTION_HEADER_SIZE = 64
DYNAMIC_ENTRY_SIZE = 16
SYMBOL_ENTRY_SIZE = 24
RELA_ENTRY_SIZE = 24
REL_ENTRY_SIZE = 16
ELF64_CLASS = 2
LITTLE_ENDIAN = 1
CURRENT_VERSION = 1
ET_EXEC = 2
ET_DYN = 3
EM_X86_64 = 62
PT_LOAD = 1
PT_DYNAMIC = 2
PF_X = 1
PF_W = 2
PF_R = 4
SHT_SYMTAB = 2
SHT_RELA = 4
SHT_DYNAMIC = 6
SHT_NOBITS = 8
SHT_REL = 9
SHT_DYNSYM = 11
PN_XNUM = 0xFFFF
SHN_XINDEX = 0xFFFF
UINT64_LIMIT = 1 << 64
MAX_ARTIFACT_BYTES = 128 * 1024 * 1024
MAX_TABLE_ENTRIES = 1_000_000
MAX_INSTRUCTIONS = 1_500_000
MAX_BASIC_BLOCKS = 500_000
MAX_POINTER_SCAN_BYTES = 16 * 1024 * 1024
MAX_POINTER_TABLES = 2_048
MAX_CANDIDATES = 1_024
MAX_HANDLER_BODY_BLOCKS = 2_048
MAX_HANDLER_OWNERSHIP_TRAVERSALS = 16_384
MAX_INDIRECT_PREDECESSOR_BLOCKS = 96
MAX_INDIRECT_PREDECESSOR_INSTRUCTIONS = 4_096
MAX_INDIRECT_RECOVERY_SPAN = 0x20_000
MAX_INDIRECT_FLOW_TOKENS = 256
MAX_TOOL_OUTPUT_BYTES = 64 * 1024 * 1024
TOOL_TIMEOUT_SECONDS = 30.0
INDIRECT_CALL_OBSERVATION_CONTROL_SCORE = 4
SHARED_HANDLER_PATH_STORAGES = frozenset(
    ("shared_handler_path_dynamic_memory", "shared_handler_path_mapped_data")
)



@dataclasses.dataclass(frozen=True)
class Issue:
    code: str
    severity: str

    def as_dict(self) -> dict[str, str]:
        return {"code": self.code, "severity": self.severity}


@dataclasses.dataclass(frozen=True)
class LoadSegment:
    index: int
    offset: int
    vaddr: int
    filesz: int
    memsz: int
    flags: int
    align: int

    @property
    def file_end(self) -> int:
        return self.offset + self.filesz

    @property
    def memory_end(self) -> int:
        return self.vaddr + self.memsz

    @property
    def executable(self) -> bool:
        return bool(self.flags & PF_X)

    @property
    def readable(self) -> bool:
        return bool(self.flags & PF_R)

    @property
    def writable(self) -> bool:
        return bool(self.flags & PF_W)


@dataclasses.dataclass(frozen=True)
class SectionHeader:
    index: int
    section_type: int
    flags: int
    addr: int
    offset: int
    size: int
    link: int
    info: int
    addralign: int
    entsize: int


@dataclasses.dataclass
class ParsedElf:
    supported: bool
    usable: bool
    elf_type: int | None
    entry: int | None
    loads: list[LoadSegment]
    sections: list[SectionHeader]
    metadata: dict[str, int]
    issues: list[Issue]


@dataclasses.dataclass(frozen=True)
class ArtifactBytes:
    data: bytes | None
    sha256: str | None
    size: int
    issues: tuple[Issue, ...]


@dataclasses.dataclass(frozen=True)
class ToolResult:
    outcome: str
    stdout: bytes


@dataclasses.dataclass(frozen=True)
class Instruction:
    address: int
    mnemonic: str
    operands: str
    direct_target: int | None
    is_call: bool
    is_jump: bool
    is_conditional_jump: bool
    is_indirect: bool
    is_return: bool
    is_trap: bool
    registers: frozenset[str]
    writes: frozenset[str]
    stack_read: bool
    stack_write: bool
    data_refs: tuple[int, ...]
    data_write_refs: tuple[int, ...]


@dataclasses.dataclass
class BasicBlock:
    index: int
    instructions: tuple[Instruction, ...]
    successors: list[int]
    unknown_successor: bool
    terminator: str
    region: int = -1
    scc: int = -1

    @property
    def start(self) -> int:
        return self.instructions[0].address

    @property
    def end(self) -> int:
        return self.instructions[-1].address

    @property
    def registers(self) -> set[str]:
        return set().union(*(instruction.registers for instruction in self.instructions))

    @property
    def writes(self) -> set[str]:
        return set().union(*(instruction.writes for instruction in self.instructions))

    @property
    def stack_read(self) -> bool:
        return any(instruction.stack_read for instruction in self.instructions)

    @property
    def stack_write(self) -> bool:
        return any(instruction.stack_write for instruction in self.instructions)

    @property
    def data_refs(self) -> set[int]:
        return set().union(*(set(instruction.data_refs) for instruction in self.instructions))

    @property
    def data_write_refs(self) -> set[int]:
        return set().union(*(set(instruction.data_write_refs) for instruction in self.instructions))


@dataclasses.dataclass
class FunctionRegion:
    index: int
    blocks: tuple[int, ...]
    roots: tuple[int, ...]


@dataclasses.dataclass
class DataRegion:
    kind: str
    start: int
    end: int
    segment_index: int
    writable: bool
    pointer_targets: tuple[int, ...] = ()
    index: int = -1
    pointer_width: int = 0


@dataclasses.dataclass
class DispatcherEvidence:
    key: tuple[Any, ...]
    selection_blocks: tuple[int, ...]
    target_blocks: tuple[int, ...]
    table_regions: tuple[int, ...]
    indirect: bool
    recurrent: bool
    region: int
    immediate_target_addresses: tuple[int, ...] = ()
    immediate_selection_blocks: tuple[int, ...] = ()
    target_recovery_limited: bool = False
    immediate_source_blocks: tuple[int, ...] = ()


@dataclasses.dataclass(frozen=True)
class IndirectTargetRecovery:
    branch_block: int
    target_addresses: tuple[int, ...]
    target_blocks: tuple[int, ...]
    selection_blocks: tuple[int, ...]
    source_blocks: tuple[int, ...]
    limited: bool


@dataclasses.dataclass(frozen=True)
class IndirectCallTableReference:
    table_access_address: int
    operand_provenance: str
    index_provenance: str


@dataclasses.dataclass(frozen=True)
class IndirectCallEvidence:
    call_block: int
    table_region: int
    table_access_address: int
    operand_provenance: str
    index_provenance: str
    potential_target_blocks: tuple[int, ...]

@dataclasses.dataclass
class HandlerEvidence:
    dispatcher_key: tuple[Any, ...]
    entry_block: int
    body_blocks: tuple[int, ...]
    reenters: bool
    candidate_id: str = ""


@dataclasses.dataclass
class StateEvidence:
    dispatcher_key: tuple[Any, ...]
    storage: str
    update_handlers: tuple[tuple[Any, ...], ...]
    data_region: int | None
    candidate_id: str = ""


@dataclasses.dataclass
class DataEvidence:
    dispatcher_key: tuple[Any, ...]
    region_index: int | None
    handler_keys: tuple[tuple[Any, ...], ...]
    state_keys: tuple[tuple[Any, ...], ...]
    dispatch_reference: bool
    table_target_handlers: tuple[tuple[Any, ...], ...]
    storage: str = "mapped_data"
    consumption_modes: tuple[str, ...] = ()
    linked_handler_keys: tuple[tuple[Any, ...], ...] = ()
    limitations: tuple[str, ...] = ()
    candidate_id: str = ""


ADDRESS_HEX_WIDTH = 16
INSTRUCTION_LINE = re.compile(r"^\s*(?P<address>[0-9A-Fa-f]+):\s*(?P<body>.*?)\s*$")
LEADING_BYTES = re.compile(r"^(?:(?:[0-9A-Fa-f]{2})\s+)+(?P<assembly>[A-Za-z.][^\n]*)$")
DIRECT_OPERAND = re.compile(r"^\s*\$?(?:0x)?(?P<address>[0-9A-Fa-f]+)\b")
COMMENT_ADDRESS = re.compile(r"#\s*(?:0x)?(?P<address>[0-9A-Fa-f]+)\b")
OPERAND_SYMBOL = re.compile(r"<[^>]*>")
REGISTER_PATTERN = re.compile(r"%([A-Za-z][A-Za-z0-9]*)")
IMMEDIATE_OPERAND = re.compile(r"(?:^|[\s,])\$(?:0x)?(?P<address>[0-9A-Fa-f]+)\b")
MEMORY_DISPLACEMENT = re.compile(
    r"(?:^|,)\s*\*?\s*(?P<address>0[xX][0-9A-Fa-f]+)\s*"
    r"\((?P<fields>[^)]*)\)(?=\s*(?:,|$))"
)
MEMORY_ADDRESSING = re.compile(r"\((?P<fields>[^)]*)\)")


REGISTER_ALIASES = {
    "al": "rax", "ah": "rax", "ax": "rax", "eax": "rax", "rax": "rax",
    "bl": "rbx", "bh": "rbx", "bx": "rbx", "ebx": "rbx", "rbx": "rbx",
    "cl": "rcx", "ch": "rcx", "cx": "rcx", "ecx": "rcx", "rcx": "rcx",
    "dl": "rdx", "dh": "rdx", "dx": "rdx", "edx": "rdx", "rdx": "rdx",
    "sil": "rsi", "si": "rsi", "esi": "rsi", "rsi": "rsi",
    "dil": "rdi", "di": "rdi", "edi": "rdi", "rdi": "rdi",
    "bpl": "rbp", "bp": "rbp", "ebp": "rbp", "rbp": "rbp",
    "spl": "rsp", "sp": "rsp", "esp": "rsp", "rsp": "rsp",
    "eip": "rip", "rip": "rip",
}
for _number in range(8, 16):
    REGISTER_ALIASES[f"r{_number}"] = f"r{_number}"
    REGISTER_ALIASES[f"r{_number}b"] = f"r{_number}"
    REGISTER_ALIASES[f"r{_number}w"] = f"r{_number}"
    REGISTER_ALIASES[f"r{_number}d"] = f"r{_number}"


WRITE_PREFIXES = (
    "add", "adc", "and", "bsf", "bsr", "btc", "btr", "bts", "cmov", "dec",
    "imul", "inc", "lea", "mov", "neg", "not", "or", "pop", "rol", "ror", "sal",
    "sar", "sbb", "set", "shl", "shr", "sub", "xor", "xadd", "xchg",
)
NO_DESTINATION_WRITE_PREFIXES = ("cmp", "test", "bt", "call", "jmp", "j", "ret", "push")

NON_DATA_MEMORY_READ_PREFIXES = (
    "lea", "nop", "prefetch", "clflush", "clwb", "cldemote", "invlpg",
    "invpcid", "invept", "invvpid",
)


def address_id(address: int) -> str:
    return f"va:{address:0{ADDRESS_HEX_WIDTH}x}"


def range_dict(start: int, end: int) -> dict[str, str]:
    return {"end": address_id(end), "start": address_id(start)}


def segment_flags(flags: int) -> str:
    return "".join(("r" if flags & PF_R else "-", "w" if flags & PF_W else "-", "x" if flags & PF_X else "-"))


def unique_issues(issues: Iterable[Issue]) -> list[Issue]:
    return [Issue(code, severity) for code, severity in sorted({(item.code, item.severity) for item in issues})]


def checked_range(length: int, offset: int, size: int) -> bool:
    return offset >= 0 and size >= 0 and offset <= length and size <= length - offset


def checked_table(length: int, offset: int, entry_size: int, count: int) -> bool:
    return entry_size >= 0 and count >= 0 and checked_range(length, offset, entry_size * count)


def valid_u64_range(start: int, size: int) -> bool:
    return 0 <= start < UINT64_LIMIT and 0 <= size <= UINT64_LIMIT and start + size <= UINT64_LIMIT


def is_power_of_two(value: int) -> bool:
    return value > 0 and value & (value - 1) == 0


def empty_metadata() -> dict[str, int]:
    return {
        "dynamic_entries": 0,
        "dynamic_tables": 0,
        "dynamic_symbols": 0,
        "relocation_entries": 0,
        "relocation_tables": 0,
        "section_headers": 0,
        "static_symbols": 0,
    }


def unsupported_elf(issues: list[Issue]) -> ParsedElf:
    return ParsedElf(False, False, None, None, [], [], empty_metadata(), unique_issues(issues))


def parse_section_zero(data: bytes, shoff: int, shentsize: int, issues: list[Issue]) -> tuple[int, ...] | None:
    if shoff == 0:
        return None
    if shentsize != SECTION_HEADER_SIZE:
        issues.append(Issue("malformed_section_header_size", "error"))
        return None
    if not checked_range(len(data), shoff, SECTION_HEADER_SIZE):
        issues.append(Issue("truncated_section_header_table", "error"))
        return None
    return struct.unpack_from("<IIQQQQIIQQ", data, shoff)


def parse_sections(
    data: bytes,
    shoff: int,
    shentsize: int,
    declared_count: int,
    section_zero: tuple[int, ...] | None,
    issues: list[Issue],
) -> tuple[list[SectionHeader], int]:
    actual_count = declared_count
    if declared_count == 0 and section_zero is not None and shoff != 0:
        actual_count = section_zero[5]
    if actual_count == 0:
        return [], 0
    if shoff == 0:
        issues.append(Issue("missing_section_header_table", "error"))
        return [], actual_count
    if shentsize != SECTION_HEADER_SIZE:
        issues.append(Issue("malformed_section_header_size", "error"))
        return [], actual_count
    if actual_count > MAX_TABLE_ENTRIES:
        issues.append(Issue("section_header_count_limit", "error"))
        return [], actual_count
    if not checked_table(len(data), shoff, shentsize, actual_count):
        issues.append(Issue("truncated_section_header_table", "error"))
        return [], actual_count
    sections: list[SectionHeader] = []
    for index in range(actual_count):
        values = struct.unpack_from("<IIQQQQIIQQ", data, shoff + index * shentsize)
        _, section_type, flags, addr, offset, size, link, info, addralign, entsize = values
        if section_type != SHT_NOBITS and not checked_range(len(data), offset, size):
            issues.append(Issue("section_range_out_of_bounds", "error"))
            continue
        if not valid_u64_range(addr, size):
            issues.append(Issue("section_address_range_invalid", "error"))
            continue
        sections.append(
            SectionHeader(index, section_type, flags, addr, offset, size, link, info, addralign, entsize)
        )
    return sections, actual_count


def parse_loads(
    data: bytes,
    phoff: int,
    phentsize: int,
    phnum: int,
    issues: list[Issue],
) -> list[LoadSegment]:
    if phnum == 0:
        issues.append(Issue("missing_program_headers", "error"))
        return []
    if phentsize != PROGRAM_HEADER_SIZE:
        issues.append(Issue("malformed_program_header_size", "error"))
        return []
    if phnum > MAX_TABLE_ENTRIES:
        issues.append(Issue("program_header_count_limit", "error"))
        return []
    if not checked_table(len(data), phoff, phentsize, phnum):
        issues.append(Issue("truncated_program_header_table", "error"))
        return []
    loads: list[LoadSegment] = []
    for index in range(phnum):
        values = struct.unpack_from("<IIQQQQQQ", data, phoff + index * phentsize)
        program_type, flags, offset, vaddr, _, filesz, memsz, align = values
        if program_type != PT_LOAD:
            continue
        if filesz > memsz:
            issues.append(Issue("load_file_size_exceeds_memory_size", "error"))
            continue
        if not checked_range(len(data), offset, filesz):
            issues.append(Issue("load_file_range_out_of_bounds", "error"))
            continue
        if not valid_u64_range(vaddr, memsz):
            issues.append(Issue("load_address_range_invalid", "error"))
            continue
        if align not in (0, 1) and not is_power_of_two(align):
            issues.append(Issue("load_alignment_invalid", "error"))
            continue
        if align not in (0, 1) and (offset - vaddr) % align != 0:
            issues.append(Issue("load_alignment_mismatch", "error"))
            continue
        loads.append(LoadSegment(index, offset, vaddr, filesz, memsz, flags, align))
    ordered = sorted((load for load in loads if load.memsz), key=lambda load: (load.vaddr, load.index))
    previous_end = -1
    for load in ordered:
        if load.vaddr < previous_end:
            issues.append(Issue("overlapping_load_segments", "error"))
            break
        previous_end = max(previous_end, load.memory_end)
    if not loads:
        issues.append(Issue("missing_load_segments", "error"))
    return loads


def count_section_entries(
    sections: Sequence[SectionHeader],
    section_type: int,
    expected_size: int,
    issue_code: str,
    issues: list[Issue],
) -> tuple[int, int]:
    table_count = 0
    entry_count = 0
    known_indexes = {section.index for section in sections}
    for section in sections:
        if section.section_type != section_type:
            continue
        table_count += 1
        if section.entsize != expected_size or section.size % expected_size:
            issues.append(Issue(issue_code, "error"))
            continue
        if section.link and section.link not in known_indexes:
            issues.append(Issue("section_link_out_of_range", "error"))
        entry_count += section.size // expected_size
    return table_count, entry_count


def count_dynamic_entries(sections: Sequence[SectionHeader], issues: list[Issue]) -> tuple[int, int]:
    tables: list[tuple[int, int]] = []
    for section in sections:
        if section.section_type == SHT_DYNAMIC:
            if section.entsize != DYNAMIC_ENTRY_SIZE or section.size % DYNAMIC_ENTRY_SIZE:
                issues.append(Issue("malformed_dynamic_section", "error"))
                continue
            tables.append((section.offset, section.size))
    return len(tables), sum(size // DYNAMIC_ENTRY_SIZE for _, size in tables)


def count_program_dynamic_entries(
    data: bytes, phoff: int, phentsize: int, phnum: int, issues: list[Issue]
) -> tuple[int, int]:
    if (
        phnum == 0
        or phentsize != PROGRAM_HEADER_SIZE
        or phnum > MAX_TABLE_ENTRIES
        or not checked_table(len(data), phoff, phentsize, phnum)
    ):
        return 0, 0
    tables: list[tuple[int, int]] = []
    for index in range(phnum):
        program_type, _, offset, _, _, filesz, _, _ = struct.unpack_from(
            "<IIQQQQQQ", data, phoff + index * phentsize
        )
        if program_type != PT_DYNAMIC:
            continue
        if filesz % DYNAMIC_ENTRY_SIZE or not checked_range(len(data), offset, filesz):
            issues.append(Issue("malformed_dynamic_segment", "error"))
            continue
        tables.append((offset, filesz))
    return len(tables), sum(size // DYNAMIC_ENTRY_SIZE for _, size in tables)


def parse_elf(data: bytes) -> ParsedElf:
    issues: list[Issue] = []
    metadata = empty_metadata()
    if len(data) < 16:
        return unsupported_elf([Issue("truncated_elf_identification", "error")])
    if data[:4] != b"\x7fELF":
        return unsupported_elf([Issue("invalid_elf_magic", "error")])
    if data[4] != ELF64_CLASS:
        return unsupported_elf([Issue("unsupported_elf_class", "error")])
    if data[5] != LITTLE_ENDIAN:
        return unsupported_elf([Issue("unsupported_elf_endianness", "error")])
    if data[6] != CURRENT_VERSION:
        return unsupported_elf([Issue("unsupported_elf_identification_version", "error")])
    if len(data) < ELF_HEADER_SIZE:
        return unsupported_elf([Issue("truncated_elf_header", "error")])
    values = struct.unpack_from("<16sHHIQQQIHHHHHH", data, 0)
    _, elf_type, machine, version, entry, phoff, shoff, _, ehsize, phentsize, phnum, shentsize, shnum, shstrndx = values
    if ehsize != ELF_HEADER_SIZE:
        issues.append(Issue("malformed_elf_header_size", "error"))
    if version != CURRENT_VERSION:
        issues.append(Issue("unsupported_elf_version", "error"))
    if elf_type not in (ET_EXEC, ET_DYN):
        issues.append(Issue("unsupported_elf_type", "error"))
    if machine != EM_X86_64:
        issues.append(Issue("unsupported_elf_machine", "error"))
    if any(item.severity == "error" for item in issues):
        return ParsedElf(False, False, elf_type, entry, [], [], metadata, unique_issues(issues))

    section_zero = parse_section_zero(data, shoff, shentsize, issues)
    sections, actual_shnum = parse_sections(data, shoff, shentsize, shnum, section_zero, issues)
    if shstrndx == SHN_XINDEX:
        if section_zero is None:
            issues.append(Issue("missing_extended_section_index", "error"))
        elif section_zero[6] >= actual_shnum:
            issues.append(Issue("extended_section_index_out_of_range", "error"))
    elif shstrndx not in (0,) and shstrndx >= actual_shnum:
        issues.append(Issue("section_name_index_out_of_range", "error"))

    actual_phnum = phnum
    if phnum == PN_XNUM:
        if section_zero is None:
            issues.append(Issue("missing_extended_program_count", "error"))
            actual_phnum = 0
        else:
            actual_phnum = section_zero[7]
    loads = parse_loads(data, phoff, phentsize, actual_phnum, issues)
    metadata["section_headers"] = len(sections)
    static_tables, static_symbols = count_section_entries(
        sections, SHT_SYMTAB, SYMBOL_ENTRY_SIZE, "malformed_static_symbol_table", issues
    )
    dynamic_tables, dynamic_symbols = count_section_entries(
        sections, SHT_DYNSYM, SYMBOL_ENTRY_SIZE, "malformed_dynamic_symbol_table", issues
    )
    rela_tables, rela_entries = count_section_entries(
        sections, SHT_RELA, RELA_ENTRY_SIZE, "malformed_rela_table", issues
    )
    rel_tables, rel_entries = count_section_entries(
        sections, SHT_REL, REL_ENTRY_SIZE, "malformed_rel_table", issues
    )
    dynamic_section_tables, dynamic_entries = count_dynamic_entries(sections, issues)
    dynamic_program_tables, dynamic_program_entries = count_program_dynamic_entries(
        data, phoff, phentsize, actual_phnum, issues
    )
    if dynamic_section_tables:
        dynamic_tables = dynamic_section_tables
        dynamic_entry_count = dynamic_entries
    else:
        dynamic_tables = dynamic_program_tables
        dynamic_entry_count = dynamic_program_entries
    metadata["static_symbols"] = static_symbols
    metadata["dynamic_symbols"] = dynamic_symbols
    metadata["relocation_tables"] = rela_tables + rel_tables
    metadata["relocation_entries"] = rela_entries + rel_entries
    metadata["dynamic_tables"] = dynamic_tables
    metadata["dynamic_entries"] = dynamic_entry_count

    executable_loads = [load for load in loads if load.executable and load.filesz]
    if not executable_loads:
        issues.append(Issue("missing_executable_load_segment", "error"))
    entry_in_exec = any(load.executable and load.vaddr <= entry < load.vaddr + load.filesz for load in loads)
    if not entry_in_exec:
        issues.append(Issue("entry_not_in_executable_file_range", "warning"))
    usable = bool(executable_loads) and not any(
        item.code in {
            "malformed_program_header_size",
            "truncated_program_header_table",
            "program_header_count_limit",
            "missing_program_headers",
            "missing_load_segments",
            "missing_executable_load_segment",
        }
        for item in issues
    )
    return ParsedElf(True, usable, elf_type, entry, loads, sections, metadata, unique_issues(issues))


class AddressMap:
    def __init__(self, loads: Sequence[LoadSegment]) -> None:
        self.loads = tuple(loads)

    def matching_file_loads(self, address: int, executable: bool | None = None) -> list[LoadSegment]:
        matches = []
        for load in self.loads:
            if executable is not None and load.executable != executable:
                continue
            if load.vaddr <= address < load.vaddr + load.filesz:
                matches.append(load)
        return matches

    def file_load(self, address: int, executable: bool | None = None) -> LoadSegment | None:
        matches = self.matching_file_loads(address, executable)
        return matches[0] if len(matches) == 1 else None

    def is_executable_address(self, address: int) -> bool:
        return self.file_load(address, True) is not None

    def is_data_address(self, address: int) -> bool:
        return self.file_load(address, False) is not None

    def offset_for(self, address: int) -> int | None:
        load = self.file_load(address)
        if load is None:
            return None
        return load.offset + address - load.vaddr


def read_artifact(path_text: str) -> ArtifactBytes:
    try:
        descriptor = os.open(
            path_text,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0),
        )
    except OSError as error:
        if error.errno == errno.ENOENT:
            return ArtifactBytes(None, None, 0, (Issue("input_missing", "error"),))
        if error.errno in (errno.EACCES, errno.EPERM):
            return ArtifactBytes(None, None, 0, (Issue("input_unreadable", "error"),))
        return ArtifactBytes(None, None, 0, (Issue("input_read_error", "error"),))
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            return ArtifactBytes(None, None, 0, (Issue("input_not_regular", "error"),))
        if before.st_size > MAX_ARTIFACT_BYTES:
            return ArtifactBytes(
                None, None, before.st_size, (Issue("artifact_size_limit", "error"),)
            )
        hasher = hashlib.sha256()
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            if total + len(chunk) > MAX_ARTIFACT_BYTES:
                return ArtifactBytes(
                    None, None, total + len(chunk), (Issue("artifact_size_limit", "error"),)
                )
            total += len(chunk)
            hasher.update(chunk)
            chunks.append(chunk)
        after = os.fstat(descriptor)
    except OSError:
        return ArtifactBytes(None, None, 0, (Issue("input_read_error", "error"),))
    finally:
        os.close(descriptor)
    if before.st_dev != after.st_dev or before.st_ino != after.st_ino or before.st_size != after.st_size or total != after.st_size:
        return ArtifactBytes(None, None, total, (Issue("artifact_changed_during_read", "error"),))
    digest = hasher.hexdigest()
    return ArtifactBytes(b"".join(chunks), digest, total, ())


def run_objdump(tool_path: str, binary_path: str) -> ToolResult:
    executable_path = os.path.abspath(tool_path)
    command = [
        executable_path,
        "--disassemble",
        "--no-show-raw-insn",
        "--print-imm-hex",
        binary_path,
    ]
    environment = {"LANG": "C", "LC_ALL": "C"}
    try:
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            close_fds=True,
            env=environment,
            start_new_session=True,
        )
    except OSError:
        return ToolResult("objdump_start_failed", b"")
    stdout = bytearray()
    stderr = bytearray()
    selector = selectors.DefaultSelector()
    assert process.stdout is not None
    assert process.stderr is not None
    selector.register(process.stdout, selectors.EVENT_READ, "stdout")
    selector.register(process.stderr, selectors.EVENT_READ, "stderr")
    deadline = time.monotonic() + TOOL_TIMEOUT_SECONDS
    outcome = "ok"
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                outcome = "objdump_timeout"
                process.kill()
                break
            events = selector.select(remaining)
            if not events:
                continue
            for key, _ in events:
                try:
                    chunk = os.read(key.fileobj.fileno(), 65536)
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                if len(stdout) + len(stderr) + len(chunk) > MAX_TOOL_OUTPUT_BYTES:
                    outcome = "objdump_output_limit"
                    process.kill()
                    break
                if key.data == "stdout":
                    stdout.extend(chunk)
                else:
                    stderr.extend(chunk)
            if outcome != "ok":
                break
        if outcome != "ok":
            try:
                process.wait(timeout=2.0)
            except subprocess.TimeoutExpired:
                process.kill()
        else:
            process.wait(timeout=2.0)
            if process.returncode != 0:
                outcome = "objdump_nonzero_exit"
    except (OSError, subprocess.TimeoutExpired):
        outcome = "objdump_read_failed"
        try:
            process.kill()
        except OSError:
            pass
    finally:
        selector.close()
        process.stdout.close()
        process.stderr.close()
    return ToolResult(outcome, bytes(stdout) if outcome == "ok" else b"")


def normalize_register(name: str) -> str:
    lowered = name.lower()
    if lowered in REGISTER_ALIASES:
        return REGISTER_ALIASES[lowered]
    return lowered


def registers_in(text: str) -> frozenset[str]:
    return frozenset(normalize_register(match.group(1)) for match in REGISTER_PATTERN.finditer(text))


def split_operands(operands: str) -> list[str]:
    code = operands.split("#", 1)[0]
    return [item.strip() for item in code.split(",") if item.strip()]


def mnemonic_writes_destination(mnemonic: str) -> bool:
    if mnemonic.startswith(NO_DESTINATION_WRITE_PREFIXES):
        return False
    return mnemonic.startswith(WRITE_PREFIXES)


def operand_is_memory(operand: str) -> bool:
    return "(" in operand and ")" in operand


def instruction_access(mnemonic: str, operands: str, data_refs: tuple[int, ...]) -> tuple[frozenset[str], bool, bool, tuple[int, ...]]:
    operand_parts = split_operands(operands)
    all_registers = registers_in(operands)
    destination = operand_parts[-1] if operand_parts else ""
    writes: frozenset[str] = frozenset()
    stack_read = any(operand_is_memory(item) and ("%rsp" in item.lower() or "%rbp" in item.lower()) for item in operand_parts)
    stack_write = False
    data_write_refs: tuple[int, ...] = ()
    if mnemonic_writes_destination(mnemonic) and destination:
        writes = registers_in(destination)
        if operand_is_memory(destination):
            if "%rsp" in destination.lower() or "%rbp" in destination.lower():
                stack_write = True
            data_write_refs = data_refs
    if mnemonic.startswith(("push", "pop", "call", "ret")):
        stack_read = True
        stack_write = True
    return all_registers | writes, stack_read, stack_write, data_write_refs


def direct_target_from_operands(operands: str, indirect: bool) -> int | None:
    if indirect:
        return None
    match = DIRECT_OPERAND.match(operands.split("#", 1)[0])
    if match is None:
        return None
    try:
        return int(match.group("address"), 16)
    except ValueError:
        return None


def classify_control(mnemonic: str, operands: str) -> tuple[bool, bool, bool, bool, bool]:
    lowered = mnemonic.lower()
    is_call = lowered.startswith("call")
    is_return = lowered.startswith(("ret", "iret"))
    is_jump = lowered.startswith("j") or lowered.startswith("loop")
    is_conditional = is_jump and not lowered.startswith("jmp")
    is_indirect = (is_call or is_jump) and (
        "*" in operands or "%" in operands or "(" in operands or ")" in operands
    )
    is_trap = lowered in {"ud2", "hlt", "int3"} or lowered.startswith("int$")
    return is_call, is_jump, is_conditional, is_indirect, is_return or is_trap


def data_references_from_operands(operands: str, address_map: AddressMap) -> tuple[int, ...]:
    if "%rip" not in operands.lower() and "(" not in operands:
        return ()
    references: set[int] = set()
    for match in COMMENT_ADDRESS.finditer(operands):
        try:
            address = int(match.group("address"), 16)
        except ValueError:
            continue
        if address_map.is_data_address(address):
            references.add(address)
    for match in MEMORY_DISPLACEMENT.finditer(operands.split("#", 1)[0]):
        fields = tuple(field.strip() for field in match.group("fields").split(","))
        if not fields or len(fields) > 3 or fields[0]:
            continue
        if len(fields) > 1 and REGISTER_PATTERN.fullmatch(fields[1]) is None:
            continue
        if len(fields) > 2 and fields[2] not in {"1", "2", "4", "8"}:
            continue
        address = int(match.group("address"), 16)
        if address_map.is_data_address(address):
            references.add(address)
    return tuple(sorted(references))


def parse_disassembly(output: bytes, address_map: AddressMap) -> tuple[list[Instruction], list[Issue]]:
    issues: list[Issue] = []
    instructions: dict[int, Instruction] = {}
    try:
        lines = output.decode("utf-8", "replace").splitlines()
    except UnicodeDecodeError:
        return [], [Issue("objdump_output_decode_failed", "error")]
    for line in lines:
        match = INSTRUCTION_LINE.match(line)
        if match is None:
            continue
        try:
            address = int(match.group("address"), 16)
        except ValueError:
            continue
        if not address_map.is_executable_address(address):
            continue
        body = match.group("body").strip()
        byte_match = LEADING_BYTES.match(body)
        if byte_match is not None:
            body = byte_match.group("assembly").strip()
        if not body or body.startswith("."):
            continue
        pieces = body.split(None, 1)
        mnemonic = pieces[0].lower()
        operands = OPERAND_SYMBOL.sub("", pieces[1] if len(pieces) > 1 else "")
        is_call, is_jump, is_conditional, is_indirect, is_terminal = classify_control(mnemonic, operands)
        is_return = mnemonic.startswith(("ret", "iret"))
        is_trap = mnemonic in {"ud2", "hlt", "int3"} or mnemonic.startswith("int$")
        data_refs = data_references_from_operands(operands, address_map)
        registers, stack_read, stack_write, data_write_refs = instruction_access(mnemonic, operands, data_refs)
        direct_target = direct_target_from_operands(operands, is_indirect)
        instruction = Instruction(
            address=address,
            mnemonic=mnemonic,
            operands=operands,
            direct_target=direct_target,
            is_call=is_call,
            is_jump=is_jump,
            is_conditional_jump=is_conditional,
            is_indirect=is_indirect,
            is_return=is_return,
            is_trap=is_trap,
            registers=registers,
            writes=registers_in(split_operands(operands)[-1]) if mnemonic_writes_destination(mnemonic) and split_operands(operands) else frozenset(),
            stack_read=stack_read,
            stack_write=stack_write,
            data_refs=data_refs,
            data_write_refs=data_write_refs,
        )
        instructions.setdefault(address, instruction)
        if len(instructions) > MAX_INSTRUCTIONS:
            issues.append(Issue("instruction_count_limit", "error"))
            break
    result = [instructions[address] for address in sorted(instructions)]
    if not result:
        issues.append(Issue("no_mapped_instructions", "error"))
    return result, unique_issues(issues)


def instruction_fallthrough(
    instructions: Sequence[Instruction], address_map: AddressMap
) -> dict[int, int | None]:
    result: dict[int, int | None] = {}
    for position, instruction in enumerate(instructions):
        if position + 1 == len(instructions):
            result[instruction.address] = None
            continue
        following = instructions[position + 1].address
        current_load = address_map.file_load(instruction.address, True)
        following_load = address_map.file_load(following, True)
        if (
            current_load is not None
            and following_load is not None
            and current_load.index == following_load.index
            and 0 < following - instruction.address <= 15
        ):
            result[instruction.address] = following
        else:
            result[instruction.address] = None
    return result


def build_basic_blocks(
    instructions: Sequence[Instruction], address_map: AddressMap, entry: int | None
) -> tuple[list[BasicBlock], dict[int, int], dict[int, int | None]]:
    if not instructions:
        return [], {}, {}
    fallthrough = instruction_fallthrough(instructions, address_map)
    addresses = {instruction.address for instruction in instructions}
    leaders = {instructions[0].address}
    if entry in addresses:
        leaders.add(entry)
    for instruction in instructions:
        if instruction.direct_target in addresses and (instruction.is_jump or instruction.is_call):
            leaders.add(instruction.direct_target)
        if (instruction.is_jump or instruction.is_call or instruction.is_return or instruction.is_trap) and fallthrough[instruction.address] is not None:
            leaders.add(fallthrough[instruction.address])
    provisional: list[tuple[Instruction, ...]] = []
    current: list[Instruction] = []
    for instruction in instructions:
        if current and instruction.address in leaders:
            provisional.append(tuple(current))
            current = []
        if current and fallthrough[current[-1].address] != instruction.address:
            provisional.append(tuple(current))
            current = []
        current.append(instruction)
        if instruction.is_jump or instruction.is_return or instruction.is_trap or instruction.is_call:
            provisional.append(tuple(current))
            current = []
        if len(provisional) >= MAX_BASIC_BLOCKS:
            break
    if current and len(provisional) < MAX_BASIC_BLOCKS:
        provisional.append(tuple(current))
    blocks = [BasicBlock(index, chunk, [], False, "fallthrough") for index, chunk in enumerate(provisional)]
    by_start = {block.start: block.index for block in blocks}
    by_address = {
        instruction.address: block.index
        for block in blocks
        for instruction in block.instructions
    }
    for block in blocks:
        last = block.instructions[-1]
        successor_addresses: list[int] = []
        unknown = False
        terminator = "fallthrough"
        if last.is_trap:
            terminator = "trap"
        elif last.is_return:
            terminator = "return"
        elif last.is_jump:
            if last.is_indirect:
                terminator = "indirect_branch"
                unknown = True
            elif last.is_conditional_jump:
                terminator = "conditional_branch"
                if last.direct_target is not None:
                    successor_addresses.append(last.direct_target)
                if fallthrough[last.address] is not None:
                    successor_addresses.append(fallthrough[last.address])
            else:
                terminator = "direct_branch"
                if last.direct_target is not None:
                    successor_addresses.append(last.direct_target)
        elif last.is_call:
            terminator = "call"
            if fallthrough[last.address] is not None:
                successor_addresses.append(fallthrough[last.address])
        elif fallthrough[last.address] is not None:
            successor_addresses.append(fallthrough[last.address])
        successors = sorted({by_address[address] for address in successor_addresses if address in by_address})
        if any(address not in by_address for address in successor_addresses):
            unknown = True
        block.successors = successors
        block.unknown_successor = unknown
        block.terminator = terminator
    return blocks, by_start, fallthrough


def compute_sccs(blocks: Sequence[BasicBlock]) -> tuple[list[tuple[int, ...]], dict[int, int]]:
    adjacency = {block.index: tuple(sorted(block.successors)) for block in blocks}
    reverse: dict[int, list[int]] = {block.index: [] for block in blocks}
    for source, targets in adjacency.items():
        for target in targets:
            reverse[target].append(source)
    for targets in reverse.values():
        targets.sort()
    seen: set[int] = set()
    finish: list[int] = []
    for start in sorted(adjacency):
        if start in seen:
            continue
        stack: list[tuple[int, int]] = [(start, 0)]
        seen.add(start)
        while stack:
            vertex, position = stack[-1]
            targets = adjacency[vertex]
            if position < len(targets):
                target = targets[position]
                stack[-1] = (vertex, position + 1)
                if target not in seen:
                    seen.add(target)
                    stack.append((target, 0))
                continue
            finish.append(vertex)
            stack.pop()
    components: list[tuple[int, ...]] = []
    assigned: set[int] = set()
    for start in reversed(finish):
        if start in assigned:
            continue
        component: list[int] = []
        stack = [start]
        assigned.add(start)
        while stack:
            vertex = stack.pop()
            component.append(vertex)
            for target in reversed(reverse[vertex]):
                if target not in assigned:
                    assigned.add(target)
                    stack.append(target)
        components.append(tuple(sorted(component)))
    components.sort(key=lambda component: component[0])
    mapping = {
        block_index: component_index
        for component_index, component in enumerate(components)
        for block_index in component
    }
    return components, mapping


def compute_function_regions(
    blocks: Sequence[BasicBlock], entry: int | None
) -> tuple[list[FunctionRegion], dict[int, int]]:
    reverse: dict[int, set[int]] = {block.index: set() for block in blocks}
    for block in blocks:
        for target in block.successors:
            reverse[target].add(block.index)
    seen: set[int] = set()
    raw_regions: list[tuple[int, ...]] = []
    for block in blocks:
        if block.index in seen:
            continue
        component: list[int] = []
        stack = [block.index]
        seen.add(block.index)
        while stack:
            current = stack.pop()
            component.append(current)
            neighbors = set(blocks[current].successors) | reverse[current]
            for neighbor in sorted(neighbors, reverse=True):
                if neighbor not in seen:
                    seen.add(neighbor)
                    stack.append(neighbor)
        raw_regions.append(tuple(sorted(component)))
    raw_regions.sort(key=lambda component: blocks[component[0]].start)
    call_roots = {
        instruction.direct_target
        for block in blocks
        for instruction in block.instructions
        if instruction.is_call and instruction.direct_target is not None
    }
    regions: list[FunctionRegion] = []
    mapping: dict[int, int] = {}
    for index, members in enumerate(raw_regions):
        starts = {blocks[member].start for member in members}
        roots = set()
        if entry in starts:
            roots.add(entry)
        roots.update(target for target in call_roots if target in starts)
        regions.append(FunctionRegion(index, members, tuple(sorted(roots))))
        for member in members:
            mapping[member] = index
    return regions, mapping

def scc_is_loop(component: Sequence[int], blocks: Sequence[BasicBlock]) -> bool:
    return len(component) > 1 or (
        len(component) == 1 and component[0] in blocks[component[0]].successors
    )


def reverse_reachable(goals: Iterable[int], blocks: Sequence[BasicBlock]) -> set[int]:
    reverse: dict[int, list[int]] = {block.index: [] for block in blocks}
    for block in blocks:
        for target in block.successors:
            reverse[target].append(block.index)
    seen = set(goals)
    queue = collections.deque(sorted(seen))
    while queue:
        current = queue.popleft()
        for predecessor in sorted(reverse[current]):
            if predecessor not in seen:
                seen.add(predecessor)
                queue.append(predecessor)
    return seen


def discover_data_regions(
    data: bytes, loads: Sequence[LoadSegment], address_map: AddressMap, issues: list[Issue]
) -> list[DataRegion]:
    regions: list[DataRegion] = []
    scan_budget = MAX_POINTER_SCAN_BYTES
    table_count = 0

    def append_table(start: int, values: list[int], segment: LoadSegment, width: int) -> None:
        nonlocal table_count
        if len(values) < 2 or table_count >= MAX_POINTER_TABLES:
            return
        candidate = DataRegion(
            "pointer_table",
            start,
            start + len(values) * width,
            segment.index,
            segment.writable,
            tuple(values),
            pointer_width=width,
        )
        if any(
            existing.kind == candidate.kind
            and existing.start == candidate.start
            and existing.end == candidate.end
            and existing.pointer_targets == candidate.pointer_targets
            for existing in regions
        ):
            return
        regions.append(candidate)
        table_count += 1

    for load in sorted(loads, key=lambda item: (item.vaddr, item.index)):
        if not load.readable or load.executable or not load.filesz:
            continue
        regions.append(
            DataRegion(
                "mapped_data",
                load.vaddr,
                load.vaddr + load.filesz,
                load.index,
                load.writable,
            )
        )
        if scan_budget <= 0:
            issues.append(Issue("pointer_table_scan_limited", "warning"))
            continue
        scan_length = min(load.filesz, scan_budget)
        if scan_length < load.filesz:
            issues.append(Issue("pointer_table_scan_limited", "warning"))
        scan_budget -= scan_length

        relative = (-load.vaddr) % 8
        run_start: int | None = None
        run_values: list[int] = []
        while relative + 8 <= scan_length:
            value = struct.unpack_from("<Q", data, load.offset + relative)[0]
            if address_map.is_executable_address(value):
                if run_start is None:
                    run_start = load.vaddr + relative
                    run_values = []
                run_values.append(value)
            else:
                if run_start is not None:
                    append_table(run_start, run_values, load, 8)
                run_start = None
                run_values = []
            relative += 8
        if run_start is not None:
            append_table(run_start, run_values, load, 8)

        relative = (-load.vaddr) % 4
        while relative + 4 <= scan_length:
            table_start = load.vaddr + relative
            displacement = struct.unpack_from("<i", data, load.offset + relative)[0]
            target = table_start + displacement
            if not address_map.is_executable_address(target):
                relative += 4
                continue
            values = [target]
            cursor = relative + 4
            while cursor + 4 <= scan_length:
                next_displacement = struct.unpack_from("<i", data, load.offset + cursor)[0]
                next_target = table_start + next_displacement
                if not address_map.is_executable_address(next_target):
                    break
                values.append(next_target)
                cursor += 4
            if len(values) >= 3:
                append_table(table_start, values, load, 4)
                relative = cursor
            else:
                relative += 4
    if table_count >= MAX_POINTER_TABLES:
        issues.append(Issue("pointer_table_count_limit", "warning"))
    kind_order = {"mapped_data": 0, "pointer_table": 1}
    regions.sort(key=lambda region: (region.start, region.end, kind_order[region.kind], region.segment_index))
    for index, region in enumerate(regions):
        region.index = index
    return regions


def data_region_for_address(regions: Sequence[DataRegion], address: int) -> int | None:
    matching = [
        region
        for region in regions
        if region.start <= address < region.end
    ]
    if not matching:
        return None
    matching.sort(key=lambda region: (0 if region.kind == "pointer_table" else 1, region.end - region.start, region.index))
    return matching[0].index


def block_data_region_sets(
    blocks: Sequence[BasicBlock], regions: Sequence[DataRegion]
) -> tuple[dict[int, set[int]], dict[int, set[int]]]:
    references: dict[int, set[int]] = {}
    writes: dict[int, set[int]] = {}
    for block in blocks:
        references[block.index] = {
            region_index
            for address in block.data_refs
            if (region_index := data_region_for_address(regions, address)) is not None
        }
        writes[block.index] = {
            region_index
            for address in block.data_write_refs
            if (region_index := data_region_for_address(regions, address)) is not None
        }
    return references, writes


def block_for_instruction_address(blocks: Sequence[BasicBlock]) -> dict[int, int]:
    return {
        instruction.address: block.index
        for block in blocks
        for instruction in block.instructions
    }



def indirect_jump_target_register(instruction: Instruction) -> str | None:
    if not instruction.is_jump or not instruction.is_indirect:
        return None
    operands = split_operands(instruction.operands)
    if len(operands) != 1:
        return None
    registers = registers_in(operands[0])
    if len(registers) != 1:
        return None
    return next(iter(registers))


def stable_stack_slot(operand: str) -> str | None:
    if not operand_is_memory(operand):
        return None
    registers = registers_in(operand)
    if len(registers) != 1:
        return None
    register = next(iter(registers))
    if register not in {"rbp", "rsp"}:
        return None
    displacement = REGISTER_PATTERN.sub("", operand.lower())
    return f"{register}:{''.join(displacement.split())}"


def instruction_stack_slots(instruction: Instruction) -> set[str]:
    if instruction.mnemonic.startswith(("call", "lea", "pop", "push", "ret")):
        return set()
    return {
        slot
        for operand in split_operands(instruction.operands)
        if (slot := stable_stack_slot(operand)) is not None
    }


def instruction_stack_write_slots(instruction: Instruction) -> set[str]:
    if not mnemonic_writes_destination(instruction.mnemonic):
        return set()
    operands = split_operands(instruction.operands)
    if not operands:
        return set()
    slot = stable_stack_slot(operands[-1])
    return {slot} if slot is not None else set()


def union_stack_slots(
    block_indexes: Iterable[int], blocks: Sequence[BasicBlock], writes: bool = False
) -> set[str]:
    result: set[str] = set()
    for block_index in block_indexes:
        for instruction in blocks[block_index].instructions:
            if writes:
                result.update(instruction_stack_write_slots(instruction))
            else:
                result.update(instruction_stack_slots(instruction))
    return result

def split_explicit_operands(operands: str) -> tuple[str, ...]:
    code = operands.split("#", 1)[0]
    result: list[str] = []
    start = 0
    depth = 0
    for index, character in enumerate(code):
        if character == "(":
            depth += 1
        elif character == ")":
            depth = max(0, depth - 1)
        elif character == "," and depth == 0:
            operand = code[start:index].strip()
            if operand:
                result.append(operand)
            start = index + 1
    operand = code[start:].strip()
    if operand:
        result.append(operand)
    return tuple(result)


def source_memory_operands(instruction: Instruction) -> tuple[str, ...]:
    if instruction.mnemonic.startswith("lea"):
        return ()
    operands = split_explicit_operands(instruction.operands)
    if mnemonic_writes_destination(instruction.mnemonic) and operands:
        operands = operands[:-1]
    return tuple(operand for operand in operands if operand_is_memory(operand))


def instruction_can_read_data_memory(instruction: Instruction) -> bool:
    if (
        instruction.is_call
        or instruction.is_jump
        or instruction.is_return
        or instruction.is_trap
    ):
        return False
    return not instruction.mnemonic.startswith(NON_DATA_MEMORY_READ_PREFIXES)



def memory_operand_fields(operand: str) -> tuple[str, ...] | None:
    match = MEMORY_ADDRESSING.search(operand)
    if match is None:
        return None
    return tuple(field.strip() for field in match.group("fields").split(","))


def byte_or_subword_memory_fetch(instruction: Instruction) -> bool:
    mnemonic = instruction.mnemonic
    if mnemonic.startswith(("movsb", "movsw", "movzb", "movzw")):
        return True
    if len(mnemonic) < 4 or mnemonic[-1] not in {"b", "w"}:
        return False
    return mnemonic[:-1] in {
        "adc", "add", "and", "cmp", "dec", "div", "idiv", "imul", "inc", "mov",
        "neg", "not", "or", "rol", "ror", "sal", "sar", "sbb", "shl", "shr",
        "sub", "test", "xadd", "xchg", "xor",
    }


def dynamic_memory_fetch_modes(instruction: Instruction, operand: str) -> set[str]:
    fields = memory_operand_fields(operand)
    if fields is None:
        return set()
    if not byte_or_subword_memory_fetch(instruction):
        return set()
    if len(fields) > 1 and registers_in(fields[1]):
        return {"indexed_memory_fetch"}
    base_registers = registers_in(fields[0]) if fields else frozenset()
    if base_registers - {"rip", "rsp", "rbp"}:
        return {"byte_subword_memory_fetch"}
    return set()


def handler_data_consumption(
    handler: HandlerEvidence,
    blocks: Sequence[BasicBlock],
    regions: Sequence[DataRegion],
    owned_blocks: Iterable[int] | None = None,
) -> dict[int | None, set[str]]:
    result: dict[int | None, set[str]] = collections.defaultdict(set)
    for block_index in (
        handler.body_blocks if owned_blocks is None else owned_blocks
    ):
        for instruction in blocks[block_index].instructions:
            if not instruction_can_read_data_memory(instruction):
                continue
            source_operands = source_memory_operands(instruction)
            if not source_operands:
                continue
            dynamic_modes: set[str] = set()
            for operand in source_operands:
                dynamic_modes.update(dynamic_memory_fetch_modes(instruction, operand))
            operands = split_explicit_operands(instruction.operands)
            writes_memory = (
                mnemonic_writes_destination(instruction.mnemonic)
                and bool(operands)
                and operand_is_memory(operands[-1])
            )
            mapped_regions = {
                region_index
                for address in instruction.data_refs
                if not writes_memory
                and (region_index := data_region_for_address(regions, address)) is not None
            }
            non_pointer_regions = {
                region_index
                for region_index in mapped_regions
                if regions[region_index].kind != "pointer_table"
            }
            if non_pointer_regions:
                for region_index in sorted(non_pointer_regions):
                    result[region_index].add("mapped_data_access")
                    result[region_index].update(dynamic_modes)
            elif not mapped_regions and dynamic_modes:
                result[None].update(dynamic_modes)
    return result


def immediate_assignment_addresses(
    instruction: Instruction, source_operands: Sequence[str], address_map: AddressMap
) -> set[int]:
    result: set[int] = set()
    for operand in source_operands:
        for match in IMMEDIATE_OPERAND.finditer(operand):
            try:
                address = int(match.group("address"), 16)
            except ValueError:
                continue
            if address_map.is_executable_address(address):
                result.add(address)
    if instruction.mnemonic.startswith("lea") and any(
        "%rip" in operand.lower() for operand in source_operands
    ):
        for match in COMMENT_ADDRESS.finditer(instruction.operands):
            try:
                address = int(match.group("address"), 16)
            except ValueError:
                continue
            if address_map.is_executable_address(address):
                result.add(address)
    return result


def target_flow_destination(instruction: Instruction) -> str | None:
    if not mnemonic_writes_destination(instruction.mnemonic):
        return None
    operands = split_operands(instruction.operands)
    if len(operands) < 2:
        return None
    destination = operands[-1]
    if (slot := stable_stack_slot(destination)) is not None:
        return f"stack:{slot}"
    if operand_is_memory(destination):
        return None
    registers = registers_in(destination)
    if len(registers) != 1:
        return None
    return f"register:{next(iter(registers))}"


def capped_flow_tokens(
    values: Iterable[tuple[int, int]]
) -> tuple[frozenset[tuple[int, int]], bool]:
    tokens = tuple(sorted(set(values)))
    return frozenset(tokens[:MAX_INDIRECT_FLOW_TOKENS]), len(tokens) > MAX_INDIRECT_FLOW_TOKENS


def target_flow_sources(
    state: dict[str, frozenset[tuple[int, int]]],
    instruction: Instruction,
    source_operands: Sequence[str],
    block_index: int,
    address_map: AddressMap,
) -> tuple[frozenset[tuple[int, int]], bool]:
    values: set[tuple[int, int]] = {
        (address, block_index)
        for address in immediate_assignment_addresses(instruction, source_operands, address_map)
    }
    for operand in source_operands:
        if (slot := stable_stack_slot(operand)) is not None:
            values.update(state.get(f"stack:{slot}", ()))
            continue
        if operand_is_memory(operand):
            continue
        for register in registers_in(operand):
            values.update(state.get(f"register:{register}", ()))
    return capped_flow_tokens(values)


def transfer_target_flow(
    state: dict[str, frozenset[tuple[int, int]]],
    instruction: Instruction,
    block_index: int,
    address_map: AddressMap,
) -> tuple[dict[str, frozenset[tuple[int, int]]], bool]:
    destination = target_flow_destination(instruction)
    if destination is None:
        return state, False
    operands = split_operands(instruction.operands)
    source_values, limited = target_flow_sources(
        state, instruction, operands[:-1], block_index, address_map
    )
    if instruction.mnemonic.startswith("cmov"):
        values, values_limited = capped_flow_tokens(
            set(state.get(destination, ())) | set(source_values)
        )
        limited = limited or values_limited
    elif instruction.mnemonic.startswith(("lea", "mov")):
        values = source_values
    else:
        values = frozenset()
    if values == state.get(destination, frozenset()):
        return state, limited
    result = dict(state)
    if values:
        result[destination] = values
    else:
        result.pop(destination, None)
    return result, limited


def merge_target_flow(
    existing: dict[str, frozenset[tuple[int, int]]],
    incoming: dict[str, frozenset[tuple[int, int]]],
) -> tuple[dict[str, frozenset[tuple[int, int]]], bool, bool]:
    result = existing
    changed = False
    limited = False
    for key in sorted(incoming):
        values, values_limited = capped_flow_tokens(
            set(existing.get(key, ())) | set(incoming[key])
        )
        limited = limited or values_limited
        if values == existing.get(key, frozenset()):
            continue
        if result is existing:
            result = dict(existing)
        result[key] = values
        changed = True
    return result, changed, limited


def bounded_predecessor_window(
    branch_block: int, blocks: Sequence[BasicBlock]
) -> tuple[tuple[int, ...], bool]:
    reverse: dict[int, list[int]] = {block.index: [] for block in blocks}
    for block in blocks:
        for target in block.successors:
            reverse[target].append(block.index)
    branch_address = blocks[branch_block].start
    result: list[int] = []
    seen = {branch_block}
    queue = collections.deque([branch_block])
    instruction_count = 0
    limited = False
    while queue:
        current = queue.popleft()
        block = blocks[current]
        if abs(block.start - branch_address) > MAX_INDIRECT_RECOVERY_SPAN:
            limited = True
            continue
        if (
            len(result) >= MAX_INDIRECT_PREDECESSOR_BLOCKS
            or instruction_count + len(block.instructions) > MAX_INDIRECT_PREDECESSOR_INSTRUCTIONS
        ):
            limited = True
            continue
        result.append(current)
        instruction_count += len(block.instructions)
        for predecessor in sorted(reverse[current]):
            if predecessor not in seen:
                seen.add(predecessor)
                queue.append(predecessor)
    return tuple(sorted(result)), limited


def recover_indirect_jump_targets(
    blocks: Sequence[BasicBlock], address_map: AddressMap
) -> dict[int, IndirectTargetRecovery]:
    address_to_block = block_for_instruction_address(blocks)
    recoveries: dict[int, IndirectTargetRecovery] = {}
    for branch in blocks:
        target_register = indirect_jump_target_register(branch.instructions[-1])
        if target_register is None:
            continue
        window, limited = bounded_predecessor_window(branch.index, blocks)
        window_set = set(window)
        incoming: dict[int, dict[str, frozenset[tuple[int, int]]]] = {
            block_index: {} for block_index in window
        }
        queue = collections.deque(window)
        queued = set(window)
        branch_state: dict[str, frozenset[tuple[int, int]]] = {}
        flow_limited = limited
        while queue:
            block_index = queue.popleft()
            queued.remove(block_index)
            state = incoming[block_index]
            instruction_limit = -1 if block_index == branch.index else None
            for instruction in blocks[block_index].instructions[:instruction_limit]:
                state, instruction_limited = transfer_target_flow(
                    state, instruction, block_index, address_map
                )
                flow_limited = flow_limited or instruction_limited
            if block_index == branch.index:
                branch_state = state
            for successor in blocks[block_index].successors:
                if successor not in window_set:
                    continue
                merged, changed, merge_limited = merge_target_flow(incoming[successor], state)
                flow_limited = flow_limited or merge_limited
                if changed:
                    incoming[successor] = merged
                    if successor not in queued:
                        queue.append(successor)
                        queued.add(successor)
        tokens = branch_state.get(f"register:{target_register}", frozenset())
        addresses = tuple(sorted({address for address, _ in tokens}))
        target_blocks = tuple(
            sorted({address_to_block[address] for address in addresses if address in address_to_block})
        )
        selection_blocks = tuple(
            block_index
            for block_index in window
            if blocks[block_index].terminator == "conditional_branch"
            or any(
                instruction.mnemonic.startswith("cmov")
                for instruction in blocks[block_index].instructions
            )
        )
        if len(target_blocks) < 2 or not selection_blocks:
            continue
        recoveries[branch.index] = IndirectTargetRecovery(
            branch.index,
            addresses,
            target_blocks,
            selection_blocks,
            tuple(sorted({source for _, source in tokens})),
            flow_limited,
        )
    return recoveries


def dispatcher_context_blocks(dispatcher: DispatcherEvidence) -> tuple[int, ...]:
    return tuple(
        sorted(set(dispatcher.selection_blocks) | set(dispatcher.immediate_selection_blocks))
    )


def nearby_source_blocks(
    starts: Iterable[int], candidate_sources: set[int], blocks: Sequence[BasicBlock], region: int, max_depth: int = 4
) -> bool:
    if not candidate_sources:
        return False
    reverse: dict[int, list[int]] = {block.index: [] for block in blocks}
    for block in blocks:
        for target in block.successors:
            reverse[target].append(block.index)
    queue = collections.deque((start, 0) for start in sorted(set(starts)))
    seen = {start for start, _ in queue}
    while queue:
        current, depth = queue.popleft()
        if current in candidate_sources:
            return True
        if depth >= max_depth:
            continue
        neighbors = set(blocks[current].successors) | set(reverse[current])
        for neighbor in sorted(neighbors):
            if neighbor not in seen and blocks[neighbor].region == region:
                seen.add(neighbor)
                queue.append((neighbor, depth + 1))
    return False


def table_target_blocks(
    regions: Sequence[DataRegion], address_to_block: dict[int, int]
) -> dict[int, tuple[int, ...]]:
    result: dict[int, tuple[int, ...]] = {}
    for region in regions:
        if region.kind != "pointer_table":
            continue
        result[region.index] = tuple(
            sorted({address_to_block[address] for address in region.pointer_targets if address in address_to_block})
        )
    return result

def indirect_call_memory_fields(instruction: Instruction) -> tuple[str, ...] | None:
    match = MEMORY_ADDRESSING.search(instruction.operands.split("#", 1)[0])
    if match is None:
        return None
    return tuple(field.strip() for field in match.group("fields").split(","))


def indirect_call_base_register(instruction: Instruction) -> str | None:
    if not instruction.is_call or not instruction.is_indirect:
        return None
    fields = indirect_call_memory_fields(instruction)
    if fields is None or not fields:
        return None
    registers = registers_in(fields[0])
    return next(iter(registers)) if len(registers) == 1 else None


def indirect_call_index_provenance(instruction: Instruction) -> str:
    fields = indirect_call_memory_fields(instruction)
    if fields is None or len(fields) < 2 or not registers_in(fields[1]):
        return "fixed_slot"
    return "unknown_index"


def indirect_call_memory_displacement(instruction: Instruction) -> int | None:
    operands = instruction.operands.split("#", 1)[0]
    match = MEMORY_ADDRESSING.search(operands)
    if match is None:
        return None
    displacement = operands[: match.start()].strip()
    if displacement.startswith("*"):
        displacement = displacement[1:].strip()
    if not displacement:
        return 0
    try:
        return int(displacement, 0)
    except ValueError:
        return None


def direct_indirect_call_memory_addresses(
    instruction: Instruction, address_map: AddressMap
) -> tuple[int, ...]:
    addresses = set(instruction.data_refs)
    if not addresses and indirect_call_memory_fields(instruction) is None:
        operand = instruction.operands.split("#", 1)[0].strip()
        if operand.startswith("*"):
            operand = operand[1:].strip()
        try:
            address = int(operand, 0)
        except ValueError:
            address = None
        if address is not None and address_map.is_data_address(address):
            addresses.add(address)
    return tuple(sorted(addresses))


def indirect_call_table_references(
    block: BasicBlock, address_map: AddressMap
) -> tuple[IndirectCallTableReference, ...]:
    instruction = block.instructions[-1]
    if not instruction.is_call or not instruction.is_indirect:
        return ()
    index_provenance = indirect_call_index_provenance(instruction)
    references = {
        address: IndirectCallTableReference(
            address,
            "direct_memory_operand",
            index_provenance,
        )
        for address in direct_indirect_call_memory_addresses(instruction, address_map)
    }
    base_register = indirect_call_base_register(instruction)
    displacement = indirect_call_memory_displacement(instruction)
    if base_register is not None and displacement is not None:
        for preceding in reversed(block.instructions[:-1]):
            if base_register not in preceding.writes:
                continue
            if preceding.mnemonic.startswith("lea"):
                for base_address in preceding.data_refs:
                    address = base_address + displacement
                    if address_map.is_data_address(address):
                        references.setdefault(
                            address,
                            IndirectCallTableReference(
                                address,
                                "same_block_lea",
                                index_provenance,
                            ),
                        )
            break
    return tuple(
        sorted(
            references.values(),
            key=lambda item: (
                item.table_access_address,
                item.operand_provenance,
                item.index_provenance,
            ),
        )
    )


def discover_indirect_call_evidence(
    blocks: Sequence[BasicBlock],
    regions: Sequence[DataRegion],
    address_map: AddressMap,
) -> list[IndirectCallEvidence]:
    address_to_block = block_for_instruction_address(blocks)
    result: set[IndirectCallEvidence] = set()
    for block in blocks:
        if block.terminator != "call":
            continue
        for reference in indirect_call_table_references(block, address_map):
            region_index = data_region_for_address(regions, reference.table_access_address)
            if region_index is None:
                continue
            region = regions[region_index]
            if region.kind != "pointer_table" or region.pointer_width != 8:
                continue
            table_offset = reference.table_access_address - region.start
            if table_offset % region.pointer_width:
                continue
            if reference.index_provenance == "fixed_slot":
                target = region.pointer_targets[table_offset // region.pointer_width]
                target_block = address_to_block.get(target)
                target_blocks = () if target_block is None else (target_block,)
            else:
                target_blocks = tuple(
                    sorted(
                        {
                            address_to_block[target]
                            for target in region.pointer_targets
                            if target in address_to_block
                        }
                    )
                )
            if len(target_blocks) < 2:
                continue
            result.add(
                IndirectCallEvidence(
                    block.index,
                    region.index,
                    reference.table_access_address,
                    reference.operand_provenance,
                    reference.index_provenance,
                    target_blocks,
                )
            )
    return sorted(
        result,
        key=lambda item: (
            blocks[item.call_block].start,
            regions[item.table_region].start,
            item.table_access_address,
            item.operand_provenance,
            item.index_provenance,
        ),
    )[:MAX_CANDIDATES]


def discover_dispatchers(
    blocks: Sequence[BasicBlock],
    sccs: Sequence[tuple[int, ...]],
    region_by_block: dict[int, int],
    data_references: dict[int, set[int]],
    regions: Sequence[DataRegion],
    target_recoveries: dict[int, IndirectTargetRecovery],
) -> list[DispatcherEvidence]:
    address_to_block = block_for_instruction_address(blocks)
    table_targets = table_target_blocks(regions, address_to_block)
    table_sources: dict[int, set[int]] = collections.defaultdict(set)
    for block_index, references in data_references.items():
        for reference in references:
            if regions[reference].kind == "pointer_table":
                table_sources[reference].add(block_index)
    result: list[DispatcherEvidence] = []
    for block in blocks:
        if block.terminator != "indirect_branch":
            continue
        direct_tables = sorted(
            reference for reference in data_references[block.index] if regions[reference].kind == "pointer_table"
        )
        nearby_tables = [
            region.index
            for region in regions
            if region.kind == "pointer_table"
            and nearby_source_blocks(
                (block.index,), table_sources.get(region.index, set()), blocks, block.region
            )
        ]
        table_ids = tuple(sorted(set(direct_tables) | set(nearby_tables)))
        immediate_recovery = target_recoveries.get(block.index)
        immediate_targets = (
            immediate_recovery.target_blocks if immediate_recovery is not None else ()
        )
        targets = tuple(
            sorted(
                {
                    target
                    for table_id in table_ids
                    for target in table_targets.get(table_id, ())
                }
                | set(immediate_targets)
            )
        )
        reentry = reverse_reachable((block.index,), blocks)
        recurrent = bool(targets and any(target in reentry for target in targets)) or scc_is_loop(
            sccs[block.scc], blocks
        )
        readonly_table = any(not regions[table_id].writable for table_id in table_ids)
        if not recurrent and not readonly_table and not immediate_targets:
            continue
        if not targets and not recurrent:
            continue
        result.append(
            DispatcherEvidence(
                ("indirect", block.start),
                (block.index,),
                targets,
                table_ids,
                True,
                recurrent,
                region_by_block[block.index],
                immediate_recovery.target_addresses if immediate_recovery is not None else (),
                immediate_recovery.selection_blocks if immediate_recovery is not None else (),
                immediate_recovery.limited if immediate_recovery is not None else False,
                immediate_recovery.source_blocks if immediate_recovery is not None else (),
            )
        )
    for component in sccs:
        if not scc_is_loop(component, blocks):
            continue
        selection = tuple(
            block_index
            for block_index in component
            if blocks[block_index].terminator == "conditional_branch" and len(blocks[block_index].successors) >= 2
        )
        if len(selection) < 2:
            continue
        selection_set = set(selection)
        targets = tuple(
            sorted(
                {
                    target
                    for block_index in selection
                    for target in blocks[block_index].successors
                    if target not in selection_set
                }
            )
        )
        if len(targets) < 2:
            continue
        result.append(
            DispatcherEvidence(
                ("direct", blocks[selection[0]].start),
                selection,
                targets,
                (),
                False,
                True,
                region_by_block[selection[0]],
            )
        )
    result.sort(key=lambda item: (item.key[1], item.key[0]))
    return result[:MAX_CANDIDATES]


def apply_resolved_indirect_targets(
    dispatchers: Sequence[DispatcherEvidence], blocks: Sequence[BasicBlock]
) -> None:
    for dispatcher in dispatchers:
        if not dispatcher.indirect or not dispatcher.target_blocks:
            continue
        branch_blocks = [
            block_index
            for block_index in dispatcher.selection_blocks
            if blocks[block_index].terminator == "indirect_branch"
        ]
        if len(branch_blocks) != 1:
            continue
        branch = blocks[branch_blocks[0]]
        branch.successors = sorted(set(branch.successors) | set(dispatcher.target_blocks))


def refresh_dispatcher_graph(
    dispatchers: Sequence[DispatcherEvidence],
    blocks: Sequence[BasicBlock],
    region_by_block: dict[int, int],
) -> None:
    for dispatcher in dispatchers:
        dispatcher.region = region_by_block[dispatcher.selection_blocks[0]]
        if not dispatcher.indirect:
            continue
        reentry = reverse_reachable(dispatcher.selection_blocks, blocks)
        dispatcher.recurrent = bool(
            dispatcher.target_blocks
            and any(target in reentry for target in dispatcher.target_blocks)
        )


def collect_handler_body(
    start: int,
    selection_blocks: set[int],
    competing_entry_blocks: set[int],
    blocks: Sequence[BasicBlock],
    allowed_blocks: set[int],
) -> tuple[int, ...]:
    body: list[int] = []
    seen: set[int] = set()
    queue = collections.deque([start])
    while queue and len(body) < MAX_HANDLER_BODY_BLOCKS:
        current = queue.popleft()
        if current in seen:
            continue
        seen.add(current)
        if current not in allowed_blocks:
            continue
        if current != start and (
            current in selection_blocks or current in competing_entry_blocks
        ):
            continue
        body.append(current)
        for target in sorted(blocks[current].successors):
            if target not in seen:
                queue.append(target)
    return tuple(sorted(body))


def discover_handlers(
    dispatchers: Sequence[DispatcherEvidence], blocks: Sequence[BasicBlock]
) -> list[HandlerEvidence]:
    result: list[HandlerEvidence] = []
    for dispatcher in dispatchers:
        selection = set(dispatcher.selection_blocks)
        target_entries = set(dispatcher.target_blocks)
        reentry = reverse_reachable(selection, blocks)
        for target in dispatcher.target_blocks:
            if target in selection:
                continue
            reaches_selection = target in reentry
            body = collect_handler_body(
                target,
                selection,
                target_entries - {target},
                blocks,
                reentry if reaches_selection else {target},
            )
            if not body:
                continue
            result.append(
                HandlerEvidence(
                    dispatcher.key,
                    target,
                    body,
                    reaches_selection,
                )
            )
    result.sort(key=lambda item: (item.dispatcher_key, blocks[item.entry_block].start))
    return result[:MAX_CANDIDATES]


def handler_key(handler: HandlerEvidence) -> tuple[Any, ...]:
    return handler.dispatcher_key + (handler.entry_block,)


def full_handler_ownership(
    dispatcher: DispatcherEvidence,
    blocks: Sequence[BasicBlock],
) -> dict[int, tuple[int, ...]] | None:
    selection_blocks = set(dispatcher.selection_blocks)
    reentry_blocks = reverse_reachable(selection_blocks, blocks)
    roots = tuple(sorted(set(dispatcher.target_blocks) - selection_blocks))
    uncertainty_seen: set[int] = set()
    for root in roots:
        if root in uncertainty_seen:
            continue
        if len(uncertainty_seen) >= MAX_HANDLER_OWNERSHIP_TRAVERSALS:
            return None
        queue = collections.deque([root])
        uncertainty_seen.add(root)
        while queue:
            current = queue.popleft()
            block = blocks[current]
            if block.unknown_successor:
                return None
            for target in sorted(block.successors):
                if target in selection_blocks or target in uncertainty_seen:
                    continue
                if len(uncertainty_seen) >= MAX_HANDLER_OWNERSHIP_TRAVERSALS:
                    return None
                uncertainty_seen.add(target)
                queue.append(target)
    owners: dict[int, tuple[int, ...]] = {}
    traversal_count = len(uncertainty_seen)
    for root in roots:
        if root not in reentry_blocks:
            continue
        if traversal_count >= MAX_HANDLER_OWNERSHIP_TRAVERSALS:
            return None
        queue = collections.deque([root])
        seen = {root}
        while queue:
            current = queue.popleft()
            traversal_count += 1
            if traversal_count > MAX_HANDLER_OWNERSHIP_TRAVERSALS:
                return None
            if current in selection_blocks:
                continue
            block = blocks[current]
            if block.unknown_successor:
                return None
            current_owners = owners.get(current)
            if current_owners is None:
                owners[current] = (root,)
            elif root in current_owners or len(current_owners) >= 2:
                continue
            else:
                owners[current] = tuple(sorted((current_owners[0], root)))
            for target in sorted(block.successors):
                if (
                    target not in reentry_blocks
                    or target in selection_blocks
                    or target in seen
                ):
                    continue
                target_owners = owners.get(target)
                if target_owners is not None and len(target_owners) >= 2:
                    continue
                if (
                    traversal_count + len(queue)
                    >= MAX_HANDLER_OWNERSHIP_TRAVERSALS
                ):
                    return None
                seen.add(target)
                queue.append(target)
    return owners



def state_key(state: StateEvidence) -> tuple[Any, ...]:
    return state.dispatcher_key + (state.storage, state.data_region)


def data_key(data: DataEvidence) -> tuple[Any, ...]:
    return data.dispatcher_key + (data.storage, data.region_index)


def dispatcher_selector_registers(dispatcher: DispatcherEvidence, blocks: Sequence[BasicBlock]) -> set[str]:
    registers: set[str] = set()
    for block_index in dispatcher.selection_blocks:
        block = blocks[block_index]
        if dispatcher.indirect:
            registers.update(block.instructions[-1].registers)
        else:
            registers.update(block.registers)
    return registers - {"rip", "rsp", "rbp"}


def union_block_property(
    block_indexes: Iterable[int], blocks: Sequence[BasicBlock], property_name: str
) -> set[Any]:
    result: set[Any] = set()
    for block_index in block_indexes:
        result.update(getattr(blocks[block_index], property_name))
    return result


def discover_states(
    dispatchers: Sequence[DispatcherEvidence],
    handlers: Sequence[HandlerEvidence],
    blocks: Sequence[BasicBlock],
    data_references: dict[int, set[int]],
    data_writes: dict[int, set[int]],
    regions: Sequence[DataRegion],
) -> list[StateEvidence]:
    handlers_by_dispatcher: dict[tuple[Any, ...], list[HandlerEvidence]] = collections.defaultdict(list)
    for handler in handlers:
        handlers_by_dispatcher[handler.dispatcher_key].append(handler)
    result: list[StateEvidence] = []
    storage_order = {"register": 0, "stack": 1, "mapped_data": 2}
    for dispatcher in dispatchers:
        dispatcher_handlers = handlers_by_dispatcher.get(dispatcher.key, [])
        selection_blocks = dispatcher_context_blocks(dispatcher)
        selector_registers = dispatcher_selector_registers(dispatcher, blocks)
        selection_stack_slots = union_stack_slots(selection_blocks, blocks)
        selection_data = set().union(
            *(data_references[block_index] for block_index in selection_blocks)
        ) if selection_blocks else set()
        register_updates = tuple(
            handler_key(handler)
            for handler in dispatcher_handlers
            if handler.reenters
            and selector_registers.intersection(
                union_block_property(handler.body_blocks, blocks, "writes")
            )
        )
        if register_updates:
            result.append(StateEvidence(dispatcher.key, "register", tuple(sorted(register_updates)), None))
        stack_updates = tuple(
            handler_key(handler)
            for handler in dispatcher_handlers
            if handler.reenters
            and selection_stack_slots.intersection(
                union_stack_slots(handler.body_blocks, blocks, writes=True)
            )
        )
        if stack_updates:
            result.append(StateEvidence(dispatcher.key, "stack", tuple(sorted(stack_updates)), None))
        for data_region in sorted(selection_data):
            if not regions[data_region].writable:
                continue
            updates = tuple(
                handler_key(handler)
                for handler in dispatcher_handlers
                if handler.reenters
                and data_region in set().union(
                    *(data_writes[block_index] for block_index in handler.body_blocks)
                )
            )
            if updates:
                result.append(
                    StateEvidence(dispatcher.key, "mapped_data", tuple(sorted(updates)), data_region)
                )
    result.sort(
        key=lambda item: (
            item.dispatcher_key,
            storage_order[item.storage],
            item.data_region if item.data_region is not None else -1,
        )
    )
    return result[:MAX_CANDIDATES]


def recovered_dispatcher(dispatcher: DispatcherEvidence) -> bool:
    return dispatcher.indirect and dispatcher.recurrent and len(dispatcher.target_blocks) >= 2


def dispatcher_admits_vm_graph_analysis(
    dispatcher: DispatcherEvidence, handlers: Sequence[HandlerEvidence]
) -> bool:
    reentering_handler_count = sum(
        1
        for handler in handlers
        if handler.dispatcher_key == dispatcher.key and handler.reenters
    )
    return (
        dispatcher.recurrent
        and len(dispatcher.target_blocks) >= 2
        and reentering_handler_count >= 2
        and (dispatcher.indirect or len(dispatcher.selection_blocks) >= 2)
    )


def discover_data_candidates(
    dispatchers: Sequence[DispatcherEvidence],
    handlers: Sequence[HandlerEvidence],
    states: Sequence[StateEvidence],
    blocks: Sequence[BasicBlock],
    data_references: dict[int, set[int]],
    regions: Sequence[DataRegion],
) -> list[DataEvidence]:
    handlers_by_dispatcher: dict[tuple[Any, ...], list[HandlerEvidence]] = collections.defaultdict(list)
    states_by_dispatcher: dict[tuple[Any, ...], list[StateEvidence]] = collections.defaultdict(list)
    for handler in handlers:
        if handler.reenters:
            handlers_by_dispatcher[handler.dispatcher_key].append(handler)
    for state in states:
        states_by_dispatcher[state.dispatcher_key].append(state)
    table_targets = table_target_blocks(regions, block_for_instruction_address(blocks))
    result: list[DataEvidence] = []
    for dispatcher in dispatchers:
        dispatcher_handlers = handlers_by_dispatcher.get(dispatcher.key, [])
        handler_by_entry = {handler.entry_block: handler_key(handler) for handler in dispatcher_handlers}
        for region_index in sorted(set(dispatcher.table_regions)):
            target_handlers = tuple(
                sorted(
                    {
                        handler_by_entry[target]
                        for target in table_targets.get(region_index, ())
                        if target in handler_by_entry
                    }
                )
            )
            result.append(
                DataEvidence(
                    dispatcher.key,
                    region_index,
                    (),
                    (),
                    True,
                    target_handlers,
                    "pointer_table",
                    (),
                    (),
                    (
                        "pointer_table_control_metadata_only",
                        "handler_data_consumption_not_observed",
                        "state_selection_link_not_observed",
                    ),
                )
            )
        if not dispatcher_admits_vm_graph_analysis(dispatcher, handlers):
            continue
        block_owners = full_handler_ownership(dispatcher, blocks)
        if block_owners is None:
            continue
        selection_blocks = dispatcher_context_blocks(dispatcher)
        dispatcher_references = set().union(
            *(data_references[block_index] for block_index in selection_blocks)
        ) if selection_blocks else set()
        dispatcher_references.update(dispatcher.table_regions)
        handler_accesses: dict[
            int | None, dict[tuple[Any, ...], set[str]]
        ] = collections.defaultdict(dict)
        shared_accesses: dict[int | None, set[str]] = collections.defaultdict(set)
        for handler in dispatcher_handlers:
            key = handler_key(handler)
            exclusive_blocks: list[int] = []
            shared_blocks: list[int] = []
            for block_index in handler.body_blocks:
                if block_owners.get(block_index) == (handler.entry_block,):
                    exclusive_blocks.append(block_index)
                else:
                    shared_blocks.append(block_index)
            for region_index, modes in handler_data_consumption(
                handler, blocks, regions, exclusive_blocks
            ).items():
                handler_accesses[region_index].setdefault(key, set()).update(modes)
            for region_index, modes in handler_data_consumption(
                handler, blocks, regions, shared_blocks
            ).items():
                shared_accesses[region_index].update(modes)
        dispatcher_states = states_by_dispatcher.get(dispatcher.key, [])
        for region_index in sorted(
            handler_accesses,
            key=lambda value: (value is not None, value if value is not None else -1),
        ):
            handler_modes = handler_accesses[region_index]
            consuming_handlers = tuple(sorted(handler_modes))
            consuming_handler_set = set(consuming_handlers)
            linked_handler_keys: set[tuple[Any, ...]] = set()
            state_keys: list[tuple[Any, ...]] = []
            for state in dispatcher_states:
                if region_index is not None and state.data_region == region_index:
                    continue
                state_updates = consuming_handler_set.intersection(state.update_handlers)
                if not state_updates:
                    continue
                linked_handler_keys.update(state_updates)
                state_keys.append(state_key(state))
            if not state_keys:
                continue
            target_handlers = (
                tuple(
                    sorted(
                        {
                            handler_by_entry[target]
                            for target in table_targets.get(region_index, ())
                            if target in handler_by_entry
                        }
                    )
                )
                if region_index is not None
                else ()
            )
            modes = tuple(
                sorted({mode for values in handler_modes.values() for mode in values})
            )
            limitations = [
                "data_values_unrecovered",
                "instruction_to_state_value_flow_unrecovered",
            ]
            if region_index is None:
                limitations.extend(
                    ("dynamic_address_unresolved", "dynamic_source_identity_unresolved")
                )
            result.append(
                DataEvidence(
                    dispatcher.key,
                    region_index,
                    consuming_handlers,
                    tuple(sorted(state_keys)),
                    region_index is not None and region_index in dispatcher_references,
                    target_handlers,
                    "mapped_data" if region_index is not None else "dynamic_memory",
                    modes,
                    tuple(sorted(linked_handler_keys)),
                    tuple(limitations),
                )
            )
        for region_index in sorted(
            shared_accesses,
            key=lambda value: (value is not None, value if value is not None else -1),
        ):
            result.append(
                DataEvidence(
                    dispatcher.key,
                    region_index,
                    (),
                    (),
                    False,
                    (),
                    (
                        "shared_handler_path_mapped_data"
                        if region_index is not None
                        else "shared_handler_path_dynamic_memory"
                    ),
                    tuple(sorted(shared_accesses[region_index])),
                    (),
                    (
                        "shared_handler_path_data_excluded_from_handler_connectivity",
                        "conservative_path_ownership_may_exclude_ambiguous_or_unrecovered_handler_data",
                    ),
                )
            )
    result.sort(
        key=lambda item: (
            item.storage in SHARED_HANDLER_PATH_STORAGES,
            item.dispatcher_key,
            item.storage,
            regions[item.region_index].start if item.region_index is not None else -1,
            item.region_index if item.region_index is not None else -1,
        )
    )
    return result[:MAX_CANDIDATES]


def block_id(index: int) -> str:
    return f"block:{index:04d}"


def function_id(index: int) -> str:
    return f"function:{index:04d}"


def data_id(index: int) -> str:
    return f"data:{index:04d}"


def candidate_confidence_dispatcher(dispatcher: DispatcherEvidence) -> str:
    return "supported" if recovered_dispatcher(dispatcher) else "candidate"


def candidate_confidence_state(state: StateEvidence) -> str:
    return "supported" if len(state.update_handlers) >= 2 else "candidate"


def build_candidate_records(
    dispatchers: Sequence[DispatcherEvidence],
    handlers: Sequence[HandlerEvidence],
    states: Sequence[StateEvidence],
    data_candidates: Sequence[DataEvidence],
    blocks: Sequence[BasicBlock],
    regions: Sequence[DataRegion],
    indirect_calls: Sequence[IndirectCallEvidence] = (),
) -> tuple[
    list[dict[str, Any]],
    dict[tuple[Any, ...], DispatcherEvidence],
    dict[tuple[Any, ...], HandlerEvidence],
    dict[tuple[Any, ...], StateEvidence],
    dict[tuple[Any, ...], DataEvidence],
]:
    dispatcher_map = {item.key: item for item in dispatchers}
    handler_map = {handler_key(item): item for item in handlers}
    state_map = {state_key(item): item for item in states}
    data_map = {data_key(item): item for item in data_candidates}
    pending: list[tuple[tuple[Any, ...], dict[str, Any], Any]] = []
    kind_order = {"dispatcher": 0, "handler": 1, "state": 2, "data": 3, "indirect_call": 4}
    for item in dispatchers:
        positive = ["recurrent_control"] if item.recurrent else []
        if item.indirect:
            positive.append("indirect_transfer")
        if item.immediate_target_addresses:
            positive.append("immediate_selection_dataflow")
        if len(item.target_blocks) >= 2:
            positive.append("multiple_selection_targets")
        missing = [] if len(item.target_blocks) >= 2 else ["multiple_selection_targets"]
        if item.indirect and not item.target_blocks:
            missing.append("resolved_indirect_targets")
        record = {
            "block_ids": [block_id(block_index) for block_index in item.selection_blocks],
            "confidence": candidate_confidence_dispatcher(item),
            "evidence": {
                "immediate_selection_block_count": len(item.immediate_selection_blocks),
                "immediate_target_address_count": len(item.immediate_target_addresses),
                "immediate_source_block_ids": [
                    block_id(block_index) for block_index in item.immediate_source_blocks
                ],
                "missing": missing,
                "pointer_table_count": len(item.table_regions),
                "positive": positive,
                "resolved_indirect_target_block_ids": [
                    block_id(block_index) for block_index in item.target_blocks
                ],
                "selection_target_count": len(item.target_blocks),
                "target_recovery_limited": item.target_recovery_limited,
                "unknown_indirect_target_paths": item.indirect,
            },
            "function_region_id": function_id(item.region),
            "kind": "dispatcher",
        }
        pending.append(((blocks[item.selection_blocks[0]].start, kind_order["dispatcher"], item.key), record, item))
    for item in indirect_calls:
        table = regions[item.table_region]
        record = {
            "block_id": block_id(item.call_block),
            "confidence": "candidate",
            "data_region_id": data_id(item.table_region),
            "evidence": {
                "missing": ["dispatcher_handler_state_data_graph"],
                "pointer_table_target_count": len(table.pointer_targets),
                "pointer_width": table.pointer_width,
                "positive": [
                    "indirect_call",
                    "mapped_pointer_table",
                    "unknown_index",
                    "potential_code_targets",
                ],
                "potential_code_target_block_count": len(item.potential_target_blocks),
                "potential_code_target_block_ids": [
                    block_id(block_index) for block_index in item.potential_target_blocks
                ],
                "table_access": {
                    "address_id": address_id(item.table_access_address),
                    "index_provenance": item.index_provenance,
                    "operand_provenance": item.operand_provenance,
                },
            },
            "function_region_id": function_id(blocks[item.call_block].region),
            "kind": "indirect_call",
        }
        pending.append(
            (
                (
                    blocks[item.call_block].start,
                    kind_order["indirect_call"],
                    table.start,
                    item.table_access_address,
                    item.operand_provenance,
                    item.index_provenance,
                ),
                record,
                item,
            )
        )
    for item in handlers:
        key = handler_key(item)
        record = {
            "block_id": block_id(item.entry_block),
            "confidence": "supported" if item.reenters else "candidate",
            "evidence": {
                "body_block_count": len(item.body_blocks),
                "missing": [] if item.reenters else ["reentry"],
                "positive": ["reentry"] if item.reenters else ["selected_target"],
            },
            "function_region_id": function_id(blocks[item.entry_block].region),
            "kind": "handler",
        }
        pending.append(((blocks[item.entry_block].start, kind_order["handler"], key), record, item))
    storage_order = {"register": 0, "stack": 1, "mapped_data": 2}
    for key, item in state_map.items():
        dispatcher = dispatcher_map[item.dispatcher_key]
        record = {
            "confidence": candidate_confidence_state(item),
            "evidence": {
                "missing": [] if len(item.update_handlers) >= 2 else ["multiple_handler_updates"],
                "positive": ["selection_link", "handler_update"],
                "update_handler_count": len(item.update_handlers),
            },
            "function_region_id": function_id(dispatcher.region),
            "kind": "state",
            "storage": item.storage,
        }
        if item.data_region is not None:
            record["data_region_id"] = data_id(item.data_region)
        pending.append(
            (
                (
                    blocks[dispatcher.selection_blocks[0]].start,
                    kind_order["state"],
                    storage_order[item.storage],
                    item.data_region if item.data_region is not None else -1,
                ),
                record,
                item,
            )
        )
    for key, item in data_map.items():
        dispatcher = dispatcher_map[item.dispatcher_key]
        consumption_count = len(item.handler_keys)
        state_linked = bool(item.state_keys)
        is_shared_handler_path = item.storage in SHARED_HANDLER_PATH_STORAGES
        supported = (
            not is_shared_handler_path
            and state_linked
            and bool(item.consumption_modes)
            and bool(item.linked_handler_keys)
        )
        if item.storage == "pointer_table":
            positive = ["mapped_pointer_table"]
            if item.table_target_handlers:
                positive.append("potential_handler_targets")
            missing = ["handler_data_consumption", "state_selection_link"]
            hypothesis = "control_table_like"
        elif is_shared_handler_path:
            positive = ["shared_handler_path_data_observation", *item.consumption_modes]
            missing = ["exclusive_handler_data_consumption_path"]
            hypothesis = "shared_handler_path_data_observation"
        else:
            positive = [
                "handler_data_consumption",
                "state_selection_link",
                *item.consumption_modes,
            ]
            missing = [] if supported else ["connected_handler_data_consumption_path"]
            hypothesis = "data_consumption_like"
        record = {
            "confidence": "supported" if supported else "candidate",
            "hypothesis": hypothesis,
            "evidence": {
                "data_consumption": {
                    "linked_state_update_handler_count": len(item.linked_handler_keys),
                    "modes": list(item.consumption_modes),
                    "observed": bool(item.consumption_modes),
                    "source": item.storage,
                },
                "dispatcher_reference": item.dispatch_reference,
                "handler_data_consumption_count": consumption_count,
                "handler_reference_count": consumption_count,
                "limitations": list(item.limitations),
                "missing": missing,
                "pointer_target_count": (
                    len(regions[item.region_index].pointer_targets)
                    if item.region_index is not None
                    else 0
                ),
                "positive": positive,
                "state_link": state_linked,
            },
            "function_region_id": function_id(dispatcher.region),
            "kind": "data",
            "storage": item.storage,
        }
        if is_shared_handler_path:
            record["evidence"]["shared_handler_path"] = {
                "excluded_from_handler_connectivity": True,
            }
        if item.region_index is not None:
            record["data_region_id"] = data_id(item.region_index)
        pending.append(
            (
                (
                    (
                        regions[item.region_index].start
                        if item.region_index is not None
                        else blocks[dispatcher.selection_blocks[0]].start
                    ),
                    kind_order["data"],
                    item.dispatcher_key,
                    item.storage,
                    item.region_index if item.region_index is not None else -1,
                ),
                record,
                item,
            )
        )
    pending.sort(key=lambda item: item[0])
    records: list[dict[str, Any]] = []
    for index, (_, record, evidence) in enumerate(pending):
        record["id"] = f"candidate:{index:04d}"
        records.append(record)
        if isinstance(evidence, DispatcherEvidence):
            evidence.candidate_id = record["id"]
        elif isinstance(evidence, HandlerEvidence):
            evidence.candidate_id = record["id"]
        elif isinstance(evidence, StateEvidence):
            evidence.candidate_id = record["id"]
        elif isinstance(evidence, DataEvidence):
            evidence.candidate_id = record["id"]
    return records, dispatcher_map, handler_map, state_map, data_map


def build_relationships(
    dispatchers: Sequence[DispatcherEvidence],
    handlers: Sequence[HandlerEvidence],
    states: Sequence[StateEvidence],
    data_candidates: Sequence[DataEvidence],
    handler_map: dict[tuple[Any, ...], HandlerEvidence],
    state_map: dict[tuple[Any, ...], StateEvidence],
    data_map: dict[tuple[Any, ...], DataEvidence],
) -> list[dict[str, Any]]:
    pending: dict[tuple[str, str, str], set[str]] = collections.defaultdict(set)

    def add(source: str, target: str, relation_type: str, evidence: str) -> None:
        if source and target:
            pending[(relation_type, source, target)].add(evidence)

    handlers_by_dispatcher: dict[tuple[Any, ...], list[HandlerEvidence]] = collections.defaultdict(list)
    states_by_dispatcher: dict[tuple[Any, ...], list[StateEvidence]] = collections.defaultdict(list)
    data_by_dispatcher: dict[tuple[Any, ...], list[DataEvidence]] = collections.defaultdict(list)
    for handler in handlers:
        handlers_by_dispatcher[handler.dispatcher_key].append(handler)
    for state in states:
        states_by_dispatcher[state.dispatcher_key].append(state)
    for data in data_candidates:
        data_by_dispatcher[data.dispatcher_key].append(data)
    for dispatcher in dispatchers:
        for handler in handlers_by_dispatcher.get(dispatcher.key, []):
            add(dispatcher.candidate_id, handler.candidate_id, "dispatcher_selects_handler", "selection_target")
            if handler.reenters:
                add(handler.candidate_id, dispatcher.candidate_id, "handler_reenters_dispatcher", "reentry")
        for state in states_by_dispatcher.get(dispatcher.key, []):
            add(state.candidate_id, dispatcher.candidate_id, "state_selects_dispatcher", "selection_link")
            for update_key in state.update_handlers:
                handler = handler_map.get(update_key)
                if handler is not None:
                    add(handler.candidate_id, state.candidate_id, "handler_updates_state", "state_update")
        for data in data_by_dispatcher.get(dispatcher.key, []):
            if data.storage in SHARED_HANDLER_PATH_STORAGES:
                continue
            if data.dispatch_reference:
                add(dispatcher.candidate_id, data.candidate_id, "dispatcher_references_data", "data_reference")
            for handler_key_value in data.handler_keys:
                handler = handler_map.get(handler_key_value)
                if handler is not None:
                    add(handler.candidate_id, data.candidate_id, "handler_references_data", "data_consumption")
            for handler_key_value in data.table_target_handlers:
                handler = handler_map.get(handler_key_value)
                if handler is not None:
                    add(data.candidate_id, handler.candidate_id, "data_selects_handler", "pointer_target")
            for state_key_value in data.state_keys:
                state = state_map.get(state_key_value)
                if (
                    state is not None
                    and set(data.linked_handler_keys).intersection(state.update_handlers)
                ):
                    add(
                        data.candidate_id,
                        state.candidate_id,
                        "data_supports_state",
                        "handler_data_consumption_path",
                    )
    ordered = sorted(
        (
            relation_type,
            source,
            target,
            tuple(sorted(evidence)),
        )
        for (relation_type, source, target), evidence in pending.items()
    )
    return [
        {
            "evidence": list(evidence),
            "id": f"relationship:{index:04d}",
            "source": source,
            "target": target,
            "type": relation_type,
        }
        for index, (relation_type, source, target, evidence) in enumerate(ordered)
    ]


def connected_nodes(nodes: set[str], relationships: Sequence[dict[str, Any]]) -> bool:
    if not nodes:
        return False
    adjacency: dict[str, set[str]] = {node: set() for node in nodes}
    for relationship in relationships:
        source = relationship["source"]
        target = relationship["target"]
        if source in adjacency and target in adjacency:
            adjacency[source].add(target)
            adjacency[target].add(source)
    seen = {next(iter(nodes))}
    queue = collections.deque(seen)
    while queue:
        source = queue.popleft()
        for target in sorted(adjacency[source]):
            if target not in seen:
                seen.add(target)
                queue.append(target)
    return seen == nodes


def assess_recovery(
    dispatchers: Sequence[DispatcherEvidence],
    handlers: Sequence[HandlerEvidence],
    states: Sequence[StateEvidence],
    data_candidates: Sequence[DataEvidence],
    relationships: Sequence[dict[str, Any]],
    unavailable: bool = False,
    indirect_calls: Sequence[IndirectCallEvidence] = (),
) -> str:
    if unavailable:
        return "unavailable"
    handlers_by_dispatcher: dict[tuple[Any, ...], list[HandlerEvidence]] = collections.defaultdict(list)
    states_by_dispatcher: dict[tuple[Any, ...], list[StateEvidence]] = collections.defaultdict(list)
    data_by_dispatcher: dict[tuple[Any, ...], list[DataEvidence]] = collections.defaultdict(list)
    for handler in handlers:
        handlers_by_dispatcher[handler.dispatcher_key].append(handler)
    for state in states:
        states_by_dispatcher[state.dispatcher_key].append(state)
    for data in data_candidates:
        data_by_dispatcher[data.dispatcher_key].append(data)
    has_control_handler_graph = False
    for dispatcher in dispatchers:
        reentering = [
            handler
            for handler in handlers_by_dispatcher.get(dispatcher.key, [])
            if handler.reenters
        ]
        if not (dispatcher.recurrent and len(dispatcher.target_blocks) >= 2 and len(reentering) >= 2):
            continue
        has_control_handler_graph = True
        if not dispatcher_admits_vm_graph_analysis(dispatcher, handlers):
            continue
        reentering_keys = {handler_key(handler) for handler in reentering}
        for state in states_by_dispatcher.get(dispatcher.key, []):
            updating = set(state.update_handlers) & reentering_keys
            if len(updating) < 2:
                continue
            for data in data_by_dispatcher.get(dispatcher.key, []):
                if (
                    data.storage not in {"dynamic_memory", "mapped_data"}
                    or not data.consumption_modes
                    or not data.linked_handler_keys
                    or state_key(state) not in data.state_keys
                    or not set(data.linked_handler_keys).intersection(updating)
                ):
                    continue
                selected_handlers = sorted(updating)[:2]
                candidate_handlers = {
                    handler.candidate_id
                    for handler in reentering
                    if handler_key(handler) in selected_handlers
                }
                nodes = {
                    dispatcher.candidate_id,
                    state.candidate_id,
                    data.candidate_id,
                    *candidate_handlers,
                }
                if connected_nodes(nodes, relationships):
                    return "vm_candidate"
    if has_control_handler_graph:
        return "interpreter_like"
    if dispatchers or handlers or states or data_candidates or indirect_calls:
        return "partial"
    return "inconclusive"


def score_recovery(
    dispatchers: Sequence[DispatcherEvidence],
    handlers: Sequence[HandlerEvidence],
    states: Sequence[StateEvidence],
    data_candidates: Sequence[DataEvidence],
    indirect_calls: Sequence[IndirectCallEvidence] = (),
) -> dict[str, int]:
    handlers_by_dispatcher: dict[tuple[Any, ...], list[HandlerEvidence]] = collections.defaultdict(list)
    states_by_dispatcher: dict[tuple[Any, ...], list[StateEvidence]] = collections.defaultdict(list)
    data_by_dispatcher: dict[tuple[Any, ...], list[DataEvidence]] = collections.defaultdict(list)
    for handler in handlers:
        handlers_by_dispatcher[handler.dispatcher_key].append(handler)
    for state in states:
        states_by_dispatcher[state.dispatcher_key].append(state)
    for data in data_candidates:
        data_by_dispatcher[data.dispatcher_key].append(data)
    control = 0
    handler_score = 0
    state_score = 0
    data_score = 0
    if indirect_calls:
        control = max(control, INDIRECT_CALL_OBSERVATION_CONTROL_SCORE)
    for dispatcher in dispatchers:
        local_control = 6
        if dispatcher.recurrent:
            local_control += 8
        if dispatcher.indirect or len(dispatcher.target_blocks) >= 2:
            local_control += 8
        reentering = sum(
            handler.reenters
            for handler in handlers_by_dispatcher.get(dispatcher.key, [])
        )
        if reentering >= 2:
            local_control += 8
        control = max(control, min(30, local_control))
        handler_score = max(
            handler_score,
            min(25, 8 * min(reentering, 3) + (1 if reentering >= 2 else 0)),
        )
        for state in states_by_dispatcher.get(dispatcher.key, []):
            local_state = 8 + min(12, 6 * len(state.update_handlers))
            if state.data_region is not None:
                local_state += 3
            state_score = max(state_score, min(25, local_state))
        for data in data_by_dispatcher.get(dispatcher.key, []):
            if (
                data.storage not in {"dynamic_memory", "mapped_data"}
                or not data.consumption_modes
                or not data.linked_handler_keys
                or not data.state_keys
            ):
                continue
            local_data = 5 if data.dispatch_reference else 0
            local_data += min(10, 5 * len(data.handler_keys))
            if data.state_keys:
                local_data += 5
            if data.table_target_handlers:
                local_data += 2
            data_score = max(data_score, min(20, local_data))
    structural = min(100, control + handler_score + state_score + data_score)
    return {
        "control": control,
        "data": data_score,
        "handlers": handler_score,
        "state": state_score,
        "structural": structural,
    }


def serialize_function_regions(
    function_regions: Sequence[FunctionRegion],
    blocks: Sequence[BasicBlock],
    sccs: Sequence[tuple[int, ...]],
) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for region in function_regions:
        members = [blocks[index] for index in region.blocks]
        member_sccs = sorted({block.scc for block in members})
        result.append(
            {
                "block_count": len(members),
                "entry_points": [address_id(address) for address in region.roots],
                "id": function_id(region.index),
                "loop_scc_count": sum(scc_is_loop(sccs[index], blocks) for index in member_sccs),
                "range": range_dict(min(block.start for block in members), max(block.end for block in members)),
                "scc_count": len(member_sccs),
            }
        )
    return result


def serialize_basic_blocks(blocks: Sequence[BasicBlock]) -> list[dict[str, Any]]:
    return [
        {
            "function_region_id": function_id(block.region),
            "has_unknown_successor": block.unknown_successor,
            "id": block_id(block.index),
            "instruction_count": len(block.instructions),
            "range": range_dict(block.start, block.end),
            "scc_id": f"scc:{block.scc:04d}",
            "successors": [block_id(successor) for successor in block.successors],
            "terminator": block.terminator,
        }
        for block in blocks
    ]


def serialize_sccs(sccs: Sequence[tuple[int, ...]], blocks: Sequence[BasicBlock]) -> list[dict[str, Any]]:
    return [
        {
            "block_ids": [block_id(block_index) for block_index in component],
            "id": f"scc:{index:04d}",
            "loop": scc_is_loop(component, blocks),
        }
        for index, component in enumerate(sccs)
    ]


def serialize_data_regions(
    regions: Sequence[DataRegion],
    blocks: Sequence[BasicBlock],
    data_references: dict[int, set[int]],
) -> list[dict[str, Any]]:
    reference_counts: dict[int, int] = collections.Counter(
        reference
        for references in data_references.values()
        for reference in references
    )
    address_to_block = block_for_instruction_address(blocks)
    result: list[dict[str, Any]] = []
    for region in regions:
        target_count = len(
            {
                address_to_block[target]
                for target in region.pointer_targets
                if target in address_to_block
            }
        )
        result.append(
            {
                "id": data_id(region.index),
                "kind": region.kind,
                "pointer_count": len(region.pointer_targets),
                "pointer_width": region.pointer_width,
                "range": range_dict(region.start, region.end),
                "referencing_block_count": reference_counts.get(region.index, 0),
                "target_block_count": target_count,
                "writable": region.writable,
            }
        )
    return result


def empty_recovery(classification: str) -> dict[str, Any]:
    return {
        "assessment": {
            "classification": classification,
            "semantic_recovery": "unavailable",
        },
        "basic_blocks": [],
        "candidates": [],
        "data_regions": [],
        "function_regions": [],
        "indirect_transfer_recovery": {
            "immediate_selection_branch_count": 0,
            "resolved_branch_count": 0,
            "unknown_successor_branch_count": 0,
        },
        "relationships": [],
        "sccs": [],
        "score_caps": {
            "control": 30,
            "data": 20,
            "handlers": 25,
            "state": 25,
            "structural": 100,
        },
        "scores": {
            "control": 0,
            "data": 0,
            "handlers": 0,
            "state": 0,
            "structural": 0,
        },
    }


def recover_structure(
    data: bytes,
    parsed: ParsedElf,
    objdump_output: bytes,
) -> tuple[dict[str, Any], list[Issue], bool]:
    issues: list[Issue] = []
    address_map = AddressMap(parsed.loads)
    instructions, instruction_issues = parse_disassembly(objdump_output, address_map)
    issues.extend(instruction_issues)
    if not instructions:
        return empty_recovery("unavailable"), unique_issues(issues), False
    blocks, _, _ = build_basic_blocks(instructions, address_map, parsed.entry)
    if len(blocks) >= MAX_BASIC_BLOCKS:
        issues.append(Issue("basic_block_count_limit", "error"))
    if not blocks:
        return empty_recovery("unavailable"), unique_issues(issues), False
    sccs, scc_by_block = compute_sccs(blocks)
    function_regions, region_by_block = compute_function_regions(blocks, parsed.entry)
    for block in blocks:
        block.scc = scc_by_block[block.index]
        block.region = region_by_block[block.index]
    data_regions = discover_data_regions(data, parsed.loads, address_map, issues)
    data_references, data_writes = block_data_region_sets(blocks, data_regions)
    indirect_calls = discover_indirect_call_evidence(blocks, data_regions, address_map)
    target_recoveries = recover_indirect_jump_targets(blocks, address_map)
    if any(recovery.limited for recovery in target_recoveries.values()):
        issues.append(Issue("indirect_target_recovery_limited", "warning"))
    dispatchers = discover_dispatchers(
        blocks,
        sccs,
        region_by_block,
        data_references,
        data_regions,
        target_recoveries,
    )
    apply_resolved_indirect_targets(dispatchers, blocks)
    sccs, scc_by_block = compute_sccs(blocks)
    function_regions, region_by_block = compute_function_regions(blocks, parsed.entry)
    for block in blocks:
        block.scc = scc_by_block[block.index]
        block.region = region_by_block[block.index]
    refresh_dispatcher_graph(dispatchers, blocks, region_by_block)
    handlers = discover_handlers(dispatchers, blocks)
    states = discover_states(
        dispatchers,
        handlers,
        blocks,
        data_references,
        data_writes,
        data_regions,
    )
    data_candidates = discover_data_candidates(
        dispatchers,
        handlers,
        states,
        blocks,
        data_references,
        data_regions,
    )
    candidate_records, _, handler_map, state_map, data_map = build_candidate_records(
        dispatchers,
        handlers,
        states,
        data_candidates,
        blocks,
        data_regions,
        indirect_calls=indirect_calls,
    )
    relationships = build_relationships(
        dispatchers,
        handlers,
        states,
        data_candidates,
        handler_map,
        state_map,
        data_map,
    )
    classification = assess_recovery(
        dispatchers,
        handlers,
        states,
        data_candidates,
        relationships,
        indirect_calls=indirect_calls,
    )
    recovery = {
        "assessment": {
            "classification": classification,
            "semantic_recovery": "unavailable",
        },
        "basic_blocks": serialize_basic_blocks(blocks),
        "candidates": candidate_records,
        "data_regions": serialize_data_regions(data_regions, blocks, data_references),
        "function_regions": serialize_function_regions(function_regions, blocks, sccs),
        "indirect_transfer_recovery": {
            "immediate_selection_branch_count": sum(
                bool(item.immediate_target_addresses) for item in dispatchers
            ),
            "resolved_branch_count": sum(
                item.indirect and bool(item.target_blocks) for item in dispatchers
            ),
            "unknown_successor_branch_count": sum(
                block.unknown_successor and block.terminator == "indirect_branch"
                for block in blocks
            ),
        },
        "relationships": relationships,
        "sccs": serialize_sccs(sccs, blocks),
        "score_caps": {
            "control": 30,
            "data": 20,
            "handlers": 25,
            "state": 25,
            "structural": 100,
        },
        "scores": score_recovery(
            dispatchers, handlers, states, data_candidates, indirect_calls=indirect_calls
        ),
    }
    return recovery, unique_issues(issues), True


def metadata_exposure(metadata: dict[str, int]) -> dict[str, Any]:
    return {
        "dynamic": {
            "entry_count": metadata["dynamic_entries"],
            "table_count": metadata["dynamic_tables"],
        },
        "names_used_for_recovery": False,
        "relocations": {
            "entry_count": metadata["relocation_entries"],
            "table_count": metadata["relocation_tables"],
        },
        "score_contribution": 0,
        "section_header_count": metadata["section_headers"],
        "symbols": {
            "dynamic_entry_count": metadata["dynamic_symbols"],
            "static_entry_count": metadata["static_symbols"],
        },
    }


def elf_facts(parsed: ParsedElf | None) -> dict[str, Any]:
    if parsed is None or parsed.elf_type is None:
        return {
            "class": "unavailable",
            "endianness": "unavailable",
            "entry_point": None,
            "load_segments": [],
            "machine": "unavailable",
            "type": "unavailable",
        }
    if parsed.elf_type == ET_EXEC:
        type_name = "ET_EXEC"
    elif parsed.elf_type == ET_DYN:
        type_name = "ET_DYN"
    else:
        type_name = "unsupported"
    return {
        "class": "ELF64",
        "endianness": "little",
        "entry_point": address_id(parsed.entry) if parsed.entry is not None else None,
        "load_segments": [
            {
                "alignment": load.align,
                "file_size": load.filesz,
                "flags": segment_flags(load.flags),
                "id": f"load:{load.index:04d}",
                "memory_size": load.memsz,
                "range": range_dict(load.vaddr, load.memory_end),
            }
            for load in sorted(parsed.loads, key=lambda item: item.index)
        ],
        "machine": "x86-64",
        "type": type_name,
    }


def unavailable_capabilities() -> dict[str, str]:
    return {
        "cfg_recovery": "unavailable",
        "disassembly": "unavailable",
        "dynamic": "unavailable",
        "elf": "unavailable",
        "instruction_recovery": "unavailable",
        "load_layout": "unavailable",
        "relocations": "unavailable",
        "sections": "unavailable",
        "semantic_recovery": "unavailable",
        "symbols": "unavailable",
    }


def parsed_capabilities(parsed: ParsedElf, recovered: bool, has_instructions: bool) -> dict[str, str]:
    return {
        "cfg_recovery": "available" if recovered else "unavailable",
        "disassembly": "available",
        "dynamic": "available" if parsed.metadata["dynamic_tables"] else "absent",
        "elf": "available",
        "instruction_recovery": "available" if has_instructions else "unavailable",
        "load_layout": "available",
        "relocations": "available" if parsed.metadata["relocation_tables"] else "absent",
        "sections": "available" if parsed.metadata["section_headers"] else "absent",
        "semantic_recovery": "unavailable",
        "symbols": (
            "available"
            if parsed.metadata["static_symbols"] or parsed.metadata["dynamic_symbols"]
            else "absent"
        ),
    }


def status_for_issues(issues: Sequence[Issue], available: bool) -> str:
    if not available:
        return "unavailable"
    if any(issue.severity == "error" for issue in issues):
        return "partial"
    return "analyzed"


def _analyze_artifact(
    binary_path: str, llvm_objdump: str, artifact: ArtifactBytes
) -> dict[str, Any]:
    identity = {"sha256": artifact.sha256, "size": artifact.size}
    if artifact.data is None:
        return {
            "capabilities": unavailable_capabilities(),
            "elf": elf_facts(None),
            "identity": identity,
            "issues": [issue.as_dict() for issue in unique_issues(artifact.issues)],
            "metadata_exposure": metadata_exposure(empty_metadata()),
            "recovery": empty_recovery("unavailable"),
            "status": "unavailable",
        }
    parsed = parse_elf(artifact.data)
    parse_issues = unique_issues(parsed.issues)
    if not parsed.usable:
        return {
            "capabilities": unavailable_capabilities() | {
                "elf": "available" if parsed.supported else "unavailable",
                "load_layout": "available" if parsed.loads else "unavailable",
            },
            "elf": elf_facts(parsed),
            "identity": identity,
            "issues": [issue.as_dict() for issue in parse_issues],
            "metadata_exposure": metadata_exposure(parsed.metadata),
            "recovery": empty_recovery("unavailable"),
            "status": "unavailable",
        }
    tool_result = run_objdump(llvm_objdump, binary_path)
    if tool_result.outcome != "ok":
        issues = unique_issues([*parse_issues, Issue(tool_result.outcome, "error")])
        return {
            "capabilities": unavailable_capabilities() | {
                "dynamic": "available" if parsed.metadata["dynamic_tables"] else "absent",
                "elf": "available",
                "load_layout": "available",
                "relocations": "available" if parsed.metadata["relocation_tables"] else "absent",
                "sections": "available" if parsed.metadata["section_headers"] else "absent",
                "symbols": (
                    "available"
                    if parsed.metadata["static_symbols"] or parsed.metadata["dynamic_symbols"]
                    else "absent"
                ),
            },
            "elf": elf_facts(parsed),
            "identity": identity,
            "issues": [issue.as_dict() for issue in issues],
            "metadata_exposure": metadata_exposure(parsed.metadata),
            "recovery": empty_recovery("unavailable"),
            "status": "unavailable",
        }
    recovery, recovery_issues, recovered = recover_structure(artifact.data, parsed, tool_result.stdout)
    all_issues = unique_issues([*parse_issues, *recovery_issues])
    has_instructions = bool(recovery["basic_blocks"])
    return {
        "capabilities": parsed_capabilities(parsed, recovered, has_instructions),
        "elf": elf_facts(parsed),
        "identity": identity,
        "issues": [issue.as_dict() for issue in all_issues],
        "metadata_exposure": metadata_exposure(parsed.metadata),
        "recovery": recovery,
        "status": status_for_issues(all_issues, True),
    }


def analyze_artifact(binary_path: str, llvm_objdump: str) -> dict[str, Any]:
    artifact = read_artifact(binary_path)
    try:
        return _analyze_artifact(binary_path, llvm_objdump, artifact)
    except Exception:
        return {
            "capabilities": unavailable_capabilities(),
            "elf": elf_facts(None),
            "identity": {"sha256": artifact.sha256, "size": artifact.size},
            "issues": [Issue("analysis_internal_error", "error").as_dict()],
            "metadata_exposure": metadata_exposure(empty_metadata()),
            "recovery": empty_recovery("unavailable"),
            "status": "unavailable",
        }


def add_gate_results(
    artifacts: Sequence[dict[str, Any]], strict: bool, maximum_score: int | None
) -> int:
    failures = 0
    for artifact in artifacts:
        strict_failure = strict and any(
            issue["severity"] == "error" for issue in artifact["issues"]
        )
        threshold_failure = (
            maximum_score is not None
            and artifact["recovery"]["scores"]["structural"] > maximum_score
        )
        artifact["gate"] = {
            "score_threshold_failed": threshold_failure,
            "strict_failed": strict_failure,
        }
        if strict_failure or threshold_failure:
            failures += 1
    return failures


def artifact_sort_key(artifact: dict[str, Any]) -> tuple[Any, ...]:
    digest = artifact["identity"]["sha256"]
    return (
        0 if digest is not None else 1,
        digest or "",
        artifact["identity"]["size"],
        json.dumps(artifact, sort_keys=True, separators=(",", ":")),
    )


def build_payload(
    artifacts: list[dict[str, Any]], strict: bool, maximum_score: int | None
) -> dict[str, Any]:
    artifacts.sort(key=artifact_sort_key)
    failures = add_gate_results(artifacts, strict, maximum_score)
    classifications = collections.Counter(
        artifact["recovery"]["assessment"]["classification"] for artifact in artifacts
    )
    statuses = collections.Counter(artifact["status"] for artifact in artifacts)
    summary = {
        "artifact_count": len(artifacts),
        "classifications": dict(sorted(classifications.items())),
        "fail_max_recovery_score": maximum_score,
        "failures": failures,
        "max_structural_score": max(
            (artifact["recovery"]["scores"]["structural"] for artifact in artifacts),
            default=0,
        ),
        "status": "failed" if failures else "passed",
        "statuses": dict(sorted(statuses.items())),
        "strict": strict,
    }
    return {
        "analysis_boundary": "binary-only",
        "artifacts": artifacts,
        "report_kind": "binary_vm_recovery",
        "schema_version": SCHEMA_VERSION,
        "summary": summary,
        "tool": "obf-re-harness-binary",
    }


def write_payload(path_text: str, payload: dict[str, Any]) -> None:
    path = pathlib.Path(path_text)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def print_report(payload: dict[str, Any], verbose: bool) -> None:
    summary = payload["summary"]
    print("binary vm recovery report")
    print(f"  artifacts: {summary['artifact_count']}")
    print(f"  failures: {summary['failures']}")
    for classification, count in summary["classifications"].items():
        print(f"  classification.{classification}: {count}")
    if verbose:
        for artifact in payload["artifacts"]:
            digest = artifact["identity"]["sha256"] or "unavailable"
            assessment = artifact["recovery"]["assessment"]
            print(
                "  artifact"
                f" sha256={digest}"
                f" status={artifact['status']}"
                f" classification={assessment['classification']}"
                f" structural={artifact['recovery']['scores']['structural']}"
            )


def nonnegative_score(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("expected a non-negative integer") from error
    if parsed < 0 or parsed > 100:
        raise argparse.ArgumentTypeError("expected an integer from 0 through 100")
    return parsed


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="measure structural binary-level recovery evidence from explicit elf artifacts"
    )
    parser.add_argument(
        "--binary",
        action="append",
        required=True,
        metavar="PATH",
        help="explicit elf artifact to analyze",
    )
    parser.add_argument(
        "--llvm-objdump",
        required=True,
        metavar="PATH",
        help="llvm-objdump executable",
    )
    parser.add_argument(
        "--json-out",
        required=True,
        metavar="PATH",
        help="deterministic report path",
    )
    parser.add_argument("--strict", action="store_true", help="fail after writing records with errors")
    parser.add_argument(
        "--fail-max-recovery-score",
        type=nonnegative_score,
        metavar="N",
        help="fail after writing when a structural score exceeds n",
    )
    parser.add_argument("--verbose", action="store_true", help="print deterministic artifact summaries")
    return parser.parse_args(argv)


def main(argv: Sequence[str]) -> int:
    args = parse_args(argv)
    artifacts = [
        analyze_artifact(binary_path, args.llvm_objdump)
        for binary_path in args.binary
    ]
    payload = build_payload(artifacts, args.strict, args.fail_max_recovery_score)
    write_payload(args.json_out, payload)
    print_report(payload, args.verbose)
    return 1 if payload["summary"]["failures"] else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
