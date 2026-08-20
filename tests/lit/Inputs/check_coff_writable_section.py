import pathlib
import struct
import sys

IMAGE_SCN_MEM_WRITE = 0x80000000


def read_name(raw_name, string_table):
    if raw_name[:4] == b"\0\0\0\0":
        offset = struct.unpack_from("<I", raw_name, 4)[0]
        if offset < 4 or offset >= len(string_table):
            raise SystemExit("invalid COFF string-table symbol offset")
        end = string_table.find(b"\0", offset)
        if end < 0:
            raise SystemExit("unterminated COFF string-table symbol")
        return string_table[offset:end].decode("ascii", "replace")
    return raw_name.rstrip(b"\0").decode("ascii", "replace")


def main():
    if len(sys.argv) != 3:
        raise SystemExit("usage: check_coff_writable_section.py <obj> <symbol>")
    data = pathlib.Path(sys.argv[1]).read_bytes()
    target_name = sys.argv[2]
    if len(data) < 20 or data[:2] != b"\x64\x86":
        raise SystemExit("not COFF x86-64")
    section_count = struct.unpack_from("<H", data, 2)[0]
    symbol_ptr, symbol_count = struct.unpack_from("<II", data, 8)
    section_table = 20
    section_end = section_table + section_count * 40
    if section_end > len(data):
        raise SystemExit("truncated COFF section table")

    sections = {}
    for index in range(section_count):
        offset = section_table + index * 40
        name = data[offset : offset + 8].rstrip(b"\0").decode("ascii", "replace")
        characteristics = struct.unpack_from("<I", data, offset + 36)[0]
        sections[index + 1] = (name, characteristics)

    symbol_end = symbol_ptr + symbol_count * 18
    if symbol_ptr <= 0 or symbol_end + 4 > len(data):
        raise SystemExit("invalid COFF symbol table bounds")
    string_size = struct.unpack_from("<I", data, symbol_end)[0]
    if string_size < 4 or symbol_end + string_size > len(data):
        raise SystemExit("invalid COFF string table bounds")
    string_table = data[symbol_end : symbol_end + string_size]

    target = None
    index = 0
    while index < symbol_count:
        offset = symbol_ptr + index * 18
        name = read_name(data[offset : offset + 8], string_table)
        section_number = struct.unpack_from("<h", data, offset + 12)[0]
        aux_count = data[offset + 17]
        if name == target_name:
            if target is not None:
                raise SystemExit(f"duplicate {target_name} symbols")
            target = section_number
        index += 1 + aux_count

    if target is None:
        raise SystemExit(f"missing {target_name} symbol")
    if target <= 0 or target not in sections:
        raise SystemExit(f"{target_name} has invalid section number")
    section_name, characteristics = sections[target]
    if not (characteristics & IMAGE_SCN_MEM_WRITE):
        raise SystemExit(
            f"{target_name} section is not writable: name={section_name} flags=0x{characteristics:08X}"
        )
    print(f"COFF_DESTINATION: symbol={target_name} name={section_name} flags=0x{characteristics:08X}")


if __name__ == "__main__":
    main()
