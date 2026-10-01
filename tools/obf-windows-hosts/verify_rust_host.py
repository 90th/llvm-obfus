import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess


class PeImage:
    def __init__(self, path):
        self.data = Path(path).read_bytes()
        if self.data[:2] != b"MZ":
            raise ValueError(f"not a PE image: {path}")
        pe = self.u32(0x3C)
        if self.data[pe:pe + 4] != b"PE\0\0" or self.u16(pe + 4) != 0x8664:
            raise ValueError(f"Rust host must be x86-64 PE: {path}")
        optional = pe + 24
        if self.u16(optional) != 0x20B:
            raise ValueError(f"Rust host must use PE32+: {path}")
        self.directories = optional + 112
        section = optional + self.u16(pe + 20)
        self.sections = []
        for index in range(self.u16(pe + 6)):
            entry = section + index * 40
            self.sections.append((self.u32(entry + 12), self.u32(entry + 16), self.u32(entry + 20)))

    def u16(self, offset):
        return struct.unpack_from("<H", self.data, offset)[0]

    def u32(self, offset):
        return struct.unpack_from("<I", self.data, offset)[0]

    def offset(self, rva):
        for virtual, size, raw in self.sections:
            if virtual <= rva < virtual + size:
                result = raw + rva - virtual
                if result < len(self.data):
                    return result
        raise ValueError(f"unmapped PE RVA: {rva:#x}")

    def text(self, rva):
        start = self.offset(rva)
        end = self.data.find(b"\0", start)
        if end == -1:
            raise ValueError("unterminated PE name")
        return self.data[start:end].decode("ascii")

    def imports(self):
        rva = self.u32(self.directories + 8)
        size = self.u32(self.directories + 12)
        if not rva:
            return set()
        result = set()
        for relative in range(0, size, 20):
            entry = self.offset(rva + relative)
            words = struct.unpack_from("<5I", self.data, entry)
            if not any(words):
                return result
            result.add(self.text(words[3]).lower())
        raise ValueError("unterminated PE import table")

    def exports(self):
        rva = self.u32(self.directories)
        if not rva:
            return set()
        entry = self.offset(rva)
        count = self.u32(entry + 24)
        table = self.offset(self.u32(entry + 32))
        return {self.text(self.u32(table + index * 4)) for index in range(count)}


def import_library_owners(path):
    data = Path(path).read_bytes()
    if data[:8] != b"!<arch>\n":
        raise ValueError("Rust host import library is not a COFF archive")
    owners = set()
    cursor = 8
    while cursor < len(data):
        if cursor + 60 > len(data) or data[cursor + 58:cursor + 60] != b"`\n":
            raise ValueError("invalid import-library archive member")
        size = int(data[cursor + 48:cursor + 58])
        body = cursor + 60
        end = body + size
        if end > len(data):
            raise ValueError("truncated import-library archive member")
        if size >= 20 and data[body:body + 4] == b"\0\0\xff\xff":
            if struct.unpack_from("<H", data, body + 6)[0] != 0x8664:
                raise ValueError("Rust host import library must target x86-64")
            first = data.index(b"\0", body + 20, end)
            last = data.index(b"\0", first + 1, end)
            owners.add(data[first + 1:last].decode("ascii").lower())
        cursor = end + (size & 1)
    if not owners:
        raise ValueError("archive has no COFF short import records")
    return owners


def validate(rustc, image, library, llvm_version):
    rustc = Path(rustc).resolve(strict=True)
    image = Path(image).resolve(strict=True)
    library = Path(library).resolve(strict=True)
    if image.parent.resolve() != rustc.parent.resolve():
        raise ValueError(
            f"Rust LLVM owner DLL ({image}) must be in the same directory as rustc ({rustc}) "
            "so the Windows dynamic loader loads the verified image."
        )
    if not re.fullmatch(r"rustc_driver(?:-[0-9a-f]+)?\.dll", image.name, re.IGNORECASE):
        raise ValueError("Rust LLVM owner must be a rustc_driver DLL")
    if image.name.lower() not in PeImage(rustc).imports():
        raise ValueError("bound rustc does not import the configured Rust LLVM owner")
    if import_library_owners(library) != {image.name.lower()}:
        raise ValueError("Rust import library does not bind exclusively to its configured owner")
    required = {
        "?semBogus@APFloatBase@llvm@@0UfltSemantics@2@B",
        "?get@ConstantFP@llvm@@SAPEAV12@AEAVLLVMContext@2@AEBVAPFloat@2@@Z",
    }
    if not required <= PeImage(image).exports():
        raise ValueError("Rust owner lacks canonical LLVM floating-point API exports")
    result = subprocess.run([str(rustc), "-vV"], capture_output=True, text=True, check=True, timeout=30)
    fields = dict(re.findall(r"(?m)^([^:\n]+):\s*(.+)$", result.stdout))
    if not re.search(r"(?:^|[-.])(nightly|dev)(?:$|[-.])", fields.get("release", "")):
        raise ValueError("bound Rust compiler must be nightly or dev")
    if fields.get("LLVM version") != llvm_version:
        raise ValueError("bound Rust LLVM version must exactly match the plugin SDK")
    return {"rustc": str(rustc), "image": str(image), "import_library": str(library),
            "rustc_sha256": hashlib.sha256(rustc.read_bytes()).hexdigest(),
            "image_sha256": hashlib.sha256(image.read_bytes()).hexdigest(),
            "import_library_sha256": hashlib.sha256(library.read_bytes()).hexdigest(),
            "version": fields}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--rustc", required=True)
    parser.add_argument("--image", required=True)
    parser.add_argument("--import-library", required=True)
    parser.add_argument("--llvm-version", required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(validate(args.rustc, args.image, args.import_library, args.llvm_version)))
    except (ValueError, OSError, struct.error, subprocess.SubprocessError) as error:
        parser.exit(1, f"invalid Windows Rust LLVM binding: {error}\n")


if __name__ == "__main__":
    main()
