#include "obf/support/self_checksum_record.h"

#include <elf.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <bit>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace {

class bind_error : public std::runtime_error {
 public:
  using std::runtime_error::runtime_error;
};

template <typename T>
T checked_struct(const std::vector<std::uint8_t>& data, std::uint64_t offset, const char* what) {
  if (offset > data.size() || sizeof(T) > data.size() - static_cast<std::size_t>(offset)) {
    throw bind_error(std::string("truncated ") + what);
  }
  T value{};
  std::memcpy(&value, data.data() + static_cast<std::size_t>(offset), sizeof(T));
  return value;
}

std::uint16_t read_u16(const std::vector<std::uint8_t>& data, std::uint64_t offset) {
  if (offset > data.size() || 2 > data.size() - static_cast<std::size_t>(offset)) {
    throw bind_error("truncated self-checksum record");
  }
  const std::size_t i = static_cast<std::size_t>(offset);
  return static_cast<std::uint16_t>(data[i]) |
         (static_cast<std::uint16_t>(data[i + 1]) << 8U);
}

std::uint32_t read_u32(const std::vector<std::uint8_t>& data, std::uint64_t offset) {
  if (offset > data.size() || 4 > data.size() - static_cast<std::size_t>(offset)) {
    throw bind_error("truncated self-checksum record");
  }
  const std::size_t i = static_cast<std::size_t>(offset);
  return static_cast<std::uint32_t>(data[i]) |
         (static_cast<std::uint32_t>(data[i + 1]) << 8U) |
         (static_cast<std::uint32_t>(data[i + 2]) << 16U) |
         (static_cast<std::uint32_t>(data[i + 3]) << 24U);
}

std::uint64_t read_u64(const std::vector<std::uint8_t>& data, std::uint64_t offset) {
  if (offset > data.size() || 8 > data.size() - static_cast<std::size_t>(offset)) {
    throw bind_error("truncated self-checksum record");
  }
  std::uint64_t value = 0;
  for (unsigned byte = 0; byte < 8; ++byte) {
    value |= static_cast<std::uint64_t>(data[static_cast<std::size_t>(offset) + byte])
             << (byte * 8U);
  }
  return value;
}

void write_u32(std::vector<std::uint8_t>& data, std::uint64_t offset, std::uint32_t value) {
  if (offset > data.size() || 4 > data.size() - static_cast<std::size_t>(offset)) {
    throw bind_error("self-checksum record write exceeds file bounds");
  }
  for (unsigned byte = 0; byte < 4; ++byte) {
    data[static_cast<std::size_t>(offset) + byte] =
        static_cast<std::uint8_t>((value >> (byte * 8U)) & 0xffU);
  }
}

void write_u64(std::vector<std::uint8_t>& data, std::uint64_t offset, std::uint64_t value) {
  if (offset > data.size() || 8 > data.size() - static_cast<std::size_t>(offset)) {
    throw bind_error("self-checksum record write exceeds file bounds");
  }
  for (unsigned byte = 0; byte < 8; ++byte) {
    data[static_cast<std::size_t>(offset) + byte] =
        static_cast<std::uint8_t>((value >> (byte * 8U)) & 0xffU);
  }
}

bool add_overflows(std::uint64_t lhs, std::uint64_t rhs, std::uint64_t& result) {
  if (rhs > std::numeric_limits<std::uint64_t>::max() - lhs) { return true; }
  result = lhs + rhs;
  return false;
}

std::uint64_t add_signed(std::uint64_t base, std::int64_t delta) {
  if (delta >= 0) {
    std::uint64_t result = 0;
    if (add_overflows(base, static_cast<std::uint64_t>(delta), result)) {
      throw bind_error("target record-relative address overflows");
    }
    return result;
  }
  const std::uint64_t magnitude = static_cast<std::uint64_t>(-(delta + 1)) + 1U;
  if (magnitude > base) { throw bind_error("target record-relative address underflows"); }
  return base - magnitude;
}

std::uint64_t checksum_bytes(const std::uint8_t* bytes,
                             std::size_t size,
                             std::uint64_t seed) {
  std::uint64_t h = seed ^ UINT64_C(0x9e3779b97f4a7c15);
  for (std::size_t i = 0; i < size; ++i) {
    h = (h ^ bytes[i]) * UINT64_C(1099511628211);
    h ^= h >> 27U;
  }
  return h;
}

std::vector<std::uint8_t> read_file(const std::filesystem::path& path, struct stat& st) {
  if (::lstat(path.c_str(), &st) != 0) {
    throw bind_error("cannot stat input: " + std::string(std::strerror(errno)));
  }
  if (S_ISLNK(st.st_mode)) { throw bind_error("refusing to bind a symbolic link"); }
  if (!S_ISREG(st.st_mode)) { throw bind_error("input is not a regular file"); }
  if (st.st_nlink != 1) { throw bind_error("refusing to replace a multiply-linked input file"); }
  if (st.st_size < 0) { throw bind_error("invalid negative file size"); }

  const int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (fd < 0) { throw bind_error("cannot open input: " + std::string(std::strerror(errno))); }
  struct stat opened_stat {};
  if (::fstat(fd, &opened_stat) != 0 || opened_stat.st_dev != st.st_dev ||
      opened_stat.st_ino != st.st_ino || opened_stat.st_size != st.st_size) {
    (void)::close(fd);
    throw bind_error("input changed while being opened");
  }

  std::vector<std::uint8_t> data(static_cast<std::size_t>(st.st_size));
  std::size_t done = 0;
  while (done < data.size()) {
    const ssize_t count = ::read(fd, data.data() + done, data.size() - done);
    if (count < 0) {
      const int saved = errno;
      ::close(fd);
      throw bind_error("read failed: " + std::string(std::strerror(saved)));
    }
    if (count == 0) {
      ::close(fd);
      throw bind_error("input changed while being read");
    }
    done += static_cast<std::size_t>(count);
  }
  struct stat final_stat {};
  if (::fstat(fd, &final_stat) != 0 || final_stat.st_size != opened_stat.st_size ||
      final_stat.st_mtim.tv_sec != opened_stat.st_mtim.tv_sec ||
      final_stat.st_mtim.tv_nsec != opened_stat.st_mtim.tv_nsec ||
      final_stat.st_ctim.tv_sec != opened_stat.st_ctim.tv_sec ||
      final_stat.st_ctim.tv_nsec != opened_stat.st_ctim.tv_nsec) {
    (void)::close(fd);
    throw bind_error("input changed while being read");
  }
  if (::close(fd) != 0) { throw bind_error("close failed after read"); }
  return data;
}

std::string_view bounded_c_string(const std::vector<std::uint8_t>& data,
                                  std::uint64_t table_offset,
                                  std::uint64_t table_size,
                                  std::uint32_t string_offset) {
  if (string_offset >= table_size) { throw bind_error("invalid ELF section-name offset"); }
  std::uint64_t begin = 0;
  if (add_overflows(table_offset, string_offset, begin) || begin >= data.size()) {
    throw bind_error("invalid ELF section-name offset");
  }
  const std::uint64_t table_end = table_offset + table_size;
  std::uint64_t end = begin;
  while (end < table_end && end < data.size() && data[static_cast<std::size_t>(end)] != 0) { ++end; }
  if (end >= table_end || end >= data.size()) { throw bind_error("unterminated ELF section name"); }
  return std::string_view(reinterpret_cast<const char*>(data.data() + begin),
                          static_cast<std::size_t>(end - begin));
}

struct elf_view {
  Elf64_Ehdr header{};
  std::vector<Elf64_Shdr> sections;
  std::vector<Elf64_Phdr> segments;
  std::vector<std::size_t> record_section_indices;
};

elf_view parse_elf(const std::vector<std::uint8_t>& data) {
  if (data.size() < sizeof(Elf64_Ehdr)) { throw bind_error("file is too small to be ELF64"); }
  const Elf64_Ehdr header = checked_struct<Elf64_Ehdr>(data, 0, "ELF header");
  if (std::memcmp(header.e_ident, ELFMAG, SELFMAG) != 0 ||
      header.e_ident[EI_CLASS] != ELFCLASS64 || header.e_ident[EI_DATA] != ELFDATA2LSB ||
      header.e_ident[EI_VERSION] != EV_CURRENT) {
    throw bind_error("only little-endian ELF64 is supported");
  }
  if (header.e_machine != EM_X86_64) { throw bind_error("only ELF x86-64 is supported"); }
  if (header.e_type != ET_EXEC && header.e_type != ET_DYN) {
    throw bind_error("only final ELF ET_EXEC/ET_DYN artifacts are supported");
  }
  if (header.e_shnum == 0 || header.e_shentsize != sizeof(Elf64_Shdr)) {
    throw bind_error("ELF section table is required");
  }
  if (header.e_phnum == 0 || header.e_phentsize != sizeof(Elf64_Phdr)) {
    throw bind_error("ELF program headers are required");
  }
  if (header.e_shstrndx == SHN_UNDEF || header.e_shstrndx >= header.e_shnum) {
    throw bind_error("invalid ELF section-name table index");
  }

  elf_view view;
  view.header = header;
  view.sections.reserve(header.e_shnum);
  for (std::uint16_t index = 0; index < header.e_shnum; ++index) {
    const std::uint64_t delta = static_cast<std::uint64_t>(index) * header.e_shentsize;
    std::uint64_t offset = 0;
    if (add_overflows(header.e_shoff, delta, offset)) {
      throw bind_error("ELF section-table offset overflows");
    }
    view.sections.push_back(checked_struct<Elf64_Shdr>(data, offset, "ELF section header"));
  }
  view.segments.reserve(header.e_phnum);
  for (std::uint16_t index = 0; index < header.e_phnum; ++index) {
    const std::uint64_t delta = static_cast<std::uint64_t>(index) * header.e_phentsize;
    std::uint64_t offset = 0;
    if (add_overflows(header.e_phoff, delta, offset)) {
      throw bind_error("ELF program-header offset overflows");
    }
    view.segments.push_back(checked_struct<Elf64_Phdr>(data, offset, "ELF program header"));
  }

  const Elf64_Shdr& strings = view.sections[header.e_shstrndx];
  if (strings.sh_type != SHT_STRTAB || strings.sh_offset > data.size() ||
      strings.sh_size > data.size() - static_cast<std::size_t>(strings.sh_offset)) {
    throw bind_error("invalid ELF section-name string table");
  }

  for (std::size_t index = 0; index < view.sections.size(); ++index) {
    const Elf64_Shdr& section = view.sections[index];
    const std::string_view name =
        bounded_c_string(data, strings.sh_offset, strings.sh_size, section.sh_name);
    if (name == ".note.gnu.build-id") {
      throw bind_error("ELF v1 binding requires linking with --build-id=none");
    }
    const bool is_record_section =
        name == OBF_SC_ELF_SECTION_NAME || name.starts_with(OBF_SC_ELF_SECTION_PREFIX);
    if (!is_record_section) { continue; }
    if (section.sh_type != SHT_PROGBITS || (section.sh_flags & SHF_ALLOC) == 0 ||
        (section.sh_flags & (SHF_WRITE | SHF_EXECINSTR)) != 0) {
      throw bind_error("self-checksum record sections must be allocated, read-only, and non-executable");
    }
    if (section.sh_offset > data.size() ||
        section.sh_size > data.size() - static_cast<std::size_t>(section.sh_offset)) {
      throw bind_error("self-checksum record section exceeds file bounds");
    }
    if (section.sh_size == 0 || section.sh_size % OBF_SC_RECORD_SIZE != 0) {
      throw bind_error("self-checksum section size is not a nonzero multiple of the v1 record size");
    }
    view.record_section_indices.push_back(index);
  }
  if (view.record_section_indices.empty()) { throw bind_error("no .obfsc records found"); }

  for (const std::size_t record_index : view.record_section_indices) {
    const Elf64_Shdr& record_section = view.sections[record_index];
    std::uint64_t record_end = 0;
    if (add_overflows(record_section.sh_addr, record_section.sh_size, record_end)) {
      throw bind_error("self-checksum record virtual range overflows");
    }
    std::size_t containing_segments = 0;
    for (const Elf64_Phdr& segment : view.segments) {
      if (segment.p_type != PT_LOAD) { continue; }
      std::uint64_t segment_end = 0;
      if (add_overflows(segment.p_vaddr, segment.p_filesz, segment_end)) {
        throw bind_error("ELF PT_LOAD range overflows");
      }
      if (record_section.sh_addr < segment.p_vaddr || record_end > segment_end) { continue; }
      ++containing_segments;
      if ((segment.p_flags & PF_R) == 0 || (segment.p_flags & PF_W) != 0) {
        throw bind_error("self-checksum records must load from readable, non-writable memory");
      }
    }
    if (containing_segments != 1) {
      throw bind_error("self-checksum record section does not map to exactly one file-backed PT_LOAD");
    }
  }
  return view;
}

std::size_t relocation_width(std::uint32_t type) {
  switch (type) {
    case R_X86_64_NONE:
      return 0;
    case R_X86_64_64:
    case R_X86_64_GLOB_DAT:
    case R_X86_64_JUMP_SLOT:
    case R_X86_64_RELATIVE:
#ifdef R_X86_64_IRELATIVE
    case R_X86_64_IRELATIVE:
#endif
      return 8;
    case R_X86_64_PC32:
    case R_X86_64_PLT32:
    case R_X86_64_GOTPCREL:
    case R_X86_64_32:
    case R_X86_64_32S:
      return 4;
    case R_X86_64_16:
    case R_X86_64_PC16:
      return 2;
    case R_X86_64_8:
    case R_X86_64_PC8:
      return 1;
    default:
      return 16;  // Conservative for unsupported x86-64 fixups.
  }
}

bool ranges_overlap(std::uint64_t lhs_begin,
                    std::uint64_t lhs_size,
                    std::uint64_t rhs_begin,
                    std::uint64_t rhs_size) {
  std::uint64_t lhs_end = 0;
  std::uint64_t rhs_end = 0;
  if (add_overflows(lhs_begin, lhs_size, lhs_end) || add_overflows(rhs_begin, rhs_size, rhs_end)) {
    throw bind_error("range arithmetic overflow");
  }
  return lhs_begin < rhs_end && rhs_begin < lhs_end;
}

constexpr std::uint32_t kShtRelr = 19U;  // ELF gABI SHT_RELR

void reject_relr_overlap(const std::vector<std::uint8_t>& data,
                         const Elf64_Shdr& section,
                         std::uint64_t sample_va,
                         std::uint64_t sample_size) {
  constexpr std::uint64_t kWordSize = sizeof(Elf64_Addr);
  constexpr unsigned kBitmapBits = sizeof(Elf64_Addr) * 8U;
  if (section.sh_entsize != kWordSize || section.sh_size % kWordSize != 0 ||
      section.sh_offset > data.size() ||
      section.sh_size > data.size() - static_cast<std::size_t>(section.sh_offset)) {
    throw bind_error("malformed ELF RELR relocation section");
  }

  std::uint64_t next_va = 0;
  bool have_next = false;
  const std::uint64_t count = section.sh_size / kWordSize;
  for (std::uint64_t index = 0; index < count; ++index) {
    const std::uint64_t entry =
        read_u64(data, section.sh_offset + index * kWordSize);
    if ((entry & 1U) == 0) {
      if ((entry % kWordSize) != 0) {
        throw bind_error("misaligned ELF RELR relocation address");
      }
      if (ranges_overlap(sample_va, sample_size, entry, kWordSize)) {
        throw bind_error("sample range intersects an ELF load-time relocation/fixup");
      }
      if (add_overflows(entry, kWordSize, next_va)) {
        throw bind_error("ELF RELR relocation address overflows");
      }
      have_next = true;
      continue;
    }

    if (!have_next) { throw bind_error("ELF RELR bitmap appears before a base address"); }
    for (unsigned bit = 1; bit < kBitmapBits; ++bit) {
      if ((entry & (UINT64_C(1) << bit)) == 0) { continue; }
      const std::uint64_t byte_delta = static_cast<std::uint64_t>(bit - 1U) * kWordSize;
      std::uint64_t relocation_va = 0;
      if (add_overflows(next_va, byte_delta, relocation_va)) {
        throw bind_error("ELF RELR bitmap relocation address overflows");
      }
      if (ranges_overlap(sample_va, sample_size, relocation_va, kWordSize)) {
        throw bind_error("sample range intersects an ELF load-time relocation/fixup");
      }
    }
    constexpr std::uint64_t kBitmapSpan = (kBitmapBits - 1U) * kWordSize;
    std::uint64_t advanced = 0;
    if (add_overflows(next_va, kBitmapSpan, advanced)) {
      throw bind_error("ELF RELR bitmap range overflows");
    }
    next_va = advanced;
  }
}

void reject_runtime_relocation_overlap(const std::vector<std::uint8_t>& data,
                                       const elf_view& view,
                                       std::uint64_t sample_va,
                                       std::uint64_t sample_size) {
  for (const Elf64_Shdr& section : view.sections) {
    // Only allocated relocation tables describe fixups the runtime loader may
    // apply to the mapped image. Linkers can retain non-allocated static
    // relocation metadata (for example via --emit-relocs); those entries
    // describe already-resolved link-time fixups and must not invalidate an
    // otherwise stable file-byte baseline.
    if ((section.sh_flags & SHF_ALLOC) == 0) { continue; }
    if (section.sh_type == kShtRelr) {
      reject_relr_overlap(data, section, sample_va, sample_size);
      continue;
    }
    if (section.sh_type != SHT_RELA && section.sh_type != SHT_REL) { continue; }
    const std::size_t entry_size = section.sh_type == SHT_RELA ? sizeof(Elf64_Rela) : sizeof(Elf64_Rel);
    if (section.sh_entsize != entry_size || section.sh_size % entry_size != 0 ||
        section.sh_offset > data.size() ||
        section.sh_size > data.size() - static_cast<std::size_t>(section.sh_offset)) {
      throw bind_error("malformed ELF relocation section");
    }

    const std::uint64_t count = section.sh_size / entry_size;
    for (std::uint64_t index = 0; index < count; ++index) {
      const std::uint64_t offset = section.sh_offset + index * entry_size;
      std::uint64_t relocation_va = 0;
      std::uint64_t info = 0;
      if (section.sh_type == SHT_RELA) {
        const Elf64_Rela relocation = checked_struct<Elf64_Rela>(data, offset, "ELF RELA entry");
        relocation_va = relocation.r_offset;
        info = relocation.r_info;
      } else {
        const Elf64_Rel relocation = checked_struct<Elf64_Rel>(data, offset, "ELF REL entry");
        relocation_va = relocation.r_offset;
        info = relocation.r_info;
      }
      const std::size_t width = relocation_width(ELF64_R_TYPE(info));
      if (width != 0 && ranges_overlap(sample_va, sample_size, relocation_va, width)) {
        throw bind_error("sample range intersects an ELF load-time relocation/fixup");
      }
    }
  }
}

std::uint64_t map_sample_to_file(const std::vector<std::uint8_t>& data,
                                 const elf_view& view,
                                 std::uint64_t sample_va,
                                 std::uint64_t sample_size) {
  std::uint64_t sample_end = 0;
  if (add_overflows(sample_va, sample_size, sample_end)) {
    throw bind_error("sample address overflows");
  }

  bool found = false;
  std::uint64_t file_offset = 0;
  for (const Elf64_Phdr& segment : view.segments) {
    if (segment.p_type != PT_LOAD ||
        (segment.p_flags & (PF_R | PF_X)) != (PF_R | PF_X)) {
      continue;
    }
    std::uint64_t file_backed_end = 0;
    if (add_overflows(segment.p_vaddr, segment.p_filesz, file_backed_end)) {
      throw bind_error("ELF executable segment address overflows");
    }
    if (sample_va < segment.p_vaddr || sample_end > file_backed_end) { continue; }
    if (found) { throw bind_error("sample maps to multiple executable PT_LOAD segments"); }
    const std::uint64_t delta = sample_va - segment.p_vaddr;
    if (add_overflows(segment.p_offset, delta, file_offset) || file_offset > data.size() ||
        sample_size > data.size() - static_cast<std::size_t>(file_offset)) {
      throw bind_error("sample maps outside file bounds");
    }
    found = true;
  }
  if (!found) { throw bind_error("sample does not map to executable file-backed PT_LOAD bytes"); }
  return file_offset;
}

void validate_reserved_zero(const std::vector<std::uint8_t>& data, std::uint64_t record_offset) {
  if (read_u32(data, record_offset + OBF_SC_OFF_RESERVED0) != 0) {
    throw bind_error("v1 reserved0 field is nonzero");
  }
  for (std::uint32_t index = 0; index < OBF_SC_RESERVED1_SIZE; ++index) {
    if (data[static_cast<std::size_t>(record_offset + OBF_SC_OFF_RESERVED1 + index)] != 0) {
      throw bind_error("v1 reserved1 field is nonzero");
    }
  }
}

struct bind_summary {
  bool changed = false;
  std::size_t records = 0;
};

bind_summary validate_and_bind(std::vector<std::uint8_t>& data, bool allow_binding, bool report) {
  const elf_view view = parse_elf(data);
  bind_summary summary;
  for (const std::size_t section_index : view.record_section_indices) {
    summary.records += static_cast<std::size_t>(
        view.sections[section_index].sh_size / OBF_SC_RECORD_SIZE);
  }

  for (const std::size_t section_index : view.record_section_indices) {
    const Elf64_Shdr& records = view.sections[section_index];
    const std::size_t section_records =
        static_cast<std::size_t>(records.sh_size / OBF_SC_RECORD_SIZE);
    for (std::size_t index = 0; index < section_records; ++index) {
      const std::uint64_t record_offset =
          records.sh_offset + static_cast<std::uint64_t>(index) * OBF_SC_RECORD_SIZE;
      const std::uint64_t record_va =
          records.sh_addr + static_cast<std::uint64_t>(index) * OBF_SC_RECORD_SIZE;

    if (read_u32(data, record_offset + OBF_SC_OFF_MAGIC) != OBF_SC_RECORD_MAGIC ||
        read_u16(data, record_offset + OBF_SC_OFF_VERSION) != OBF_SC_RECORD_VERSION ||
        read_u16(data, record_offset + OBF_SC_OFF_RECORD_SIZE) != OBF_SC_RECORD_SIZE) {
      throw bind_error("unsupported or malformed self-checksum record header");
    }

    const std::uint32_t flags = read_u32(data, record_offset + OBF_SC_OFF_FLAGS);
    if ((flags & ~OBF_SC_FLAG_V1_MASK) != 0 || (flags & OBF_SC_FLAG_REQUIRED) == 0) {
      throw bind_error("invalid v1 self-checksum flags");
    }
    if (read_u32(data, record_offset + OBF_SC_OFF_ALGORITHM) !=
            OBF_SC_ALGORITHM_RT_CORE_CC_V1 ||
        read_u32(data, record_offset + OBF_SC_OFF_OBJECT_FORMAT) != OBF_SC_OBJECT_FORMAT_ELF ||
        read_u32(data, record_offset + OBF_SC_OFF_MACHINE) != OBF_SC_MACHINE_X86_64 ||
        read_u32(data, record_offset + OBF_SC_OFF_TARGET_KIND) != OBF_SC_TARGET_RECORD_REL64) {
      throw bind_error("unsupported v1 self-checksum record semantics");
    }
    validate_reserved_zero(data, record_offset);

    const std::uint64_t site_id = read_u64(data, record_offset + OBF_SC_OFF_SITE_ID);
    if (site_id == 0) { throw bind_error("zero self-checksum site_id"); }

    const std::uint32_t sample_offset = read_u32(data, record_offset + OBF_SC_OFF_SAMPLE_OFFSET);
    const std::uint32_t sample_size = read_u32(data, record_offset + OBF_SC_OFF_SAMPLE_SIZE);
    if (sample_offset != OBF_SC_V1_SAMPLE_OFFSET ||
        sample_size < OBF_SC_V1_MIN_SAMPLE_SIZE || sample_size > OBF_SC_V1_MAX_SAMPLE_SIZE) {
      throw bind_error("unsupported v1 sample offset/size");
    }

    const std::int64_t target_delta = std::bit_cast<std::int64_t>(
        read_u64(data, record_offset + OBF_SC_OFF_TARGET_DELTA));
    const std::uint64_t target_va = add_signed(record_va, target_delta);
    std::uint64_t sample_va = 0;
    if (add_overflows(target_va, sample_offset, sample_va)) {
      throw bind_error("sample virtual address overflows");
    }
    const std::uint64_t sample_file_offset =
        map_sample_to_file(data, view, sample_va, sample_size);
    reject_runtime_relocation_overlap(data, view, sample_va, sample_size);

    const std::uint64_t seed = read_u64(data, record_offset + OBF_SC_OFF_SEED);
    const std::uint64_t actual = checksum_bytes(
        data.data() + static_cast<std::size_t>(sample_file_offset), sample_size, seed);
    const std::uint64_t expected =
        read_u64(data, record_offset + OBF_SC_OFF_EXPECTED_CHECKSUM);
    const bool bound = (flags & OBF_SC_FLAG_BOUND) != 0;

    if (bound) {
      if (expected != actual) {
        throw bind_error("already-bound record checksum does not match final target bytes");
      }
    } else {
      if (!allow_binding) { throw bind_error("candidate image still contains an UNBOUND record"); }
      if (expected != 0) { throw bind_error("UNBOUND v1 record has nonzero expected checksum"); }
      write_u64(data, record_offset + OBF_SC_OFF_EXPECTED_CHECKSUM, actual);
      write_u32(data,
                record_offset + OBF_SC_OFF_FLAGS,
                OBF_SC_FLAG_REQUIRED | OBF_SC_FLAG_BOUND);
      summary.changed = true;
    }

      if (report) {
        std::cout << "SELF_CHECKSUM_RECORD site=" << site_id << " target_va=0x" << std::hex
                  << target_va << " file_offset=0x" << sample_file_offset << " checksum=0x" << actual
                  << std::dec << (bound ? " state=BOUND" : " state=BOUND(new)") << '\n';
      }
    }
  }
  return summary;
}

void write_all(int fd, const std::vector<std::uint8_t>& data) {
  std::size_t done = 0;
  while (done < data.size()) {
    const ssize_t count = ::write(fd, data.data() + done, data.size() - done);
    if (count < 0) { throw bind_error("temporary-file write failed: " + std::string(std::strerror(errno))); }
    if (count == 0) { throw bind_error("temporary-file write made no progress"); }
    done += static_cast<std::size_t>(count);
  }
}

void publish_atomically(const std::filesystem::path& path,
                        const std::vector<std::uint8_t>& data,
                        const struct stat& original_stat) {
  std::filesystem::path directory = path.parent_path();
  if (directory.empty()) { directory = "."; }
  std::string pattern = (directory / (path.filename().string() + ".obfsc.tmp.XXXXXX")).string();
  std::vector<char> writable_pattern(pattern.begin(), pattern.end());
  writable_pattern.push_back('\0');

  const int fd = ::mkstemp(writable_pattern.data());
  if (fd < 0) { throw bind_error("cannot create temporary output: " + std::string(std::strerror(errno))); }
  const std::filesystem::path temporary(writable_pattern.data());
  bool keep_temporary = true;
  try {
    if (::fchown(fd, original_stat.st_uid, original_stat.st_gid) != 0) {
      throw bind_error("cannot preserve output ownership");
    }
    if (::fchmod(fd, original_stat.st_mode & 07777) != 0) {
      throw bind_error("cannot preserve executable mode on temporary output");
    }
    write_all(fd, data);
    if (::fsync(fd) != 0) { throw bind_error("fsync failed for temporary output"); }
    if (::close(fd) != 0) { throw bind_error("close failed for temporary output"); }

    if (::rename(temporary.c_str(), path.c_str()) != 0) {
      throw bind_error("atomic replacement failed: " + std::string(std::strerror(errno)));
    }
    keep_temporary = false;

    const int dir_fd = ::open(directory.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dir_fd >= 0) {
      (void)::fsync(dir_fd);
      (void)::close(dir_fd);
    }
  } catch (...) {
    const int saved = errno;
    (void)::close(fd);
    if (keep_temporary) { (void)::unlink(temporary.c_str()); }
    errno = saved;
    throw;
  }
}

int run(const std::filesystem::path& path) {
  struct stat original_stat {};
  std::vector<std::uint8_t> image = read_file(path, original_stat);
  const bind_summary result = validate_and_bind(image, true, true);
  (void)validate_and_bind(image, false, false);

  if (!result.changed) {
    std::cout << "SELF_CHECKSUM_BIND: already bound records=" << result.records << '\n';
    return 0;
  }

  publish_atomically(path, image, original_stat);
  std::cout << "SELF_CHECKSUM_BIND: bound records=" << result.records << '\n';
  return 0;
}

}  // namespace

int main(int argc, char** argv) {
  if (argc != 2) {
    std::cerr << "usage: obf-checksum-bind <final-elf>\n";
    return 2;
  }
  try {
    return run(argv[1]);
  } catch (const bind_error& error) {
    std::cerr << "obf-checksum-bind: " << error.what() << '\n';
    return 1;
  } catch (const std::exception& error) {
    std::cerr << "obf-checksum-bind: unexpected error: " << error.what() << '\n';
    return 1;
  }
}
