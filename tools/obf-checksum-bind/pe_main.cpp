#include "obf/support/self_checksum_record.h"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <algorithm>
#include <bit>
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
    throw bind_error("truncated PE/self-checksum data");
  }
  const std::size_t i = static_cast<std::size_t>(offset);
  return static_cast<std::uint16_t>(data[i]) |
         (static_cast<std::uint16_t>(data[i + 1]) << 8U);
}

std::uint32_t read_u32(const std::vector<std::uint8_t>& data, std::uint64_t offset) {
  if (offset > data.size() || 4 > data.size() - static_cast<std::size_t>(offset)) {
    throw bind_error("truncated PE/self-checksum data");
  }
  const std::size_t i = static_cast<std::size_t>(offset);
  return static_cast<std::uint32_t>(data[i]) |
         (static_cast<std::uint32_t>(data[i + 1]) << 8U) |
         (static_cast<std::uint32_t>(data[i + 2]) << 16U) |
         (static_cast<std::uint32_t>(data[i + 3]) << 24U);
}

std::uint64_t read_u64(const std::vector<std::uint8_t>& data, std::uint64_t offset) {
  if (offset > data.size() || 8 > data.size() - static_cast<std::size_t>(offset)) {
    throw bind_error("truncated PE/self-checksum data");
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

bool ranges_overlap(std::uint64_t lhs_start,
                    std::uint64_t lhs_size,
                    std::uint64_t rhs_start,
                    std::uint64_t rhs_size) {
  std::uint64_t lhs_end = 0;
  std::uint64_t rhs_end = 0;
  if (add_overflows(lhs_start, lhs_size, lhs_end) ||
      add_overflows(rhs_start, rhs_size, rhs_end)) {
    throw bind_error("address range overflows");
  }
  return lhs_start < rhs_end && rhs_start < lhs_end;
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

std::string windows_error(const char* operation, DWORD code = ::GetLastError()) {
  LPSTR message = nullptr;
  const DWORD count = ::FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER |
                                           FORMAT_MESSAGE_FROM_SYSTEM |
                                           FORMAT_MESSAGE_IGNORE_INSERTS,
                                       nullptr,
                                       code,
                                       0,
                                       reinterpret_cast<LPSTR>(&message),
                                       0,
                                       nullptr);
  std::string result(operation);
  result += " failed";
  if (count != 0 && message != nullptr) {
    result += ": ";
    result.append(message, count);
    while (!result.empty() &&
           (result.back() == '\r' || result.back() == '\n' || result.back() == ' ')) {
      result.pop_back();
    }
  } else {
    result += " (Windows error " + std::to_string(code) + ")";
  }
  if (message != nullptr) { ::LocalFree(message); }
  return result;
}

struct file_metadata {
  DWORD volume_serial = 0;
  DWORD file_index_high = 0;
  DWORD file_index_low = 0;
  FILETIME last_write{};
  std::uint64_t size = 0;
};

bool same_file_identity(const BY_HANDLE_FILE_INFORMATION& info, const file_metadata& metadata) {
  const std::uint64_t size =
      (static_cast<std::uint64_t>(info.nFileSizeHigh) << 32U) | info.nFileSizeLow;
  return info.dwVolumeSerialNumber == metadata.volume_serial &&
         info.nFileIndexHigh == metadata.file_index_high &&
         info.nFileIndexLow == metadata.file_index_low && size == metadata.size &&
         ::CompareFileTime(&info.ftLastWriteTime, &metadata.last_write) == 0;
}

std::vector<std::uint8_t> read_file(const std::filesystem::path& path, file_metadata& metadata) {
  HANDLE file = ::CreateFileW(path.c_str(),
                              GENERIC_READ,
                              FILE_SHARE_READ,
                              nullptr,
                              OPEN_EXISTING,
                              FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
                              nullptr);
  if (file == INVALID_HANDLE_VALUE) { throw bind_error(windows_error("CreateFileW")); }

  BY_HANDLE_FILE_INFORMATION info{};
  if (!::GetFileInformationByHandle(file, &info)) {
    const std::string error = windows_error("GetFileInformationByHandle");
    ::CloseHandle(file);
    throw bind_error(error);
  }
  if ((info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) {
    ::CloseHandle(file);
    throw bind_error("input is not a regular file");
  }
  if ((info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
    ::CloseHandle(file);
    throw bind_error("refusing to bind a reparse-point input");
  }
  if (info.nNumberOfLinks != 1) {
    ::CloseHandle(file);
    throw bind_error("refusing to replace a multiply-linked input file");
  }

  metadata.volume_serial = info.dwVolumeSerialNumber;
  metadata.file_index_high = info.nFileIndexHigh;
  metadata.file_index_low = info.nFileIndexLow;
  metadata.last_write = info.ftLastWriteTime;
  metadata.size = (static_cast<std::uint64_t>(info.nFileSizeHigh) << 32U) | info.nFileSizeLow;
  if (metadata.size > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max())) {
    ::CloseHandle(file);
    throw bind_error("input is too large to map in memory");
  }

  std::vector<std::uint8_t> data(static_cast<std::size_t>(metadata.size));
  std::size_t done = 0;
  while (done < data.size()) {
    const DWORD chunk = static_cast<DWORD>(
        std::min<std::size_t>(data.size() - done, static_cast<std::size_t>(MAXDWORD)));
    DWORD read = 0;
    if (!::ReadFile(file, data.data() + done, chunk, &read, nullptr)) {
      const std::string error = windows_error("ReadFile");
      ::CloseHandle(file);
      throw bind_error(error);
    }
    if (read == 0) {
      ::CloseHandle(file);
      throw bind_error("input changed while being read");
    }
    done += read;
  }

  BY_HANDLE_FILE_INFORMATION final_info{};
  if (!::GetFileInformationByHandle(file, &final_info) ||
      !same_file_identity(final_info, metadata)) {
    ::CloseHandle(file);
    throw bind_error("input changed while being read");
  }
  if (!::CloseHandle(file)) { throw bind_error(windows_error("CloseHandle")); }
  return data;
}

std::string section_name(const IMAGE_SECTION_HEADER& section) {
  std::size_t length = 0;
  while (length < IMAGE_SIZEOF_SHORT_NAME && section.Name[length] != 0) { ++length; }
  return std::string(reinterpret_cast<const char*>(section.Name), length);
}

struct pe_view {
  IMAGE_NT_HEADERS64 headers{};
  std::vector<IMAGE_SECTION_HEADER> sections;
  std::vector<std::size_t> record_section_indices;
  IMAGE_DATA_DIRECTORY base_relocations{};
};

pe_view parse_pe(const std::vector<std::uint8_t>& data,
                 bool require_records = true,
                 bool reject_mutation_hazards = true) {
  if (data.size() < sizeof(IMAGE_DOS_HEADER)) { throw bind_error("file is too small to be PE32+"); }
  const IMAGE_DOS_HEADER dos = checked_struct<IMAGE_DOS_HEADER>(data, 0, "DOS header");
  if (dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew < 0) {
    throw bind_error("input is not a PE image");
  }
  const std::uint64_t nt_offset = static_cast<std::uint32_t>(dos.e_lfanew);
  const std::uint64_t fixed_nt_size =
      sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + sizeof(IMAGE_OPTIONAL_HEADER64);
  if (nt_offset > data.size() || fixed_nt_size > data.size() - static_cast<std::size_t>(nt_offset)) {
    throw bind_error("truncated PE headers");
  }
  if (read_u32(data, nt_offset) != IMAGE_NT_SIGNATURE) { throw bind_error("invalid PE signature"); }

  const std::uint64_t file_header_offset = nt_offset + sizeof(DWORD);
  const IMAGE_FILE_HEADER file_header =
      checked_struct<IMAGE_FILE_HEADER>(data, file_header_offset, "PE file header");
  if (file_header.Machine != IMAGE_FILE_MACHINE_AMD64) {
    throw bind_error("only PE32+ AMD64 images are supported");
  }
  if ((file_header.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE) == 0) {
    throw bind_error("input is not a final PE executable image");
  }
  if (reject_mutation_hazards && (file_header.Characteristics & IMAGE_FILE_DLL) != 0) {
    throw bind_error("Phase 3 supports PE32+ AMD64 executables only; DLL binding is not enabled");
  }
  if (file_header.NumberOfSections == 0) { throw bind_error("PE section table is required"); }
  if (file_header.SizeOfOptionalHeader < sizeof(IMAGE_OPTIONAL_HEADER64)) {
    throw bind_error("truncated PE32+ optional header");
  }

  const std::uint64_t optional_offset = file_header_offset + sizeof(IMAGE_FILE_HEADER);
  const IMAGE_OPTIONAL_HEADER64 optional =
      checked_struct<IMAGE_OPTIONAL_HEADER64>(data, optional_offset, "PE32+ optional header");
  if (optional.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
    throw bind_error("only PE32+ AMD64 images are supported");
  }
  if (optional.NumberOfRvaAndSizes < IMAGE_NUMBEROF_DIRECTORY_ENTRIES) {
    throw bind_error("PE32+ data-directory table is incomplete");
  }
  if (optional.SizeOfImage == 0 || optional.SizeOfHeaders > data.size()) {
    throw bind_error("invalid PE32+ image/header size");
  }
  if (reject_mutation_hazards && optional.CheckSum != 0) {
    throw bind_error("PE v1 binding requires a zero PE header checksum");
  }
  const IMAGE_DATA_DIRECTORY security = optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY];
  if (reject_mutation_hazards && (security.VirtualAddress != 0 || security.Size != 0)) {
    throw bind_error("PE v1 binding refuses Authenticode-signed/certificate-bearing images; bind before signing");
  }

  const std::uint64_t section_table_offset = optional_offset + file_header.SizeOfOptionalHeader;
  const std::uint64_t section_table_size =
      static_cast<std::uint64_t>(file_header.NumberOfSections) * sizeof(IMAGE_SECTION_HEADER);
  if (section_table_offset > data.size() ||
      section_table_size > data.size() - static_cast<std::size_t>(section_table_offset)) {
    throw bind_error("truncated PE section table");
  }

  pe_view view;
  view.headers.Signature = IMAGE_NT_SIGNATURE;
  view.headers.FileHeader = file_header;
  view.headers.OptionalHeader = optional;
  view.base_relocations = optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
  view.sections.reserve(file_header.NumberOfSections);
  for (std::size_t index = 0; index < file_header.NumberOfSections; ++index) {
    const std::uint64_t offset = section_table_offset + index * sizeof(IMAGE_SECTION_HEADER);
    const IMAGE_SECTION_HEADER section =
        checked_struct<IMAGE_SECTION_HEADER>(data, offset, "PE section header");
    if (section.SizeOfRawData != 0) {
      std::uint64_t raw_end = 0;
      if (add_overflows(section.PointerToRawData, section.SizeOfRawData, raw_end) ||
          raw_end > data.size()) {
        throw bind_error("PE section raw data exceeds file bounds");
      }
    }
    if (section.Misc.VirtualSize != 0) {
      std::uint64_t virtual_end = 0;
      if (add_overflows(section.VirtualAddress, section.Misc.VirtualSize, virtual_end) ||
          virtual_end > optional.SizeOfImage) {
        throw bind_error("PE section virtual range exceeds SizeOfImage");
      }
    }
    view.sections.push_back(section);

    if (section_name(section) != OBF_SC_PE_SECTION_NAME) { continue; }
    if ((section.Characteristics & IMAGE_SCN_MEM_READ) == 0 ||
        (section.Characteristics &
         (IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_DISCARDABLE)) != 0) {
      throw bind_error(
          "self-checksum PE record section must be resident, readable, non-writable, and non-executable");
    }
    if (section.Misc.VirtualSize == 0 ||
        section.Misc.VirtualSize % OBF_SC_RECORD_SIZE != 0) {
      throw bind_error("self-checksum PE section virtual size is not a nonzero multiple of the v1 record size");
    }
    if (section.Misc.VirtualSize > section.SizeOfRawData) {
      throw bind_error("self-checksum PE records are not fully file-backed");
    }
    view.record_section_indices.push_back(index);
  }
  if (view.record_section_indices.empty() && require_records) {
    throw bind_error("no .obfsc records found");
  }
  return view;
}

std::uint64_t map_rva_to_file(const std::vector<std::uint8_t>& data,
                              const pe_view& view,
                              std::uint64_t rva,
                              std::uint64_t size,
                              bool require_executable) {
  std::uint64_t end = 0;
  if (add_overflows(rva, size, end)) { throw bind_error("PE RVA range overflows"); }

  const IMAGE_SECTION_HEADER* mapped = nullptr;
  for (const IMAGE_SECTION_HEADER& section : view.sections) {
    const std::uint64_t section_begin = section.VirtualAddress;
    const std::uint64_t virtual_size = section.Misc.VirtualSize;
    std::uint64_t section_end = 0;
    if (add_overflows(section_begin, virtual_size, section_end)) {
      throw bind_error("PE section RVA range overflows");
    }
    if (rva < section_begin || end > section_end) { continue; }
    if (mapped != nullptr) { throw bind_error("PE RVA maps to multiple sections"); }
    mapped = &section;
  }
  if (mapped == nullptr) {
    throw bind_error(require_executable ?
                         "sample does not map to executable file-backed PE bytes" :
                         "PE data directory does not map to file-backed section bytes");
  }

  if (require_executable &&
      ((mapped->Characteristics & (IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE)) !=
           (IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE) ||
       (mapped->Characteristics & IMAGE_SCN_MEM_DISCARDABLE) != 0)) {
    throw bind_error("sample does not map to executable file-backed PE bytes");
  }

  const std::uint64_t relative = rva - mapped->VirtualAddress;
  std::uint64_t raw_relative_end = 0;
  if (add_overflows(relative, size, raw_relative_end) ||
      raw_relative_end > mapped->SizeOfRawData) {
    throw bind_error(require_executable ?
                         "sample does not map to executable file-backed PE bytes" :
                         "PE data directory does not map to file-backed section bytes");
  }

  std::uint64_t file_offset = 0;
  if (add_overflows(mapped->PointerToRawData, relative, file_offset) ||
      file_offset > data.size() || size > data.size() - static_cast<std::size_t>(file_offset)) {
    throw bind_error("PE RVA maps outside file bounds");
  }
  return file_offset;
}

std::size_t pe_relocation_width(std::uint16_t type) {
  switch (type) {
    case IMAGE_REL_BASED_ABSOLUTE:
      return 0;
    case IMAGE_REL_BASED_HIGH:
    case IMAGE_REL_BASED_LOW:
      return 2;
    case IMAGE_REL_BASED_HIGHLOW:
      return 4;
    case IMAGE_REL_BASED_DIR64:
      return 8;
    default:
      throw bind_error("unsupported PE base-relocation type in AMD64 image");
  }
}

void reject_pe_base_relocation_overlap(const std::vector<std::uint8_t>& data,
                                       const pe_view& view,
                                       std::uint64_t sample_rva,
                                       std::uint64_t sample_size) {
  const IMAGE_DATA_DIRECTORY directory = view.base_relocations;
  if (directory.VirtualAddress == 0 && directory.Size == 0) { return; }
  if (directory.VirtualAddress == 0 || directory.Size < sizeof(IMAGE_BASE_RELOCATION)) {
    throw bind_error("malformed PE base-relocation directory");
  }
  const std::uint64_t directory_offset =
      map_rva_to_file(data, view, directory.VirtualAddress, directory.Size, false);
  std::uint64_t cursor = directory_offset;
  const std::uint64_t end = directory_offset + directory.Size;
  while (cursor < end) {
    if (sizeof(IMAGE_BASE_RELOCATION) > end - cursor) {
      throw bind_error("truncated PE base-relocation block");
    }
    const IMAGE_BASE_RELOCATION block =
        checked_struct<IMAGE_BASE_RELOCATION>(data, cursor, "PE base-relocation block");
    if (block.SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION) ||
        block.SizeOfBlock > end - cursor ||
        (block.SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) % sizeof(std::uint16_t) != 0) {
      throw bind_error("malformed PE base-relocation block");
    }
    const std::size_t entry_count =
        (block.SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(std::uint16_t);
    const std::uint64_t entries = cursor + sizeof(IMAGE_BASE_RELOCATION);
    for (std::size_t index = 0; index < entry_count; ++index) {
      const std::uint16_t encoded = read_u16(data, entries + index * sizeof(std::uint16_t));
      const std::uint16_t type = encoded >> 12U;
      const std::uint16_t offset = encoded & 0x0fffU;
      const std::size_t width = pe_relocation_width(type);
      if (width == 0) { continue; }
      std::uint64_t relocation_rva = 0;
      if (add_overflows(block.VirtualAddress, offset, relocation_rva)) {
        throw bind_error("PE base-relocation RVA overflows");
      }
      if (ranges_overlap(sample_rva, sample_size, relocation_rva, width)) {
        throw bind_error("sample range intersects a PE load-time base relocation/fixup");
      }
    }
    cursor += block.SizeOfBlock;
  }
  if (cursor != end) { throw bind_error("malformed PE base-relocation directory size"); }
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
  const pe_view view = parse_pe(data, true, true);
  bind_summary summary;
  for (const std::size_t section_index : view.record_section_indices) {
    summary.records += static_cast<std::size_t>(
        view.sections[section_index].Misc.VirtualSize / OBF_SC_RECORD_SIZE);
  }

  for (const std::size_t section_index : view.record_section_indices) {
    const IMAGE_SECTION_HEADER& records = view.sections[section_index];
    const std::size_t section_records =
        static_cast<std::size_t>(records.Misc.VirtualSize / OBF_SC_RECORD_SIZE);
    for (std::size_t index = 0; index < section_records; ++index) {
      const std::uint64_t record_offset =
          records.PointerToRawData + static_cast<std::uint64_t>(index) * OBF_SC_RECORD_SIZE;
      const std::uint64_t record_rva =
          records.VirtualAddress + static_cast<std::uint64_t>(index) * OBF_SC_RECORD_SIZE;
      const std::uint64_t mapped_record_offset =
          map_rva_to_file(data, view, record_rva, OBF_SC_RECORD_SIZE, false);
      if (mapped_record_offset != record_offset) {
        throw bind_error("self-checksum PE record RVA/raw mapping is inconsistent");
      }

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
          read_u32(data, record_offset + OBF_SC_OFF_OBJECT_FORMAT) != OBF_SC_OBJECT_FORMAT_PE_COFF ||
          read_u32(data, record_offset + OBF_SC_OFF_MACHINE) != OBF_SC_MACHINE_X86_64 ||
          read_u32(data, record_offset + OBF_SC_OFF_TARGET_KIND) != OBF_SC_TARGET_RECORD_REL32) {
        throw bind_error("unsupported v1 PE self-checksum record semantics");
      }
      validate_reserved_zero(data, record_offset);
      reject_pe_base_relocation_overlap(data, view, record_rva, OBF_SC_RECORD_SIZE);

      const std::uint64_t site_id = read_u64(data, record_offset + OBF_SC_OFF_SITE_ID);
      if (site_id == 0) { throw bind_error("zero self-checksum site_id"); }

      const std::uint32_t sample_offset = read_u32(data, record_offset + OBF_SC_OFF_SAMPLE_OFFSET);
      const std::uint32_t sample_size = read_u32(data, record_offset + OBF_SC_OFF_SAMPLE_SIZE);
      if (sample_offset != OBF_SC_V1_SAMPLE_OFFSET ||
          sample_size < OBF_SC_V1_MIN_SAMPLE_SIZE || sample_size > OBF_SC_V1_MAX_SAMPLE_SIZE) {
        throw bind_error("unsupported v1 sample offset/size");
      }

      const std::uint64_t encoded_delta = read_u64(data, record_offset + OBF_SC_OFF_TARGET_DELTA);
      if ((encoded_delta >> 32U) != 0) {
        throw bind_error("PE v1 record-relative target displacement is not zero-extended REL32");
      }
      const std::int32_t delta32 =
          std::bit_cast<std::int32_t>(static_cast<std::uint32_t>(encoded_delta));
      const std::uint64_t target_rva = add_signed(record_rva, delta32);
      std::uint64_t sample_rva = 0;
      if (add_overflows(target_rva, sample_offset, sample_rva) ||
          sample_rva > std::numeric_limits<std::uint32_t>::max()) {
        throw bind_error("sample PE RVA overflows");
      }
      const std::uint64_t sample_file_offset =
          map_rva_to_file(data, view, sample_rva, sample_size, true);
      reject_pe_base_relocation_overlap(data, view, sample_rva, sample_size);

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
        std::cout << "SELF_CHECKSUM_RECORD site=" << site_id << " target_rva=0x" << std::hex
                  << target_rva << " file_offset=0x" << sample_file_offset << " checksum=0x" << actual
                  << std::dec << (bound ? " state=BOUND" : " state=BOUND(new)") << '\n';
      }
    }
  }
  return summary;
}

void publish_atomically(const std::filesystem::path& path,
                        const std::vector<std::uint8_t>& data,
                        const file_metadata& metadata) {
  HANDLE current = ::CreateFileW(path.c_str(),
                                 GENERIC_READ,
                                 FILE_SHARE_READ,
                                 nullptr,
                                 OPEN_EXISTING,
                                 FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
                                 nullptr);
  if (current == INVALID_HANDLE_VALUE) {
    throw bind_error(windows_error("CreateFileW pre-replacement check"));
  }
  BY_HANDLE_FILE_INFORMATION current_info{};
  const bool unchanged = ::GetFileInformationByHandle(current, &current_info) &&
                         same_file_identity(current_info, metadata) &&
                         (current_info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0;
  (void)::CloseHandle(current);
  if (!unchanged) { throw bind_error("input changed before atomic replacement"); }

  std::filesystem::path directory = path.parent_path();
  if (directory.empty()) { directory = "."; }

  std::filesystem::path temporary;
  HANDLE output = INVALID_HANDLE_VALUE;
  for (unsigned attempt = 0; attempt < 64; ++attempt) {
    temporary = directory /
                (path.filename().wstring() + L".obfsc.tmp." +
                 std::to_wstring(::GetCurrentProcessId()) + L"." + std::to_wstring(attempt));
    output = ::CreateFileW(temporary.c_str(),
                           GENERIC_WRITE,
                           0,
                           nullptr,
                           CREATE_NEW,
                           FILE_ATTRIBUTE_NORMAL,
                           nullptr);
    if (output != INVALID_HANDLE_VALUE) { break; }
    if (::GetLastError() != ERROR_FILE_EXISTS && ::GetLastError() != ERROR_ALREADY_EXISTS) {
      throw bind_error(windows_error("CreateFileW temporary output"));
    }
  }
  if (output == INVALID_HANDLE_VALUE) { throw bind_error("cannot allocate unique temporary output"); }

  bool keep_temporary = true;
  try {
    std::size_t done = 0;
    while (done < data.size()) {
      const DWORD chunk = static_cast<DWORD>(
          std::min<std::size_t>(data.size() - done, static_cast<std::size_t>(MAXDWORD)));
      DWORD written = 0;
      if (!::WriteFile(output, data.data() + done, chunk, &written, nullptr)) {
        throw bind_error(windows_error("WriteFile temporary output"));
      }
      if (written == 0) { throw bind_error("temporary-file write made no progress"); }
      done += written;
    }
    if (!::FlushFileBuffers(output)) { throw bind_error(windows_error("FlushFileBuffers")); }
    if (!::CloseHandle(output)) {
      output = INVALID_HANDLE_VALUE;
      throw bind_error(windows_error("CloseHandle temporary output"));
    }
    output = INVALID_HANDLE_VALUE;

    if (!::ReplaceFileW(path.c_str(), temporary.c_str(), nullptr, 0, nullptr, nullptr)) {
      throw bind_error(windows_error("ReplaceFileW"));
    }
    keep_temporary = false;
  } catch (...) {
    if (output != INVALID_HANDLE_VALUE) { (void)::CloseHandle(output); }
    if (keep_temporary) { (void)::DeleteFileW(temporary.c_str()); }
    throw;
  }
}

int run(const std::filesystem::path& path) {
  file_metadata metadata{};
  std::vector<std::uint8_t> image = read_file(path, metadata);
  const bind_summary result = validate_and_bind(image, true, true);
  (void)validate_and_bind(image, false, false);

  if (!result.changed) {
    std::cout << "SELF_CHECKSUM_BIND: already bound records=" << result.records << '\n';
    return 0;
  }

  publish_atomically(path, image, metadata);
  std::cout << "SELF_CHECKSUM_BIND: bound records=" << result.records << '\n';
  return 0;
}

int probe(const std::filesystem::path& path) {
  file_metadata metadata{};
  const std::vector<std::uint8_t> image = read_file(path, metadata);
  const pe_view view = parse_pe(image, false, false);
  std::size_t records = 0;
  for (const std::size_t section_index : view.record_section_indices) {
    records += static_cast<std::size_t>(
        view.sections[section_index].Misc.VirtualSize / OBF_SC_RECORD_SIZE);
  }
  std::cout << "SELF_CHECKSUM_PROBE: records=" << records << '\n';
  return records == 0 ? 3 : 0;
}

}  // namespace

int main(int argc, char** argv) {
  const bool probe_only = argc == 3 && std::string_view(argv[1]) == "--probe";
  if ((!probe_only && argc != 2) || (probe_only && argc != 3)) {
    std::cerr << "usage: obf-checksum-bind [--probe] <final-pe>\n";
    return 2;
  }
  try {
    return probe_only ? probe(argv[2]) : run(argv[1]);
  } catch (const bind_error& error) {
    std::cerr << "obf-checksum-bind: " << error.what() << '\n';
    return 1;
  } catch (const std::exception& error) {
    std::cerr << "obf-checksum-bind: unexpected error: " << error.what() << '\n';
    return 1;
  }
}
