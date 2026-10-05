#include "llvm/ADT/SmallString.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/BinaryFormat/COFF.h"
#include "llvm/BinaryFormat/ELF.h"
#include "llvm/Object/Archive.h"
#include "llvm/Object/Binary.h"
#include "llvm/Object/COFF.h"
#include "llvm/Object/ELFObjectFile.h"
#include "llvm/Object/ObjectFile.h"
#include "llvm/Support/Allocator.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Error.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/JSON.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/Program.h"
#include "llvm/Support/SHA256.h"
#include "llvm/Support/StringSaver.h"
#include "llvm/Support/raw_ostream.h"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <compare>
#include <filesystem>
#include <map>
#include <memory>
#include <optional>
#include <regex>
#include <set>
#include <stdexcept>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

namespace {
using llvm::StringRef;
namespace object = llvm::object;
namespace fs = std::filesystem;

class ownership_error : public std::runtime_error {
 public:
  using std::runtime_error::runtime_error;
};

[[noreturn]] void fail(const std::string& message) { throw ownership_error(message); }

template <class T> T take(llvm::Expected<T> value, const std::string& context) {
  if (!value) { fail(context + ": " + llvm::toString(value.takeError())); }
  return std::move(*value);
}

std::string lower(std::string value) {
  std::transform(value.begin(), value.end(), value.begin(),
                 [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
  return value;
}

std::string trim(StringRef text) { return text.trim().str(); }

std::string canonical(const std::string& path) {
  std::error_code error;
  auto result = fs::weakly_canonical(fs::absolute(fs::path(path), error), error);
  if (error) { fail("cannot resolve input path " + path + ": " + error.message()); }
#ifdef _WIN32
  return lower(result.string());
#else
  return result.string();
#endif
}

std::string read_file(const std::string& path) {
  auto buffer = llvm::MemoryBuffer::getFile(path, false, false);
  if (!buffer) { fail("cannot read " + path + ": " + buffer.getError().message()); }
  return (*buffer)->getBuffer().str();
}

void write_file(const std::string& path, StringRef text) {
  std::error_code error;
  llvm::raw_fd_ostream stream(path, error, llvm::sys::fs::OF_None);
  if (error) { fail("cannot write " + path + ": " + error.message()); }
  stream << text;
  stream.close();
  if (stream.has_error()) { stream.clear_error(); fail("cannot finish writing " + path); }
}

struct temporary_directory {
  std::string path;
  temporary_directory() {
    llvm::SmallString<128> result;
    auto error = llvm::sys::fs::createUniqueDirectory("obf-native-link", result);
    if (error) { fail("cannot create authority directory: " + error.message()); }
    path = result.str().str();
  }
  ~temporary_directory() { (void)llvm::sys::fs::remove_directories(path); }
  std::string file(const char* name) const { return (fs::path(path) / name).string(); }
};

std::string response_text(const std::string& path) {
  std::string bytes = read_file(path);
  if (bytes.size() >= 2 &&
      ((static_cast<unsigned char>(bytes[0]) == 0xff && static_cast<unsigned char>(bytes[1]) == 0xfe) ||
       (static_cast<unsigned char>(bytes[0]) == 0xfe && static_cast<unsigned char>(bytes[1]) == 0xff))) {
    const bool little = static_cast<unsigned char>(bytes[0]) == 0xff;
    if (bytes.size() % 2 != 0) { fail("malformed UTF-16 response file " + path); }
    std::string utf8;
    auto word = [&](std::size_t offset) -> unsigned {
      const auto a = static_cast<unsigned char>(bytes[offset]);
      const auto b = static_cast<unsigned char>(bytes[offset + 1]);
      return little ? a | (b << 8) : b | (a << 8);
    };
    for (std::size_t i = 2; i < bytes.size(); i += 2) {
      unsigned cp = word(i);
      if (cp >= 0xd800 && cp <= 0xdbff) {
        if (i + 3 >= bytes.size()) { fail("truncated UTF-16 response file " + path); }
        const unsigned low = word(i + 2);
        if (low < 0xdc00 || low > 0xdfff) { fail("invalid UTF-16 response file " + path); }
        cp = 0x10000 + ((cp - 0xd800) << 10) + low - 0xdc00;
        i += 2;
      } else if (cp >= 0xdc00 && cp <= 0xdfff) {
        fail("invalid UTF-16 response file " + path);
      }
      if (cp < 0x80) { utf8 += static_cast<char>(cp); }
      else if (cp < 0x800) {
        utf8 += static_cast<char>(0xc0 | (cp >> 6));
        utf8 += static_cast<char>(0x80 | (cp & 63));
      } else if (cp < 0x10000) {
        utf8 += static_cast<char>(0xe0 | (cp >> 12));
        utf8 += static_cast<char>(0x80 | ((cp >> 6) & 63));
        utf8 += static_cast<char>(0x80 | (cp & 63));
      } else {
        utf8 += static_cast<char>(0xf0 | (cp >> 18));
        utf8 += static_cast<char>(0x80 | ((cp >> 12) & 63));
        utf8 += static_cast<char>(0x80 | ((cp >> 6) & 63));
        utf8 += static_cast<char>(0x80 | (cp & 63));
      }
    }
    return utf8;
  }
  if (StringRef(bytes).starts_with("\xef\xbb\xbf")) { bytes.erase(0, 3); }
  return bytes;
}

void expand_responses(const std::vector<std::string>& args, bool coff,
                      std::vector<std::string>& expanded, unsigned depth = 0) {
  if (depth > 20) { fail("linker response nesting exceeds 20 levels"); }
  for (const auto& arg : args) {
    if (arg.size() <= 1 || arg[0] != '@') { expanded.push_back(arg); continue; }
    const auto text = response_text(arg.substr(1));
    llvm::BumpPtrAllocator allocator;
    llvm::StringSaver saver(allocator);
    llvm::SmallVector<const char*, 32> tokens;
    if (coff) { llvm::cl::TokenizeWindowsCommandLine(text, saver, tokens); }
    else { llvm::cl::TokenizeGNUCommandLine(text, saver, tokens); }
    std::vector<std::string> nested;
    for (const auto* token : tokens) { nested.emplace_back(token); }
    expand_responses(nested, coff, expanded, depth + 1);
  }
}

// Linker response quoting is intentionally separate from driver quoting.
std::string quote_argument(const std::string& arg, bool coff) {
  std::string result = "\"";
  if (!coff) {
    for (char c : arg) {
      if (c == '\\' || c == '"') { result += '\\'; }
      result += c;
    }
  } else {
    std::size_t slashes = 0;
    for (char c : arg) {
      if (c == '\\') { ++slashes; continue; }
      result.append(c == '"' ? slashes * 2 + 1 : slashes, '\\');
      slashes = 0;
      result += c;
    }
    result.append(slashes * 2, '\\');
  }
  result += "\"\n";
  return result;
}

struct reference {
  std::string symbol;
  bool local;
  auto operator<=>(const reference&) const = default;
};
struct definition {
  reference name;
  std::string kind;
  std::vector<reference> targets;
  bool operator==(const definition&) const = default;
};
struct reader {
  reference owner;
  std::vector<reference> dependencies;
};

std::string required_string(const llvm::json::Object& record, const char* key) {
  auto value = record.getString(key);
  if (!value || value->empty() || value->contains('\0')) {
    fail(std::string("invalid ownership field ") + key);
  }
  return value->str();
}
reference parse_reference(const llvm::json::Object& record, const char* key = "symbol") {
  auto local = record.getBoolean("local");
  if (!local) { fail("ownership reference requires boolean local"); }
  return {required_string(record, key), *local};
}
std::vector<reference> parse_references(const llvm::json::Object& record, const char* key) {
  const auto* values = record.getArray(key);
  if (!values) { fail(std::string("ownership record requires array ") + key); }
  std::vector<reference> result;
  for (const auto& value : *values) {
    const auto* object = value.getAsObject();
    if (!object) { fail("ownership target is not an object"); }
    result.push_back(parse_reference(*object));
  }
  std::sort(result.begin(), result.end());
  result.erase(std::unique(result.begin(), result.end()), result.end());
  return result;
}
definition parse_definition(const llvm::json::Object& record, bool raw) {
  definition result{parse_reference(record), required_string(record, "kind"),
                    parse_references(record, "targets")};
  if (result.kind != "plaintext" && result.kind != "forward" && result.kind != "non_string" &&
      result.kind != "protected" && result.kind != "unknown") { fail("unknown definition kind " + result.kind); }
  if (raw && result.kind == "protected") { fail("raw provenance cannot declare protected definitions"); }
  if (result.kind == "forward" && result.targets.empty()) { fail("forward definition has no targets"); }
  if (result.kind != "forward" && !result.targets.empty()) { fail("non-forward definition has targets"); }
  return result;
}

struct symbol_info { bool local; std::string section; };
struct unit {
  std::string path;
  std::string member;
  std::string label;
  std::string hash;
  std::unique_ptr<object::Binary> member_binary;
  object::ObjectFile* object_file = nullptr;
  std::map<std::string, std::vector<symbol_info>> symbols;
  std::map<std::string, std::string> weak_fallbacks;
  std::map<reference, definition> definitions;
  std::vector<reader> readers;
  bool raw_loaded = false;
};

std::uint64_t little_number(StringRef data, std::size_t offset, std::size_t width) {
  if (offset > data.size() || width > data.size() - offset) { fail("truncated .obfns ownership record"); }
  std::uint64_t result = 0;
  for (std::size_t i = 0; i < width; ++i) {
    result |= static_cast<std::uint64_t>(static_cast<unsigned char>(data[offset + i])) << (8 * i);
  }
  return result;
}

void add_definition(unit& input, definition value) {
  auto [where, inserted] = input.definitions.try_emplace(value.name, std::move(value));
  if (!inserted && where->second != value) { fail("conflicting ownership for " + value.name.symbol + " in " + input.label); }
}

void parse_records(unit& input, StringRef data) {
  if (data.empty()) { fail("empty .obfns ownership section in " + input.label); }
  std::size_t cursor = 0;
  while (cursor < data.size()) {
    if (data.size() - cursor < 32 || data.substr(cursor, 4) != "OBNS" ||
        little_number(data, cursor + 4, 2) != 1 || little_number(data, cursor + 6, 2) != 32 ||
        little_number(data, cursor + 24, 4) != 0 || little_number(data, cursor + 28, 4) != 0) {
      fail("malformed or unsupported .obfns header in " + input.label);
    }
    const auto payload = little_number(data, cursor + 8, 4);
    const auto count = little_number(data, cursor + 12, 4);
    if (payload > data.size() - cursor - 32) { fail("truncated .obfns payload in " + input.label); }
    cursor += 32;
    const std::size_t end = cursor + static_cast<std::size_t>(payload);
    for (std::uint64_t i = 0; i < count; ++i) {
      if (end - cursor < 8) { fail("incorrect .obfns entry count in " + input.label); }
      const auto length = little_number(data, cursor, 4);
      const auto kind = little_number(data, cursor + 4, 2);
      if (little_number(data, cursor + 6, 2) != 0 || (kind != 1 && kind != 2)) {
        fail("invalid .obfns entry kind or flags in " + input.label);
      }
      cursor += 8;
      if (length > end - cursor) { fail("truncated .obfns entry in " + input.label); }
      auto value = take(llvm::json::parse(data.substr(cursor, static_cast<std::size_t>(length))),
                        "invalid .obfns JSON in " + input.label);
      const auto* record = value.getAsObject();
      if (!record) { fail(".obfns entry is not a JSON object in " + input.label); }
      if (kind == 1) {
        input.readers.push_back({parse_reference(*record, "owner"), parse_references(*record, "dependencies")});
      } else { add_definition(input, parse_definition(*record, false)); }
      cursor += static_cast<std::size_t>(length);
    }
    if (cursor != end) { fail("incorrect .obfns payload size in " + input.label); }
  }
}

bool has_definition(const unit& input, const reference& ref) {
  const auto found = input.symbols.find(ref.symbol);
  if (found == input.symbols.end()) { return false; }
  unsigned count = 0;
  for (const auto& info : found->second) { if (info.local == ref.local) { ++count; } }
  if (count > 1) { fail("ambiguous object-local symbol " + ref.symbol + " in " + input.label); }
  return count == 1;
}

void validate_record_section(unit& input, const object::SectionRef& section) {
  if (llvm::isa<object::ELFObjectFileBase>(input.object_file)) {
    const object::ELFSectionRef elf(section);
    if (elf.getType() != llvm::ELF::SHT_PROGBITS || (elf.getFlags() & llvm::ELF::SHF_ALLOC) != 0) {
      fail("invalid ELF .obfns section attributes in " + input.label);
    }
    for (const auto& candidate : input.object_file->sections()) {
      const auto relocated = take(candidate.getRelocatedSection(), "invalid relocation section in " + input.label);
      if (relocated != input.object_file->section_end() && relocated->getIndex() == section.getIndex() &&
          candidate.relocation_begin() != candidate.relocation_end()) {
        fail(".obfns must not contain relocations in " + input.label);
      }
    }
  } else if (auto* coff = llvm::dyn_cast<object::COFFObjectFile>(input.object_file)) {
    const auto flags = coff->getCOFFSection(section)->Characteristics;
    constexpr auto required = llvm::COFF::IMAGE_SCN_LNK_INFO | llvm::COFF::IMAGE_SCN_LNK_REMOVE;
    if ((flags & required) != required || section.relocation_begin() != section.relocation_end()) {
      fail("invalid COFF .obfns section attributes or relocations in " + input.label);
    }
  } else { fail("unsupported native .obfns object format in " + input.label); }
}

void read_unit(unit& input) {
  auto* object_file = input.object_file;
  for (const auto& symbol : object_file->symbols()) {
    auto flags = take(symbol.getFlags(), "invalid symbol flags in " + input.label);
    const auto name = take(symbol.getName(), "invalid symbol name in " + input.label);
    if ((flags & object::SymbolRef::SF_Undefined) != 0) {
      if (auto* coff = llvm::dyn_cast<object::COFFObjectFile>(object_file)) {
        const auto* weak = coff->getCOFFSymbol(symbol).getWeakExternal();
        if (weak && weak->Characteristics == llvm::COFF::IMAGE_WEAK_EXTERN_SEARCH_ALIAS) {
          const auto fallback = take(coff->getSymbol(weak->TagIndex), "invalid COFF weak fallback in " + input.label);
          input.weak_fallbacks.emplace(name.str(), take(coff->getSymbolName(fallback), "invalid COFF weak name in " + input.label).str());
        }
      }
      continue;
    }
    const auto section = take(symbol.getSection(), "invalid symbol section in " + input.label);
    std::string section_name;
    if (section != object_file->section_end()) {
      section_name = take(section->getName(), "invalid section name in " + input.label).str();
    }
    input.symbols[name.str()].push_back({(flags & object::SymbolRef::SF_Global) == 0, std::move(section_name)});
  }
  for (const auto& [name, fallback] : input.weak_fallbacks) {
    const auto found = input.symbols.find(fallback);
    if (found == input.symbols.end()) { continue; }
    for (const auto& info : found->second) {
      if (!info.local) { input.symbols[name].push_back(info); }
    }
  }
  for (const auto& section : object_file->sections()) {
    const auto name = take(section.getName(), "invalid section name in " + input.label);
    if (name == ".obfns") {
      validate_record_section(input, section);
      parse_records(input, take(section.getContents(), "cannot read .obfns in " + input.label));
    }
  }
  for (const auto& owned : input.readers) {
    if (owned.owner.local && !has_definition(input, owned.owner)) {
      fail("ownership reader has no actual local object symbol " + owned.owner.symbol + " in " + input.label);
    }
  }
}

const std::string& object_hash(unit& input) {
  if (input.hash.empty()) {
    const auto bytes = input.object_file->getMemoryBufferRef().getBuffer();
    const auto digest = llvm::SHA256::hash(llvm::ArrayRef<std::uint8_t>(
        reinterpret_cast<const std::uint8_t*>(bytes.data()), bytes.size()));
    static constexpr char hex[] = "0123456789abcdef";
    input.hash.reserve(64);
    for (auto byte : digest) { input.hash += hex[byte >> 4]; input.hash += hex[byte & 15]; }
  }
  return input.hash;
}

struct catalog {
  std::string path;
  object::OwningBinary<object::Binary> binary;
  std::set<std::string> non_owning_members;
};

struct authority {
  bool external_available = false;
  bool sections_available = false;
  std::map<std::string, std::string> prevailing;
  std::set<std::string> selected;
  std::set<std::pair<std::string, std::string>> contributions;
  std::set<std::pair<std::string, std::string>> local_symbols;
  void symbol(std::string name, std::string identity) {
    if (identity.empty() || identity.front() == '<') { return; }
    auto [it, inserted] = prevailing.emplace(name, identity);
    if (!inserted && it->second != identity) { fail("ambiguous prevailing definition for " + name); }
    selected.insert(std::move(identity));
  }
};

std::string after_columns(StringRef line, unsigned count) {
  for (unsigned i = 0; i < count; ++i) {
    line = line.ltrim();
    const auto end = line.find_first_of(" \t");
    if (end == StringRef::npos) { return {}; }
    line = line.drop_front(end);
  }
  return line.ltrim().str();
}

void parse_contributions(authority& result, StringRef map, bool lld, bool coff) {
  if (!lld) {
    const auto start = map.find("Linker script and memory map");
    if (start == StringRef::npos) { return; }
    map = map.drop_front(start);
  }
  llvm::SmallVector<StringRef, 128> lines;
  map.split(lines, '\n');
  std::string previous_section;
  std::string current_identity;
  const std::regex gnu_section(R"(^\s+(\S+)\s+0x[0-9a-fA-F]+\s+0x[0-9a-fA-F]+\s+(.+?)\s*$)");
  const std::regex gnu_wrapped(R"(^\s+0x[0-9a-fA-F]+\s+0x[0-9a-fA-F]+\s+(.+?)\s*$)");
  for (auto raw : lines) {
    const auto line = raw.rtrim().str();
    if (lld) {
      const auto tail = after_columns(raw, coff ? 3 : 4);
      const auto delimiter = tail.rfind(":(");
      if (delimiter != std::string::npos && !tail.empty() && tail.back() == ')') {
        const auto identity = tail.substr(0, delimiter);
        auto section = tail.substr(delimiter + 2, tail.size() - delimiter - 3);
        const auto offset = section.find("+0x");
        if (offset != std::string::npos) { section.erase(offset); }
        if (!identity.empty() && identity.front() != '<') {
          result.selected.insert(identity);
          result.contributions.emplace(identity, section);
          current_identity = identity;
        } else { current_identity.clear(); }
      } else if (!tail.empty() && !current_identity.empty() && raw.find("                ") != StringRef::npos) {
        // Local symbols are meaningful only within their actual contribution.
        // External prevailing definitions come from cref or normal COFF MAP.
        if (tail.find_first_of(" \t") == std::string::npos) {
          result.selected.insert(current_identity);
        }
      }
    } else {
      std::smatch matched;
      if (StringRef(line).starts_with("LOAD ")) { result.selected.insert(trim(StringRef(line).drop_front(5))); }
      if (std::regex_match(line, matched, gnu_section)) {
        const auto section = matched[1].str();
        const auto identity = matched[2].str();
        if (!section.empty() && section.front() == '.') {
          result.selected.insert(identity);
          result.contributions.emplace(identity, section);
        }
        previous_section.clear();
      } else if (!previous_section.empty() && std::regex_match(line, matched, gnu_wrapped)) {
        const auto identity = matched[1].str();
        result.selected.insert(identity);
        result.contributions.emplace(identity, previous_section);
        previous_section.clear();
      } else {
        const auto trimmed = trim(raw);
        if (!line.empty() && line.front() == ' ' && !trimmed.empty() && trimmed.front() == '.' &&
            trimmed.find_first_of(" \t") == std::string::npos) { previous_section = trimmed; }
        else { previous_section.clear(); }
      }
    }
  }
  result.sections_available = true;
}

authority parse_elf_map(StringRef map, bool lld) {
  authority result;
  const auto marker = map.find("Cross Reference Table");
  if (marker != StringRef::npos) {
    result.external_available = true;
    llvm::SmallVector<StringRef, 128> lines;
    map.drop_front(marker).split(lines, '\n');
    bool header = false;
    std::string pending;
    for (auto line : lines) {
      if (!header) { if (line.trim().starts_with("Symbol") && line.contains("File")) { header = true; } continue; }
      if (line.trim().empty()) { continue; }
      if (std::isspace(static_cast<unsigned char>(line.front()))) {
        if (!pending.empty()) { result.symbol(pending, trim(line)); pending.clear(); }
        else { result.selected.insert(trim(line)); }
        continue;
      }
      const auto split = line.find_first_of(" \t");
      if (split == StringRef::npos) { pending = line.str(); continue; }
      const auto identity = trim(line.drop_front(split));
      if (identity.empty()) { pending = line.take_front(split).str(); }
      else { result.symbol(line.take_front(split).str(), identity); }
    }
  }
  parse_contributions(result, marker == StringRef::npos ? map : map.take_front(marker), lld, false);
  return result;
}

authority parse_coff_map(StringRef map, StringRef lldmap) {
  authority result;
  result.external_available = map.contains("Publics by Value") && map.contains("Lib:Object");
  const std::regex entry(R"(^\s*[0-9a-fA-F]{4}:[0-9a-fA-F]+\s+(\S+)\s+[0-9a-fA-F]+\s+(?:[fi]\s+)*(.+?)\s*$)");
  llvm::SmallVector<StringRef, 128> lines;
  map.split(lines, '\n');
  bool public_entries = false;
  bool static_entries = false;
  for (auto raw : lines) {
    if (raw.contains("Publics by Value")) { public_entries = true; }
    if (raw.trim() == "Static symbols") { public_entries = false; static_entries = true; }
    std::smatch matched;
    const auto line = raw.str();
    if (!std::regex_match(line, matched, entry)) { continue; }
    if (public_entries) { result.symbol(matched[1].str(), matched[2].str()); }
    else if (static_entries && matched[2].str().front() != '<') {
      result.selected.insert(matched[2].str());
      result.local_symbols.emplace(matched[2].str(), matched[1].str());
    }
  }
  if (!lldmap.empty()) { parse_contributions(result, lldmap, true, true); }
  return result;
}

class validator {
  authority& resolution;
  bool coff;
  std::map<std::string, std::unique_ptr<catalog>> catalogs;
  std::map<std::pair<std::string, std::string>, std::unique_ptr<unit>> units;
  std::map<std::string, unit*> identities;
  std::set<std::string> non_owning_identities;
  std::set<std::string> non_owning_member_labels;
  std::vector<std::pair<std::string, llvm::json::Value>> manifests;
  std::set<std::tuple<unit*, std::string, bool>> active;
  std::set<std::tuple<unit*, std::string, bool>> accepted;

  void add_catalog(const std::string& path) {
    std::error_code error;
    if (!fs::is_regular_file(fs::path(path), error)) { return; }
    const auto key = canonical(path);
    if (catalogs.contains(key)) { return; }
    auto binary = object::createBinary(path);
    if (!binary) { llvm::consumeError(binary.takeError()); return; }
    if (!llvm::isa<object::ObjectFile>(binary->getBinary()) && !llvm::isa<object::Archive>(binary->getBinary())) { return; }
    auto entry = std::make_unique<catalog>();
    entry->path = key;
    entry->binary = std::move(*binary);
    catalogs.emplace(key, std::move(entry));
  }

  unit* load(catalog& source, const std::string& member) {
    const auto key = std::make_pair(source.path, member);
    if (source.non_owning_members.contains(member)) { return nullptr; }
    if (const auto found = units.find(key); found != units.end()) { return found->second.get(); }
    auto input = std::make_unique<unit>();
    input->path = source.path;
    input->member = member;
    input->label = source.path + (member.empty() ? "" : "(" + member + ")");
    if (member.empty()) {
      input->object_file = llvm::dyn_cast<object::ObjectFile>(source.binary.getBinary());
    } else {
      auto* archive = llvm::dyn_cast<object::Archive>(source.binary.getBinary());
      if (!archive) { return nullptr; }
      llvm::Error error = llvm::Error::success();
      unsigned matches = 0;
      std::string canonical_member;
      bool may_carry_records = false;
      for (const auto& child : archive->children(error)) {
        const auto name = take(child.getName(), "cannot read archive member name in " + source.path);
        bool matching = name == member;
        if (coff && member.find_first_of("/\\") == std::string::npos) {
          const auto slash = name.find_last_of("/\\");
          matching = matching || (slash != StringRef::npos && name.drop_front(slash + 1) == member);
        }
        if (!matching && archive->isThin()) {
          const auto full = take(child.getFullName(), "cannot read thin archive identity in " + source.path);
          matching = full == member || ((member.find_first_of("/\\") != std::string::npos) && canonical(full) == canonical(member));
        }
        if (!matching) { continue; }
        canonical_member = name.str();
        ++matches;
        auto binary = take(child.getAsBinary(), "cannot read selected archive member identity " + input->label);
        if (auto* candidate = llvm::dyn_cast<object::ObjectFile>(binary.get())) {
          // Inspect section headers only. Ambiguous candidates are never
          // parsed for provenance or treated as extracted definitions.
          for (const auto& section : candidate->sections()) {
            if (take(section.getName(), "invalid archive section name in " + input->label) == ".obfns") {
              may_carry_records = true;
            }
          }
        }
        if (name == member) { input->member_binary = std::move(binary); }
      }
      if (error) { fail("malformed archive " + source.path + ": " + llvm::toString(std::move(error))); }
      if (matches > 1) {
        if (may_carry_records) { fail("duplicate selected archive member identity with ownership evidence " + input->label); }
        source.non_owning_members.insert(member);
        return nullptr;
      }
      if (matches == 0) { return nullptr; }
      if (canonical_member != member) {
        auto* result = load(source, canonical_member);
        if (source.non_owning_members.contains(canonical_member)) { source.non_owning_members.insert(member); }
        return result;
      }
      input->object_file = llvm::dyn_cast<object::ObjectFile>(input->member_binary.get());
      if (input->member_binary->isCOFFImportFile()) {
        source.non_owning_members.insert(member);
        return nullptr;
      }
    }
    if (!input->object_file || !input->object_file->isRelocatableObject()) { return nullptr; }
    read_unit(*input);
    auto* result = input.get();
    units.emplace(key, std::move(input));
    return result;
  }

  bool alias_matches(const std::string& identity, const std::string& path, bool library) const {
    const auto name = fs::path(path).filename().string();
    if (lower(identity) == lower(name)) { return true; }
    return library && lower(identity) == lower(fs::path(path).stem().string());
  }

  unit* resolve(const std::string& identity, bool required) {
    if (non_owning_identities.contains(identity)) {
      if (required) { fail("unresolved required static provider identity " + identity); }
      return nullptr;
    }
    if (const auto known = identities.find(identity); known != identities.end()) { return known->second; }
    std::string path = identity;
    std::string member;
    if (!identity.empty() && identity.back() == ')') {
      const auto open = identity.rfind('(');
      if (open != std::string::npos) { path = identity.substr(0, open); member = identity.substr(open + 1, identity.size() - open - 2); }
    }
    add_catalog(path);
    std::vector<unit*> candidates;
    const auto exact = catalogs.find(canonical(path));
    if (exact != catalogs.end()) {
      if (auto* input = load(*exact->second, member)) { candidates.push_back(input); }
      else if (!member.empty() && llvm::isa<object::Archive>(exact->second->binary.getBinary())) {
        if (!exact->second->non_owning_members.contains(member)) { fail("unresolved selected archive member identity " + identity); }
        non_owning_identities.insert(identity);
        non_owning_member_labels.insert(lower(fs::path(member).filename().string()));
        if (required) { fail("unresolved required static provider identity " + identity); }
        return nullptr;
      }
    }
    if (candidates.empty() && coff) {
      std::string library;
      std::string object_name = identity;
      const auto colon = identity.rfind(':');
      if (colon != std::string::npos && !(colon == 1 && identity.size() > 2 &&
          (identity[2] == '\\' || identity[2] == '/'))) {
        library = identity.substr(0, colon);
        object_name = identity.substr(colon + 1);
      }
      if (library.empty()) {
        // LLD contribution maps abbreviate archive members. Bind that
        // abbreviation to already-authoritative MAP Lib:Object identities.
        for (const auto& [known_identity, input] : identities) {
          (void)known_identity;
          if (input->member.empty()) { continue; }
          const auto slash = input->member.find_last_of("/\\");
          const auto leaf = slash == std::string::npos ? input->member : input->member.substr(slash + 1);
          if (input->member == object_name || leaf == object_name) { candidates.push_back(input); }
        }
      }
      if (library.empty() && candidates.empty()) {
        for (auto& [key, source] : catalogs) {
          if (!llvm::isa<object::ObjectFile>(source->binary.getBinary()) || !alias_matches(object_name, key, false)) { continue; }
          if (auto* input = load(*source, "")) { candidates.push_back(input); }
        }
      } else if (!library.empty()) {
        std::vector<catalog*> libraries;
        for (auto& [key, source] : catalogs) {
          if (llvm::isa<object::Archive>(source->binary.getBinary()) && alias_matches(library, key, true)) {
            libraries.push_back(source.get());
          }
        }
        if (libraries.size() > 1) { fail("ambiguous actual searched-library identity " + library); }
        if (libraries.size() == 1) {
          auto* input = load(*libraries.front(), object_name);
          if (!input) {
            if (!libraries.front()->non_owning_members.contains(object_name)) { fail("unresolved actual archive member identity " + identity); }
            non_owning_identities.insert(identity);
            non_owning_member_labels.insert(lower(fs::path(object_name).filename().string()));
            if (required) { fail("unresolved required static provider identity " + identity); }
            return nullptr;
          }
          candidates.push_back(input);
        }
      }
    }
    std::sort(candidates.begin(), candidates.end());
    candidates.erase(std::unique(candidates.begin(), candidates.end()), candidates.end());
    if (candidates.size() > 1) {
      const bool may_own = std::any_of(candidates.begin(), candidates.end(), [](const unit* input) {
        return std::any_of(input->readers.begin(), input->readers.end(),
                           [](const reader& value) { return !value.dependencies.empty(); });
      });
      if (required || may_own) { fail("ambiguous actual linker input identity " + identity); }
      return nullptr;
    }
    if (candidates.empty()) {
      if (coff && non_owning_member_labels.contains(lower(identity))) {
        non_owning_identities.insert(identity);
        if (required) { fail("unresolved required static provider identity " + identity); }
        return nullptr;
      }
      if (required) { fail("cannot resolve actual linker provider " + identity); }
      return nullptr;
    }
    identities.emplace(identity, candidates.front());
    return candidates.front();
  }

  void load_raw(unit& input) {
    if (input.raw_loaded) { return; }
    input.raw_loaded = true;
    for (const auto& [base, value] : manifests) {
      const auto* providers = value.getAsObject()->getArray("providers");
      for (const auto& provider_value : *providers) {
        const auto* provider = provider_value.getAsObject();
        if (!provider) { continue; }
        const auto path = provider->getString("path");
        if (!path || path->empty()) { continue; }
        const auto provider_path = fs::path(path->str());
        if (canonical((provider_path.is_absolute() ? provider_path : fs::path(base) / provider_path).string()) != input.path) { continue; }
        const auto member = provider->getString("member");
        if ((!input.member.empty() && (!member || *member != input.member)) ||
            (input.member.empty() && member)) { continue; }
        const auto digest = provider->getString("sha256");
        if (!digest || digest->size() != 64 || lower(digest->str()) != object_hash(input)) {
          fail("raw provenance SHA256 mismatch for " + input.label);
        }
        const auto* definitions = provider->getArray("definitions");
        if (!definitions) { fail("raw provenance lacks definitions for " + input.label); }
        for (const auto& definition_value : *definitions) {
          const auto* record = definition_value.getAsObject();
          if (!record) { fail("raw definition is not an object for " + input.label); }
          auto def = parse_definition(*record, true);
          if (!has_definition(input, def.name)) {
            fail("raw provenance names absent definition " + def.name.symbol + " in " + input.label);
          }
          add_definition(input, std::move(def));
        }
      }
    }
  }

  unit* prevailing_provider(const std::string& symbol, bool required) {
    const auto found = resolution.prevailing.find(symbol);
    if (found != resolution.prevailing.end()) { return resolve(found->second, true); }
    unit* provider = nullptr;
    if (coff) {
      // A COFF weak alias can have only its physical fallback in MAP.
      // The fallback must itself be an actual prevailing MAP definition in
      // the alias's selected object; nominal names alone prove nothing.
      for (const auto& [key, input] : units) {
        (void)key;
        const auto weak = input->weak_fallbacks.find(symbol);
        if (weak == input->weak_fallbacks.end()) { continue; }
        const auto fallback = resolution.prevailing.find(weak->second);
        if (fallback == resolution.prevailing.end() || resolve(fallback->second, true) != input.get()) { continue; }
        if (provider && provider != input.get()) { fail("ambiguous prevailing COFF weak alias " + symbol); }
        provider = input.get();
      }
    }
    if (!provider && required) { fail("missing prevailing provider for " + symbol); }
    return provider;
  }

  bool has_live_section(unit& input, const reference& owner) {
    if (!resolution.sections_available) { return true; }
    bool unresolved = false;
    const auto found = input.symbols.find(owner.symbol);
    if (found == input.symbols.end()) { return false; }
    const auto& symbols = found->second;
    for (const auto& info : symbols) {
      if (info.local != owner.local) { continue; }
      if (info.section.empty()) { return true; }
      for (const auto& [identity, section] : resolution.contributions) {
        if (section != info.section) { continue; }
        auto* selected = resolve(identity, false);
        if (selected == &input) { return true; }
        if (!selected) { unresolved = true; }
      }
    }
    if (unresolved) { fail("unresolved actual section contribution for owned reader " + owner.symbol); }
    return false;
  }

  bool survives(unit& input, const reference& owner) {
    if (owner.local) {
      if (coff && !resolution.sections_available) {
        if (!resolution.external_available) { fail("unsupported COFF local-reader authority for " + owner.symbol); }
        for (const auto& [identity, symbol] : resolution.local_symbols) {
          if (symbol == owner.symbol && resolve(identity, true) == &input) { return true; }
        }
        return false;
      }
      return has_live_section(input, owner);
    }
    if (!has_live_section(input, owner)) { return false; }
    if (!resolution.external_available) { fail("unsupported native link authority for owned reader " + owner.symbol); }
    auto* provider = prevailing_provider(owner.symbol, false);
    if (!provider && !coff) { fail("missing prevailing authority for surviving reader " + owner.symbol); }
    return provider == &input;
  }

  void dependency(unit& origin, const reference& ref, const std::string& owner,
                  unsigned forwarding_depth = 0) {
    unit* provider = &origin;
    if (!ref.local) {
      if (!resolution.external_available) { fail("unsupported native link authority for dependency " + ref.symbol + " of " + owner); }
      provider = prevailing_provider(ref.symbol, true);
    }
    if (!ref.local && !has_definition(*provider, ref)) { fail("provider lacks actual definition " + ref.symbol + " required by " + owner); }
    const auto key = std::make_tuple(provider, ref.symbol, ref.local);
    load_raw(*provider);
    const auto found = provider->definitions.find(ref);
    if (found == provider->definitions.end()) { fail("missing native provenance for " + ref.symbol + " in " + provider->label + " required by " + owner); }
    const auto& def = found->second;
    if (def.kind == "forward" && forwarding_depth != 0) {
      fail("unsupported second forwarding level for " + ref.symbol + " required by " + owner);
    }
    // Depth is checked before the memoized result: a cell accepted as a root
    // cannot become an accepted second forwarding level on a later path.
    if (accepted.contains(key)) { return; }
    if (!active.insert(key).second) { fail("unresolved cyclic native provenance for " + ref.symbol + " required by " + owner); }
    if (ref.local && def.kind == "forward" && !has_definition(*provider, ref)) {
      fail("provider lacks actual forward definition " + ref.symbol + " required by " + owner);
    }
    if (def.kind == "plaintext") { fail("strong_vm reader " + owner + " requires plaintext static string " + ref.symbol + " in " + provider->label); }
    if (def.kind == "unknown") { fail("unknown native provenance for " + ref.symbol + " required by " + owner); }
    if (def.kind == "forward") {
      for (const auto& target : def.targets) { dependency(*provider, target, owner, forwarding_depth + 1); }
    }
    active.erase(key);
    accepted.insert(key);
  }

 public:
  validator(authority& authoritative, bool is_coff, const std::vector<std::string>& args,
            StringRef trace, const std::vector<std::string>& manifest_paths)
      : resolution(authoritative), coff(is_coff) {
    for (const auto& arg : args) { add_catalog(arg); }
    llvm::SmallVector<StringRef, 128> lines;
    trace.split(lines, '\n');
    for (auto line : lines) {
      auto text = line.trim();
      if (text.starts_with("Searching ") && text.ends_with(":")) {
        add_catalog(text.drop_front(10).drop_back().str());
      } else {
        for (const auto prefix : {StringRef("lld-link: Reading "), StringRef("Reading "),
                                  StringRef("lld-link: Loaded "), StringRef("Loaded ")}) {
          if (!text.starts_with(prefix)) { continue; }
          auto path = text.drop_front(prefix.size());
          const auto open = path.rfind('(');
          if (open != StringRef::npos) { path = path.take_front(open); }
          add_catalog(path.str());
        }
      }
    }
    for (const auto& identity : resolution.selected) {
      std::string path = identity;
      if (!path.empty() && path.back() == ')') {
        const auto open = path.rfind('(');
        if (open != std::string::npos) { path.erase(open); }
      }
      add_catalog(path);
    }
    for (const auto& path : manifest_paths) {
      auto value = take(llvm::json::parse(read_file(path)), "invalid raw provenance manifest " + path);
      const auto* manifest = value.getAsObject();
      if (!manifest || manifest->getInteger("version") != 1 || !manifest->getArray("providers")) {
        fail("unsupported raw provenance manifest " + path);
      }
      manifests.emplace_back(fs::path(canonical(path)).parent_path().string(), std::move(value));
    }
  }

  void validate() {
    // An archive candidate is considered only for an identity reported by the
    // actual link. Never walk undefined symbols to simulate archive extraction.
    for (auto& [path, source] : catalogs) {
      (void)path;
      auto* file = llvm::dyn_cast<object::ObjectFile>(source->binary.getBinary());
      if (file && file->isRelocatableObject()) { (void)load(*source, ""); }
    }
    for (const auto& [symbol, identity] : resolution.prevailing) {
      (void)symbol;
      (void)resolve(identity, false);
    }
    for (const auto& [identity, symbol] : resolution.local_symbols) {
      (void)symbol;
      (void)resolve(identity, false);
    }
    for (const auto& identity : resolution.selected) {
      if (resolve(identity, false) || non_owning_identities.contains(identity)) { continue; }
      if (coff && std::any_of(resolution.contributions.begin(), resolution.contributions.end(),
                             [&](const auto& value) { return value.first == identity; })) {
        fail("missing authoritative MAP Lib:Object binding for selected input " + identity);
      }
    }
    for (auto it = units.begin(); it != units.end(); ++it) {
      auto& input = *it->second;
      for (const auto& owned : input.readers) {
        if (owned.dependencies.empty() || !survives(input, owned.owner)) { continue; }
        for (const auto& ref : owned.dependencies) { dependency(input, ref, input.label + ":" + owned.owner.symbol); }
      }
    }
  }
};

struct link_options {
  bool coff = false;
  bool lld = false;
  bool partial = false;
  bool query = false;
  bool user_cref = false;
  std::string output;
  std::string user_map;
  std::string user_lldmap;
  std::vector<std::string> manifests;
  std::vector<std::string> args;
};

std::optional<std::string> gnu_map_output(StringRef map) {
  const std::regex statement(R"(^OUTPUT\((.+)\s+\S+\)\s*$)");
  llvm::SmallVector<StringRef, 128> lines;
  map.split(lines, '\n');
  std::optional<std::string> output;
  for (const auto line : lines) {
    std::smatch matched;
    const auto text = line.str();
    if (std::regex_match(text, matched, statement)) { output = matched[1].str(); }
  }
  return output;
}

link_options parse_options(const std::string& real_linker, const std::vector<std::string>& original,
                           bool elf_lld = false) {
  link_options result;
  const auto name = lower(fs::path(real_linker).filename().string());
  result.coff = name == "link" || name == "link.exe" || name == "lld-link" || name == "lld-link.exe";
  const char* flavor = std::getenv("OBF_NATIVE_LINK_FLAVOR");
  if (flavor && std::string(flavor) == "coff") { result.coff = true; }
  result.lld = elf_lld || name == "lld-link" || name == "lld-link.exe" || name == "ld.lld" || name == "ld.lld.exe";
  std::vector<std::string> expanded;
  expand_responses(original, result.coff, expanded);
  for (std::size_t i = 0; i < expanded.size(); ++i) {
    const auto& arg = expanded[i];
    const auto low = lower(arg);
    if (StringRef(arg).starts_with("--obf-native-provenance=")) {
      const auto path = arg.substr(std::string("--obf-native-provenance=").size());
      if (path.empty()) { fail("--obf-native-provenance requires a path"); }
      result.manifests.push_back(path);
      continue;
    }
    if (arg == "--obf-native-provenance") {
      if (++i == expanded.size() || expanded[i].empty()) { fail("--obf-native-provenance requires a path"); }
      result.manifests.push_back(expanded[i]);
      continue;
    }
    if (result.coff) {
      if (StringRef(low).starts_with("/out:") || StringRef(low).starts_with("-out:")) { result.output = arg.substr(5); }
      if (low == "/map" || low == "-map") { result.user_map = "<default>"; continue; }
      if (StringRef(low).starts_with("/map:") || StringRef(low).starts_with("-map:")) { result.user_map = arg.substr(5); continue; }
      if (low == "/lldmap" || low == "-lldmap") { result.user_lldmap = "<default>"; continue; }
      if (StringRef(low).starts_with("/lldmap:") || StringRef(low).starts_with("-lldmap:")) { result.user_lldmap = arg.substr(8); continue; }
      if (low == "/?" || low == "/help" || low == "-help" || low == "--version") { result.query = true; }
    } else {
      if (arg == "-r" || arg == "--relocatable" || arg == "-i") { result.partial = true; }
      if (arg == "--version" || arg == "--help") { result.query = true; }
      if (arg == "-o" || arg == "--output") {
        if (i + 1 == expanded.size()) { fail(arg + " requires a path"); }
        result.output = expanded[i + 1];
        result.args.push_back(arg);
        result.args.push_back(expanded[++i]);
        continue;
      }
      const auto equal = arg.find('=');
      const auto option_name = StringRef(arg).take_front(equal == std::string::npos ? arg.size() : equal);
      const bool orphan_option = option_name == "--orphan-handling" ||
          (result.lld ? option_name == "-orphan-handling" :
           (option_name.starts_with("-or") && StringRef("-orphan-handling").starts_with(option_name)));
      const bool import_library_option = !result.lld && option_name.starts_with("-ou") &&
          StringRef("-out-implib").starts_with(option_name);
      if (arg == "--oformat" || ((orphan_option || import_library_option) && equal == std::string::npos)) {
        result.args.push_back(arg);
        if (i + 1 != expanded.size()) { result.args.push_back(expanded[++i]); }
        continue;
      }
      if (StringRef(arg).starts_with("--output=")) { result.output = arg.substr(9); }
      else if (StringRef(arg).starts_with("-o") && arg.size() > 2 && !orphan_option && !import_library_option) {
        result.output = arg.substr(2);
      }
      if (arg == "-Map" || arg == "--Map") {
        if (++i == expanded.size()) { fail(arg + " requires a path"); }
        result.user_map = expanded[i];
        continue;
      }
      if (StringRef(arg).starts_with("-Map=") || StringRef(arg).starts_with("--Map=")) {
        result.user_map = arg.substr(arg.find('=') + 1); continue;
      }
      if (StringRef(arg).starts_with("-Map") && arg.size() > 4) { result.user_map = arg.substr(4); continue; }
      if (arg == "--cref") { result.user_cref = true; }
    }
    result.args.push_back(arg);
  }
  if (result.output.empty() && !result.coff) { result.output = "a.out"; }
  if (result.coff && !result.output.empty()) {
    auto path = fs::path(result.output); path.replace_extension(".map");
    if (result.user_map == "<default>") { result.user_map = path.string(); }
    if (result.user_lldmap == "<default>") { result.user_lldmap = path.string(); }
  }
  return result;
}

int execute(const std::string& real, const std::vector<std::string>& args,
            const std::string& response, bool coff,
            const std::string& stdout_path = {}, const std::string& stderr_path = {}) {
  std::string text = coff ? "\xef\xbb\xbf" : "";
  for (const auto& arg : args) { text += quote_argument(arg, coff); }
  write_file(response, text);
  const std::string reference = "@" + response;
  const llvm::StringRef command[] = {real, reference};
  std::optional<llvm::StringRef> redirects[] = {std::nullopt, std::nullopt, std::nullopt};
  if (!stdout_path.empty()) { redirects[1] = stdout_path; redirects[2] = stderr_path; }
  std::string error;
  const int result = llvm::sys::ExecuteAndWait(real, command, std::nullopt, redirects, 0, 0, &error);
  if (result < 0) { fail("cannot execute native linker: " + error); }
  return result;
}

int run(int argc, char** argv) {
  const auto* real_env = std::getenv("OBF_NATIVE_REAL_LINKER");
  if (!real_env || !*real_env) { fail("private native linker dispatch requires OBF_NATIVE_REAL_LINKER"); }
  const std::string real = real_env;
  if (canonical(real) == canonical(argv[0])) { fail("native linker proxy cannot dispatch to itself"); }
  std::vector<std::string> args;
  for (int i = 1; i < argc; ++i) { args.emplace_back(argv[i]); }
  auto options = parse_options(real, args);
  temporary_directory temporary;
  if (options.partial || options.query) {
    if (!options.manifests.empty()) { fail("raw native provenance is a final-link option"); }
    // Preserve the original partial-link/map semantics and .obfns payloads.
    return execute(real, args, temporary.file("link.rsp"), options.coff);
  }
  const auto* result_env = std::getenv("OBF_NATIVE_LINK_RESULT");
  if (result_env && *result_env) {
    if (const auto error = llvm::sys::fs::remove(result_env)) {
      fail("cannot clear private native output result: " + error.message());
    }
  }
  if (options.output.empty() || options.output == "-") { fail("native ownership requires a named final-link output"); }
  const auto private_map = temporary.file("authority.map");
  const auto private_lldmap = temporary.file("authority.lldmap");
  auto link_args = options.args;
  if (options.coff) {
    link_args.push_back("/map:" + private_map);
    link_args.push_back(options.lld ? "/verbose" : "/verbose:lib");
    if (options.lld) { link_args.push_back("/lldmap:" + private_lldmap); }
  } else {
    link_args.push_back("--cref");
    link_args.push_back("--no-demangle");
    link_args.push_back("-Map=" + private_map);
  }
  const auto stdout_path = temporary.file("stdout");
  const auto stderr_path = temporary.file("stderr");
  const int result = execute(real, link_args, temporary.file("link.rsp"), options.coff, stdout_path, stderr_path);
  try {
    if (result == 0 && !options.coff) {
      auto authority_map = llvm::MemoryBuffer::getFile(private_map, false, false);
      if (authority_map && !(*authority_map)->getBuffer().ltrim().starts_with("VMA")) {
        // GNU getopt_long_only accepts abbreviations which do not share
        // LLD's option semantics. Its map names the actual output, including
        // linker-script OUTPUT directives and joined -o filenames.
        if (const auto output = gnu_map_output((*authority_map)->getBuffer())) {
          options.output = *output;
        }
      } else if (authority_map && !options.lld) {
        // The LLD map header also identifies ELF LLD when a selected driver
        // executable has a nonstandard basename.
        options.output = parse_options(real, options.args, true).output;
        options.lld = true;
      }
    }
    const auto stdout_text = read_file(stdout_path);
    const auto stderr_text = read_file(stderr_path);
    llvm::outs() << stdout_text; llvm::outs().flush();
    llvm::errs() << stderr_text; llvm::errs().flush();
    if (result != 0) {
      // A failed real link can still produce the user's requested map.
      try {
        auto failed_map = llvm::MemoryBuffer::getFile(private_map, false, false);
        if (failed_map && options.user_map == "-") { llvm::outs() << (*failed_map)->getBuffer(); }
        else if (failed_map && !options.user_map.empty()) { write_file(options.user_map, (*failed_map)->getBuffer()); }
        auto failed_lldmap = llvm::MemoryBuffer::getFile(private_lldmap, false, false);
        if (failed_lldmap && !options.user_lldmap.empty()) { write_file(options.user_lldmap, (*failed_lldmap)->getBuffer()); }
      } catch (const ownership_error& error) { llvm::errs() << "obf-native-link: " << error.what() << "\n"; }
      return result;
    }
    const auto map = read_file(private_map);
    if (options.user_map == "-") { llvm::outs() << map; }
    else if (!options.user_map.empty()) { write_file(options.user_map, map); }
    const auto lldmap = options.coff && options.lld ? read_file(private_lldmap) : std::string();
    if (!options.user_lldmap.empty()) { write_file(options.user_lldmap, lldmap); }
    if (!options.coff && options.user_cref && options.user_map.empty()) {
      const auto marker = map.find("Cross Reference Table");
      if (marker != std::string::npos) { llvm::outs() << StringRef(map).drop_front(marker); }
    }
    auto authoritative = options.coff ? parse_coff_map(map, lldmap) :
        parse_elf_map(map, options.lld || StringRef(map).ltrim().starts_with("VMA"));
    validator enforce(authoritative, options.coff, options.args, stdout_text + "\n" + stderr_text, options.manifests);
    enforce.validate();
    if (result_env && *result_env) {
      std::error_code error;
      const auto actual_output = fs::absolute(fs::path(options.output), error);
      if (error) { fail("cannot resolve validated native output: " + error.message()); }
      write_file(result_env, actual_output.string());
    }
  } catch (...) {
    const auto error = llvm::sys::fs::remove(options.output);
    if (error) { llvm::errs() << "obf-native-link: cannot remove rejected primary output " << options.output << ": " << error.message() << "\n"; }
    throw;
  }
  return 0;
}
}  // namespace

int main(int argc, char** argv) {
  try { return run(argc, argv); }
  catch (const std::exception& error) {
    llvm::errs() << "obf-native-link: " << error.what() << "\n";
    return 2;
  }
}
