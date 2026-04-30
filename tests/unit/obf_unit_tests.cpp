#include "obf/frontend/config.h"
#include "obf/policy/policy_engine.h"
#include "obf/support/generated_names.h"
#include "obf/support/stable_hash.h"

#include "llvm/ADT/StringRef.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Type.h"
#include "llvm/Support/Error.h"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>

namespace {

int g_failures = 0;

void ExpectTrue(bool condition, const std::string &message) {
  if (condition) {
    return;
  }

  ++g_failures;
  std::cerr << "[fail] " << message << '\n';
}

void TestStableHashAndSeedMix() {
  const std::uint64_t hash_a = obf::stable_hash_string("alpha");
  const std::uint64_t hash_b = obf::stable_hash_string("alpha");
  const std::uint64_t hash_c = obf::stable_hash_string("beta");
  ExpectTrue(hash_a == hash_b, "stable_hash_string must be deterministic");
  ExpectTrue(hash_a != hash_c, "stable_hash_string should differ for different inputs");

  const std::uint64_t mixed_a = obf::mix_seed(0x1234ULL, 0x55ULL);
  const std::uint64_t mixed_b = obf::mix_seed(0x1234ULL, 0x55ULL);
  const std::uint64_t mixed_c = obf::mix_seed(0x1234ULL, 0x56ULL);
  ExpectTrue(mixed_a == mixed_b, "mix_seed must be deterministic");
  ExpectTrue(mixed_a != mixed_c, "mix_seed should differ for different salts");
}

void TestGeneratedNames() {
  llvm::LLVMContext context;
  llvm::Module module("obf_unit_generated_names", context);

  const std::string base_name =
      obf::make_unique_obf_symbol_name(module, "obf_sym", "source", 0x42ULL);
  llvm::FunctionType *type =
      llvm::FunctionType::get(llvm::Type::getVoidTy(context), false);
  llvm::Function::Create(type, llvm::GlobalValue::ExternalLinkage, base_name,
                         module);
  const std::string next_name =
      obf::make_unique_obf_symbol_name(module, "obf_sym", "source", 0x42ULL);

  ExpectTrue(!base_name.empty(), "generated base name must not be empty");
  ExpectTrue(next_name != base_name,
             "unique generated name should avoid existing symbol collision");
}

void TestPolicySelection() {
  llvm::LLVMContext context;
  llvm::Module module("policy_module", context);

  obf::obfuscation_config config;
  config.seed = 0x777ULL;
  config.default_level = obf::protection_level::none;
  config.targets.push_back(
      {.match = "check_*", .level = obf::protection_level::strong});

  obf::function_features features;
  features.name = "check_license";
  features.instruction_count = 40;
  features.cyclomatic_complexity = 4;
  features.address_taken = false;

  const obf::policy_decision decision =
      obf::select_policy(module, features, config, "");
  ExpectTrue(decision.policy.level == obf::protection_level::strong,
             "target rule should produce strong policy level");
  ExpectTrue(decision.seed != 0,
             "policy selection should derive a non-zero deterministic seed");

  const auto parsed = obf::parse_protection_level("obf:strong_vm");
  ExpectTrue(parsed.has_value() && *parsed == obf::protection_level::strong_vm,
             "parse_protection_level should parse annotation prefix form");
}

void TestConfigLoader() {
  const std::filesystem::path path =
      std::filesystem::temp_directory_path() / "obf_unit_config.yaml";
  {
    std::ofstream out(path);
    out << "profile: guarded\n";
    out << "seed: 99\n";
    out << "default_level: light\n";
  }

  llvm::Expected<obf::obfuscation_config> loaded =
      obf::load_config_from_file(path.string());
  ExpectTrue(static_cast<bool>(loaded),
             "load_config_from_file should parse a valid YAML config");
  if (loaded) {
    ExpectTrue(loaded->profile.has_value(), "profile should be present");
    ExpectTrue(loaded->seed == 99, "seed should match parsed yaml value");
    ExpectTrue(loaded->default_level == obf::protection_level::light,
               "default_level should match parsed yaml value");
    ExpectTrue(loaded->security.fail_on_public_obf_symbol,
               "guarded profile defaults should enforce strong vm symbol gate");
  }

  std::error_code ec;
  std::filesystem::remove(path, ec);
}

} // namespace

int main() {
  TestStableHashAndSeedMix();
  TestGeneratedNames();
  TestPolicySelection();
  TestConfigLoader();

  if (g_failures == 0) {
    std::cout << "[ok] obf_unit_tests passed" << '\n';
    return 0;
  }

  std::cerr << "[fail] obf_unit_tests failures=" << g_failures << '\n';
  return 1;
}
