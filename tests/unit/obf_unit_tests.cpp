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

void TestPolicyPrecedenceAndFloors() {
  // Test that protection level precedence is correctly enforced
  // Expected: none < light < strong < vm < strong_vm
  
  // Test: Verify level ordering (conceptual check)
  const auto none_val = static_cast<std::uint32_t>(obf::protection_level::none);
  const auto light_val = static_cast<std::uint32_t>(obf::protection_level::light);
  const auto strong_val = static_cast<std::uint32_t>(obf::protection_level::strong);
  const auto vm_val = static_cast<std::uint32_t>(obf::protection_level::vm);
  const auto strong_vm_val = static_cast<std::uint32_t>(obf::protection_level::strong_vm);
  
  ExpectTrue(none_val < light_val && light_val < strong_val && strong_val < vm_val && vm_val < strong_vm_val,
             "protection levels should follow precedence: none < light < strong < vm < strong_vm");
}

void TestConfigEdgeCases() {
  // Test edge cases in config loading
  
  // Test 1: Config with minimal fields
  const std::filesystem::path path1 =
      std::filesystem::temp_directory_path() / "obf_minimal.yaml";
  {
    std::ofstream out(path1);
    out << "default_level: strong\n";
    // No profile, seed, or other fields
  }
  
  llvm::Expected<obf::obfuscation_config> loaded1 = 
      obf::load_config_from_file(path1.string());
  ExpectTrue(static_cast<bool>(loaded1),
             "config with minimal fields should load successfully");
  if (loaded1) {
    ExpectTrue(loaded1->default_level == obf::protection_level::strong,
               "default_level should parse correctly");
  }
  
  // Test 2: Config with multiple rules
  const std::filesystem::path path2 =
      std::filesystem::temp_directory_path() / "obf_rules.yaml";
  {
    std::ofstream out(path2);
    out << "default_level: light\n";
    out << "targets:\n";
    out << "  - match: \"crypto_*\"\n";
    out << "    level: strong_vm\n";
    out << "  - match: \"hash_*\"\n";
    out << "    level: vm\n";
  }
  
  llvm::Expected<obf::obfuscation_config> loaded2 =
      obf::load_config_from_file(path2.string());
  ExpectTrue(static_cast<bool>(loaded2),
             "config with multiple rules should load successfully");
  if (loaded2) {
    ExpectTrue(loaded2->targets.size() == 2,
               "config should parse multiple target rules");
  }
  
  // Cleanup
  std::error_code ec;
  std::filesystem::remove(path1, ec);
  std::filesystem::remove(path2, ec);
}

void TestSeedStability() {
  // Verify that seed generation is deterministic and produces different results
  // for different inputs
  
  llvm::LLVMContext context;
  llvm::Module module("seed_stability_test", context);
  
  obf::obfuscation_config config1, config2;
  config1.seed = 0x111ULL;
  config2.seed = 0x222ULL;
  
  config1.default_level = obf::protection_level::strong;
  config2.default_level = obf::protection_level::strong;
  
  obf::function_features features;
  features.name = "test_func";
  features.instruction_count = 100;
  features.cyclomatic_complexity = 5;
  features.address_taken = false;
  
  // Test 1: Same inputs produce same seed
  obf::policy_decision d1a = obf::select_policy(module, features, config1, "");
  obf::policy_decision d1b = obf::select_policy(module, features, config1, "");
  ExpectTrue(d1a.seed == d1b.seed,
             "deterministic seed generation - same inputs must produce same seed");
  
  // Test 2: Different base seeds produce different derived seeds
  obf::policy_decision d2a = obf::select_policy(module, features, config1, "");
  obf::policy_decision d2b = obf::select_policy(module, features, config2, "");
  ExpectTrue(d2a.seed != d2b.seed,
             "different base seeds should produce different derived seeds");
  
  // Test 3: mix_seed is deterministic and provides sufficient entropy
  const std::uint64_t mixed1 = obf::mix_seed(0xDEADBEEFULL, 0x12345678ULL);
  const std::uint64_t mixed2 = obf::mix_seed(0xDEADBEEFULL, 0x12345678ULL);
  const std::uint64_t mixed3 = obf::mix_seed(0xDEADBEEFULL, 0x87654321ULL);
  
  ExpectTrue(mixed1 == mixed2,
             "mix_seed must be deterministic");
  ExpectTrue(mixed1 != mixed3,
             "different seeds should produce different mix_seed results");
}

} // namespace

int main() {
  TestStableHashAndSeedMix();
  TestGeneratedNames();
  TestPolicySelection();
  TestConfigLoader();
  TestPolicyPrecedenceAndFloors();
  TestConfigEdgeCases();
  TestSeedStability();

  if (g_failures == 0) {
    std::cout << "[ok] obf_unit_tests passed" << '\n';
    return 0;
  }

  std::cerr << "[fail] obf_unit_tests failures=" << g_failures << '\n';
  return 1;
}
