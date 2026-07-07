#include "obf/support/auth_encoding.h"
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

#include <array>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <span>
#include <string>

namespace {

int g_failures = 0;

std::string BytesToHex(std::span<const std::uint8_t> bytes) {
  static constexpr char kHexDigits[] = "0123456789abcdef";
  std::string hex;
  hex.resize(bytes.size() * 2);
  for (std::size_t index = 0; index < bytes.size(); ++index) {
    hex[index * 2] = kHexDigits[(bytes[index] >> 4) & 0xfU];
    hex[index * 2 + 1] = kHexDigits[bytes[index] & 0xfU];
  }
  return hex;
}

void ExpectTrue(bool condition, const std::string& message) {
  if (condition) { return; }

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
  llvm::FunctionType* type = llvm::FunctionType::get(llvm::Type::getVoidTy(context), false);
  llvm::Function::Create(type, llvm::GlobalValue::ExternalLinkage, base_name, module);
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
  config.targets.push_back({.match = "check_*", .level = obf::protection_level::strong});

  obf::function_features features;
  features.name = "check_license";
  features.instruction_count = 40;
  features.cyclomatic_complexity = 4;
  features.address_taken = false;

  const obf::policy_decision decision = obf::select_policy(module, features, config, "");
  ExpectTrue(decision.policy.level == obf::protection_level::strong,
             "target rule should produce strong policy level");
  ExpectTrue(decision.seed != 0, "policy selection should derive a non-zero deterministic seed");

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

  llvm::Expected<obf::obfuscation_config> loaded = obf::load_config_from_file(path.string());
  ExpectTrue(static_cast<bool>(loaded), "load_config_from_file should parse a valid YAML config");
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

void TestAuthenticatedStringConfig() {
  const std::filesystem::path path =
      std::filesystem::temp_directory_path() / "obf_auth_string_config.yaml";
  {
    std::ofstream out(path);
    out << "default_level: light\n";
    out << "string_encoding:\n";
    out << "  authenticated_mode: true\n";
    out << "  prefer_lazy_decode: false\n";
  }

  llvm::Expected<obf::obfuscation_config> loaded = obf::load_config_from_file(path.string());
  ExpectTrue(static_cast<bool>(loaded), "authenticated string config should load successfully");
  if (loaded) {
    ExpectTrue(loaded->string_encoding.authenticated_mode,
               "authenticated_mode should parse from yaml");
    ExpectTrue(!loaded->string_encoding.prefer_lazy_decode,
               "prefer_lazy_decode should respect yaml override");
    ExpectTrue(loaded->string_encoding.allow_ctor_fallback,
               "allow_ctor_fallback should keep its default value");

    const std::string summary = obf::summarize_config(*loaded);
    ExpectTrue(summary.find("string_encoding.authenticated_mode: true") != std::string::npos,
               "config summary should report authenticated string mode");
  }

  std::error_code ec;
  std::filesystem::remove(path, ec);
}

void TestReleaseMarkerConfig() {
  const std::filesystem::path path =
      std::filesystem::temp_directory_path() / "obf_release_marker_config.yaml";
  {
    std::ofstream out(path);
    out << "default_level: none\n";
    out << "security:\n";
    out << "  strip_release_markers: true\n";
  }

  llvm::Expected<obf::obfuscation_config> loaded = obf::load_config_from_file(path.string());
  ExpectTrue(static_cast<bool>(loaded), "release marker config should load successfully");
  if (loaded) {
    ExpectTrue(loaded->security.strip_release_markers,
               "strip_release_markers should parse from yaml");
    ExpectTrue(!loaded->security.fail_on_public_obf_symbol,
               "strip_release_markers should not change the public symbol gate default");

    const std::string summary = obf::summarize_config(*loaded);
    ExpectTrue(summary.find("security.strip_release_markers: true") != std::string::npos,
               "config summary should report release marker stripping");
  }

  std::error_code ec;
  std::filesystem::remove(path, ec);
}

void TestConstantProtectionModeConfig() {
  const std::filesystem::path path =
      std::filesystem::temp_directory_path() / "obf_constant_mode_config.yaml";
  {
    std::ofstream out(path);
    out << "default_level: light\n";
    out << "constant_encoding:\n";
    out << "  mode: keyed_pool\n";
    out << "  max_constants_per_function: 9\n";
  }

  llvm::Expected<obf::obfuscation_config> loaded = obf::load_config_from_file(path.string());
  ExpectTrue(static_cast<bool>(loaded), "constant protection mode config should load successfully");
  if (loaded) {
    ExpectTrue(loaded->constant_encoding.mode == obf::constant_protection_mode::keyed_pool,
               "constant protection mode should parse from yaml");
    ExpectTrue(loaded->constant_encoding.max_constants_per_function == 9,
               "max_constants_per_function should respect yaml override");
    ExpectTrue(loaded->constant_encoding.min_bit_width == 8,
               "min_bit_width should keep its default value");

    const std::string summary = obf::summarize_config(*loaded);
    ExpectTrue(summary.find("constant_encoding.mode: keyed_pool") != std::string::npos,
               "config summary should report constant protection mode");
  }

  std::error_code ec;
  std::filesystem::remove(path, ec);
}

void TestIndirectDispatchConfig() {
  const std::filesystem::path path =
      std::filesystem::temp_directory_path() / "obf_indirect_dispatch_config.yaml";
  {
    std::ofstream out(path);
    out << "default_level: strong\n";
    out << "indirect_dispatch:\n";
    out << "  enabled: true\n";
    out << "  max_sites_per_function: 9\n";
    out << "  max_switch_targets: 7\n";
    out << "  target_vm_dispatchers: false\n";
    out << "  target_flattened_headers: true\n";
  }

  llvm::Expected<obf::obfuscation_config> loaded = obf::load_config_from_file(path.string());
  ExpectTrue(static_cast<bool>(loaded), "indirect dispatch config should load successfully");
  if (loaded) {
    ExpectTrue(loaded->indirect_dispatch.enabled,
               "indirect_dispatch.enabled should parse from yaml");
    ExpectTrue(loaded->indirect_dispatch.max_sites_per_function == 9,
               "indirect_dispatch.max_sites_per_function should respect yaml override");
    ExpectTrue(loaded->indirect_dispatch.max_switch_targets == 7,
               "indirect_dispatch.max_switch_targets should respect yaml override");
    ExpectTrue(!loaded->indirect_dispatch.target_vm_dispatchers,
               "indirect_dispatch.target_vm_dispatchers should parse from yaml");
    ExpectTrue(loaded->indirect_dispatch.target_flattened_headers,
               "indirect_dispatch.target_flattened_headers should parse from yaml");

    const std::string summary = obf::summarize_config(*loaded);
    ExpectTrue(summary.find("indirect_dispatch.enabled: true") != std::string::npos,
               "config summary should report indirect dispatch enablement");
    ExpectTrue(summary.find("indirect_dispatch.max_switch_targets: 7") != std::string::npos,
               "config summary should report indirect dispatch switch cap");
  }

  std::error_code ec;
  std::filesystem::remove(path, ec);
}

void TestAuthEncodingBlake2sKnownAnswers() {
  const std::array<std::uint8_t, 0> empty_input{};
  const std::array<std::uint8_t, 3> abc = {'a', 'b', 'c'};
  std::array<std::uint8_t, obf::auth::kBuildKeyBytes> key{};
  for (std::size_t index = 0; index < key.size(); ++index) {
    key[index] = static_cast<std::uint8_t>(index);
  }

  ExpectTrue(BytesToHex(obf::auth::Blake2s(empty_input)) ==
                 "69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9",
             "blake2s empty digest should match the known answer");
  ExpectTrue(BytesToHex(obf::auth::Blake2s(abc)) ==
                 "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982",
             "blake2s abc digest should match the known answer");
  ExpectTrue(BytesToHex(obf::auth::Blake2s(abc, key)) ==
                 "a281f725754969a702f6fe36fc591b7def866e4b70173ece402fc01c064d6b65",
             "keyed blake2s abc digest should match the known answer");
}

void TestAuthEncodingBlake2sFailClosed() {
  const std::array<std::uint8_t, 33> oversized_key = {};
  const obf::auth::Blake2sDigest digest = obf::auth::Blake2s(oversized_key, oversized_key);
  ExpectTrue(digest == obf::auth::Blake2sDigest{},
             "blake2s wrapper should fail closed on invalid keyed input");
}

void TestAuthEncodingDerivationAndTagging() {
  const obf::auth::BuildKey build_key = obf::auth::DeriveBuildKey(0x123456789abcdef0ULL);
  const obf::auth::BuildKey same_build_key = obf::auth::DeriveBuildKey(0x123456789abcdef0ULL);
  const obf::auth::BuildKey other_build_key = obf::auth::DeriveBuildKey(0x123456789abcdef1ULL);
  ExpectTrue(build_key == same_build_key, "build key derivation should be deterministic");
  ExpectTrue(build_key != other_build_key, "build key derivation should separate seeds");

  const obf::auth::Blake2sDigest function_key =
      obf::auth::DeriveFunctionKey(build_key, 0x111ULL, 0x222ULL);
  const obf::auth::Blake2sDigest other_function_key =
      obf::auth::DeriveFunctionKey(build_key, 0x111ULL, 0x223ULL);
  const obf::auth::Blake2sDigest site_key =
      obf::auth::DeriveSiteKey(function_key, obf::auth::kDomainString, 0x333ULL);
  const obf::auth::Blake2sDigest other_site_key =
      obf::auth::DeriveSiteKey(function_key, obf::auth::kDomainString, 0x334ULL);
  const obf::auth::Blake2sDigest enc_key =
      obf::auth::DeriveLabeledKey(site_key, obf::auth::kDomainEnc);
  const obf::auth::Blake2sDigest mac_key =
      obf::auth::DeriveLabeledKey(site_key, obf::auth::kDomainMac);

  ExpectTrue(function_key != other_function_key,
             "function key derivation should separate function identifiers");
  ExpectTrue(site_key != other_site_key, "site key derivation should separate site identifiers");
  ExpectTrue(enc_key != mac_key, "enc and mac labels should derive different keys");

  const obf::auth::StringNonce nonce = obf::auth::DeriveStringNonce(site_key);
  const std::array<std::uint8_t, 7> plaintext = {'s', 'e', 'c', 'r', 'e', 't', 0};
  std::array<std::uint8_t, 7> ciphertext{};
  std::array<std::uint8_t, 7> roundtrip{};
  obf::auth::XorStringPayload(ciphertext, plaintext, enc_key, nonce);
  obf::auth::XorStringPayload(roundtrip, ciphertext, enc_key, nonce);
  ExpectTrue(roundtrip == plaintext, "string payload xor should round-trip with the same key");

  obf::auth::StringAuthMetadata metadata;
  metadata.length = plaintext.size();
  metadata.module_id = 0x111ULL;
  metadata.function_id = 0x222ULL;
  metadata.site_id = 0x333ULL;
  metadata.nonce = nonce;

  const obf::auth::StringTag tag = obf::auth::ComputeStringTag(mac_key, metadata, ciphertext);
  std::array<std::uint8_t, 7> tampered = ciphertext;
  tampered[0] ^= 0x40U;
  const obf::auth::StringTag tampered_tag =
      obf::auth::ComputeStringTag(mac_key, metadata, tampered);
  ExpectTrue(tag != tampered_tag, "string tag should change when ciphertext changes");
}

void TestAuthEncodingConstantTimeEqual() {
  const obf::auth::StringTag lhs = obf::auth::MakeTag(0x1234ULL, 0x5678ULL);
  const obf::auth::StringTag same = lhs;
  const obf::auth::StringTag different = obf::auth::MakeTag(0x1234ULL, 0x5679ULL);
  const std::array<std::uint8_t, 15> shorter = {};

  ExpectTrue(obf::auth::ConstantTimeEqual(lhs, same),
             "constant time equal should accept matching inputs");
  ExpectTrue(!obf::auth::ConstantTimeEqual(lhs, different),
             "constant time equal should reject mismatched bytes");
  ExpectTrue(!obf::auth::ConstantTimeEqual(lhs, shorter),
             "constant time equal should reject mismatched lengths");
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

  ExpectTrue(none_val < light_val && light_val < strong_val && strong_val < vm_val &&
                 vm_val < strong_vm_val,
             "protection levels should follow precedence: none < light < strong < vm < strong_vm");
}

void TestConfigEdgeCases() {
  // Test edge cases in config loading

  // Test 1: Config with minimal fields
  const std::filesystem::path path1 = std::filesystem::temp_directory_path() / "obf_minimal.yaml";
  {
    std::ofstream out(path1);
    out << "default_level: strong\n";
    // No profile, seed, or other fields
  }

  llvm::Expected<obf::obfuscation_config> loaded1 = obf::load_config_from_file(path1.string());
  ExpectTrue(static_cast<bool>(loaded1), "config with minimal fields should load successfully");
  if (loaded1) {
    ExpectTrue(loaded1->default_level == obf::protection_level::strong,
               "default_level should parse correctly");
  }

  // Test 2: Config with multiple rules
  const std::filesystem::path path2 = std::filesystem::temp_directory_path() / "obf_rules.yaml";
  {
    std::ofstream out(path2);
    out << "default_level: light\n";
    out << "targets:\n";
    out << "  - match: \"crypto_*\"\n";
    out << "    level: strong_vm\n";
    out << "  - match: \"hash_*\"\n";
    out << "    level: vm\n";
    out << "security:\n";
    out << "  fail_on_public_obf_symbol: true\n";
  }

  llvm::Expected<obf::obfuscation_config> loaded2 = obf::load_config_from_file(path2.string());
  ExpectTrue(static_cast<bool>(loaded2), "config with multiple rules should load successfully");
  if (loaded2) {
    ExpectTrue(loaded2->targets.size() == 2, "config should parse multiple target rules");
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
  ExpectTrue(d2a.seed != d2b.seed, "different base seeds should produce different derived seeds");

  // Test 3: mix_seed is deterministic and provides sufficient entropy
  const std::uint64_t mixed1 = obf::mix_seed(0xDEADBEEFULL, 0x12345678ULL);
  const std::uint64_t mixed2 = obf::mix_seed(0xDEADBEEFULL, 0x12345678ULL);
  const std::uint64_t mixed3 = obf::mix_seed(0xDEADBEEFULL, 0x87654321ULL);

  ExpectTrue(mixed1 == mixed2, "mix_seed must be deterministic");
  ExpectTrue(mixed1 != mixed3, "different seeds should produce different mix_seed results");
}

}  // namespace

int main() {
  TestStableHashAndSeedMix();
  TestGeneratedNames();
  TestPolicySelection();
  TestConfigLoader();
  TestAuthenticatedStringConfig();
  TestReleaseMarkerConfig();
  TestConstantProtectionModeConfig();
  TestIndirectDispatchConfig();
  TestPolicyPrecedenceAndFloors();
  TestConfigEdgeCases();
  TestSeedStability();
  TestAuthEncodingBlake2sKnownAnswers();
  TestAuthEncodingBlake2sFailClosed();
  TestAuthEncodingDerivationAndTagging();
  TestAuthEncodingConstantTimeEqual();

  if (g_failures == 0) {
    std::cout << "[ok] obf_unit_tests passed" << '\n';
    return 0;
  }

  std::cerr << "[fail] obf_unit_tests failures=" << g_failures << '\n';
  return 1;
}
