#pragma once

#include "llvm/ADT/ArrayRef.h"
#include "llvm/IR/Attributes.h"
#include "llvm/IR/CallingConv.h"
#include "llvm/IR/ValueHandle.h"

#include <cstdint>
#include <string>
#include <vector>

namespace llvm {
class CallBase;
class Function;
class FunctionType;
class Module;
class Type;
class Value;
}  // namespace llvm

namespace obf {

// Source identity never changes when a live instance is moved or outlined.
struct source_site_identity {
  std::uint64_t module_id = 0;
  std::uint64_t owner_id = 0;
  std::uint64_t site_id = 0;
  std::uint64_t instance_id = 0;
  bool operator==(const source_site_identity&) const = default;
};

struct vm_binding_identity {
  std::uint64_t module_id = 0;
  std::uint64_t owner_id = 0;
  std::uint64_t binding_id = 0;
  std::string symbol_tag;
  bool no_cache = false;
  bool operator==(const vm_binding_identity&) const = default;
};

struct proxy_abi_attribute {
  unsigned index = 0;
  std::string kind;
  llvm::Type* payload_type = nullptr;
  std::uint64_t allocation_size = 0;
  std::uint64_t abi_alignment = 0;
  std::uint64_t explicit_alignment = 0;
  std::string value;
  bool operator==(const proxy_abi_attribute&) const = default;
};

// LLVM types and AttributeList are context-owned immutable values, not pipeline
// storage. The serialized identity includes typed payloads and subtarget facts.
struct proxy_abi_descriptor {
  llvm::FunctionType* function_type = nullptr;
  llvm::Type* return_type = nullptr;
  std::vector<llvm::Type*> argument_types;
  llvm::CallingConv::ID calling_convention = llvm::CallingConv::C;
  unsigned pointer_address_space = 0;
  llvm::AttributeList attributes;
  std::vector<proxy_abi_attribute> qualified_attributes;
  std::string target_cpu;
  std::string target_features;
  std::string tune_cpu;
  std::string frame_pointer;
  std::string no_red_zone;
  std::string target_identity;
  std::uint64_t identity = 0;
  bool operator==(const proxy_abi_descriptor&) const = default;
};

proxy_abi_descriptor make_proxy_abi_descriptor(const llvm::CallBase& call);
bool proxy_abi_matches(const llvm::CallBase& call, const proxy_abi_descriptor& expected);

enum class vm_result_role { void_result, unchanged_result, encoded_integer };
struct vm_return_encoding_contract {
  vm_result_role role = vm_result_role::unchanged_result;
  std::uint64_t binding_id = 0;
  std::uint64_t token = 0;
  unsigned integer_width = 0;
  std::string key_global_name;
  bool operator==(const vm_return_encoding_contract&) const = default;
};

// Every association is owned and tracked independently. A tracking handle alone
// is not permission to change a role, an owner, or a VM binding.
struct live_proxy_site {
  source_site_identity identity;
  vm_binding_identity binding;
  llvm::WeakTrackingVH source_owner_function;
  llvm::WeakTrackingVH owner_function;
  llvm::WeakTrackingVH replacement_call;
  llvm::WeakTrackingVH decoded_target;
  llvm::WeakTrackingVH hidden_token_operand;
  llvm::WeakTrackingVH encoded_result;
  llvm::WeakTrackingVH return_decode_root;
  llvm::WeakTrackingVH expected_target;
  std::uint64_t decision_seed = 0;
  std::uint64_t original_site_token = 0;
  proxy_abi_descriptor effective_abi;
  vm_return_encoding_contract return_contract;
  bool selected = true;
  bool required = false;
  bool is_vm = false;
  bool preserved_musttail = false;
  bool preserved_unsupported = false;
  std::string preservation_reason;
  bool consumed = false;
  bool dead = false;
};
using vm_rewritten_site = live_proxy_site;

struct proxy_site_issue {
  source_site_identity identity;
  std::string code;
  std::string diagnostic;
};

enum class proxy_value_role { decoded_target, hidden_token, encoded_result, return_decode };

class live_proxy_site_registry;

class proxy_dead_site_proof {
  friend class live_proxy_site_registry;
  source_site_identity identity;
  std::uint64_t witness = 0;
  const live_proxy_site_registry* issuer = nullptr;
  llvm::WeakVH original_call;
};

class live_proxy_site_registry {
 public:
  std::vector<live_proxy_site>& sites() { return sites_; }
  const std::vector<live_proxy_site>& sites() const { return sites_; }

  void snapshot_source_sites(llvm::Module&);
  void register_selected_owner(llvm::Function&, std::uint64_t decision_seed, bool required);
  bool owner_selected(const llvm::Function&) const;
  bool owner_required(const llvm::Function&) const;
  void discover_native_sites(llvm::Module&);
  source_site_identity source_identity(llvm::CallBase&);

  // Register after the replacement/decode exist and before the old call dies.
  // The old call supplies a source identity, not a retained pipeline pointer.
  void register_rewrite(llvm::CallBase& old_call, vm_rewritten_site site);
  void register_preserved_musttail(llvm::CallBase&, live_proxy_site site);
  void register_preserved_site(llvm::CallBase&, live_proxy_site site);
  void replace_site(const source_site_identity&, live_proxy_site replacement);
  void move_site(const source_site_identity&, llvm::Function& new_owner);
  source_site_identity clone_site(const source_site_identity&, live_proxy_site clone);
  void replace_value(const source_site_identity&, proxy_value_role, llvm::Value& replacement);
  proxy_dead_site_proof prove_dead_site(const source_site_identity&) const;
  // Apply a proof only after its original instruction has actually been erased.
  void erase_dead_site(const source_site_identity&, const proxy_dead_site_proof&);

  // Rebuild only from explicit site/operand roles. Unknown null/noncall RAUW,
  // missing decode roles and ambiguous associations remain visible failures.
  std::vector<proxy_site_issue> rebuild(llvm::Module&);
  std::vector<proxy_site_issue> validate() const;

 private:
  struct selected_owner {
    llvm::WeakTrackingVH function;
    std::uint64_t module_id = 0;
    std::uint64_t owner_id = 0;
    std::uint64_t decision_seed = 0;
    bool required = false;
  };
  std::vector<selected_owner> owners_;
  std::vector<live_proxy_site> sites_;
  bool source_snapshot_taken_ = false;
  const llvm::Module* source_module_ = nullptr;
  live_proxy_site& lookup(const source_site_identity&);
  const live_proxy_site& lookup(const source_site_identity&) const;
  void annotate(live_proxy_site&);
};

// Shared discovery exclusion, not an admission shortcut for unsupported user
// calls. Direct calls into these exact runtime/authentication helper paths are
// infrastructure and must not change shape.
bool is_call_proxy_infrastructure(const llvm::Function&);

}  // namespace obf
