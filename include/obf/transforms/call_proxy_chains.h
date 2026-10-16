#pragma once

#include "obf/frontend/config.h"
#include "obf/transforms/call_proxy_sites.h"
#include "llvm/ADT/ArrayRef.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/IR/ValueHandle.h"

#include <cstdint>
#include <string>
#include <vector>

namespace llvm {
class CallBase;
class Function;
class Module;
}  // namespace llvm

namespace obf {

inline constexpr unsigned call_proxy_schema = 1;
inline constexpr llvm::StringLiteral proxy_qualification_identity =
    "proxy-v1-x86_64-c-fast-integral64";

enum class proxy_route_mode { stateful, abi_only };

struct proxy_platform_contract {
  bool supported = false;
  bool windows = false;
  bool scalar = true;
  bool floating = true;
  bool vector = true;
  bool aggregate = true;
  bool byval = true;
  bool sret = true;
  bool inreg = true;
  bool return_continuation = true;
  bool terminal_hardening = true;
  std::string identity;
  std::string rejection;
};

struct proxy_dependency_descriptor {
  std::uint64_t identity = 0;
  llvm::WeakTrackingVH function;
  std::string abi_identity;
};

struct proxy_admission {
  bool admitted = false;
  proxy_route_mode mode = proxy_route_mode::stateful;
  std::string code;
  std::string diagnostic;
  llvm::WeakTrackingVH target;
  std::string abi_identity;
  std::string security_domain;
  std::vector<proxy_dependency_descriptor> dependencies;
  std::vector<llvm::WeakTrackingVH> preserved_global_loads;
};

struct admitted_proxy_site {
  live_proxy_site site;
  proxy_admission admission;
};

struct proxy_node_descriptor {
  std::uint64_t identity = 0;
  std::uint64_t constant = 0;
  std::uint64_t multiplier = 1;
  std::uint64_t addend = 0;
  unsigned rotation = 1;
};

struct proxy_route_descriptor {
  admitted_proxy_site source;
  std::uint64_t route_id = 0;
  std::uint64_t route_seed = 0;
  std::uint64_t target_salt = 0;
  std::uint64_t terminal_id = 0;
  std::uint64_t checker_id = 0;
  std::uint32_t descriptor_index = 0;
  std::vector<proxy_node_descriptor> nodes;
  std::uint64_t reserved_instructions = 0;
  std::uint64_t context_bytes = 0;
};

struct proxy_coverage_event {
  source_site_identity identity;
  bool protected_site = false;
  bool required = false;
  proxy_route_mode mode = proxy_route_mode::stateful;
  std::uint32_t hops = 0;
  std::uint64_t route_id = 0;
  std::string code;
  std::string diagnostic;
  std::uint64_t binding_id = 0;
  std::uint64_t terminal_id = 0;
  std::string abi_identity;
};

struct proxy_resource_counts {
  std::uint64_t sites = 0;
  std::uint64_t nodes = 0;
  std::uint64_t memberships = 0;
  std::uint64_t context_bytes = 0;
  std::uint64_t added_instructions = 0;
  std::uint64_t pending_lto_guard_instructions = 0;
};

struct proxy_plan {
  std::vector<proxy_route_descriptor> routes;
  std::vector<proxy_coverage_event> events;
  proxy_resource_counts reserved;
};

struct proxy_live_contract {
  proxy_route_descriptor route;
  llvm::WeakTrackingVH owner;
  llvm::WeakTrackingVH entry;
  llvm::WeakTrackingVH context;
  llvm::WeakTrackingVH admitted_target;
  llvm::WeakTrackingVH terminal;
  llvm::WeakTrackingVH checker;
  std::vector<llvm::WeakTrackingVH> hops;
  std::string configuration_identity;
  std::string platform_identity;
  std::uint64_t exact_context_bytes = 0;
  bool recovered = false;
};

struct proxy_contract_registry {
  std::vector<proxy_live_contract> contracts;
  proxy_resource_counts exact;
  call_proxy_options options;
  bool configured = false;
  bool reserve_lto_guards = false;
};

struct proxy_stage_result {
  bool changed = false;
  std::vector<proxy_coverage_event> events;
  proxy_resource_counts exact;
};

proxy_platform_contract proxy_platform_contract_for(const llvm::Module&);
proxy_admission analyze_proxy_site(const live_proxy_site&,
                                   const proxy_platform_contract&,
                                   const call_proxy_options&);
proxy_plan plan_call_proxy_chains(llvm::Module&,
                                  llvm::ArrayRef<admitted_proxy_site>,
                                  const call_proxy_options&);
proxy_stage_result apply_call_proxy_chain_stage(llvm::Module&,
                                                const call_proxy_options&,
                                                live_proxy_site_registry&,
                                                proxy_contract_registry&);
void validate_live_proxy_contracts(llvm::Module&,
                                   const proxy_contract_registry&,
                                   const proxy_platform_contract&);
void recover_call_proxy_contracts(llvm::Module&,
                                  proxy_contract_registry&,
                                  const call_proxy_options&);
void retain_call_proxy_contracts(llvm::Module&,
                                 const proxy_contract_registry&,
                                 const call_proxy_options&);
void release_call_proxy_metadata(llvm::Module&);
bool is_call_proxy_helper(const llvm::Function&);
bool is_call_proxy_entry(const llvm::CallBase&);
std::string call_proxy_configuration_identity(const call_proxy_options&);

}  // namespace obf
