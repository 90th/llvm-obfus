#include "obf/transforms/string_encoding.h"

#include "llvm/ADT/DenseSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/Analysis/ValueTracking.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalAlias.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/Casting.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"

#include <algorithm>
#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace obf {

namespace {

constexpr llvm::StringRef kCfgStatePlaceholderName = "__obf_get_cfg_state";
constexpr llvm::StringRef kExpectedCfgStatePlaceholderName =
    "__obf_get_expected_cfg_state";

enum class string_use_kind {
  call_argument,
  compare_call_operand,
  select_operand,
  phi_operand,
  return_operand,
  address_materialization,
  forwarded_pointer_load,
  escaped_address,
  generic_operand,
  non_function_use,
};

struct classified_string_use {
  llvm::Instruction *instruction = nullptr;
  unsigned operand_index = 0;
  string_use_kind kind = string_use_kind::generic_operand;
  bool rewriteable = false;
  bool inline_candidate = false;
};

struct string_use_summary {
  llvm::SmallVector<const llvm::Function *, 4> protected_functions;
  llvm::SmallVector<const llvm::Function *, 4> unprotected_functions;
  llvm::SmallVector<classified_string_use, 8> protected_uses;
  llvm::SmallVector<string_use_kind, 8> observed_kinds;
  bool has_non_function_use = false;
  bool has_lazy_blockers = false;
  bool has_forwarded_pointer_load = false;
};

struct classified_string_candidate {
  llvm::GlobalVariable *global = nullptr;
  std::uint64_t seed = 0;
  bool has_high_security_use = false;
  bool has_strong_vm_use = false;
  string_use_summary summary;
  string_encoding_result result;
};

struct string_strategy_plan {
  llvm::GlobalVariable *global = nullptr;
  std::uint64_t seed = 0;
  bool isolate_lazy_helper = false;
  string_encoding_result result;
  llvm::SmallVector<classified_string_use, 8> lazy_uses;
  llvm::SmallVector<classified_string_use, 8> inline_uses;
};

struct descriptor_layout {
  unsigned base_index = 0;
  unsigned state_index = 1;
  unsigned length_index = 2;
  unsigned seed_index = 3;
};

int merge_group_for_shape(string_helper_shape shape) {
  switch (shape) {
  case string_helper_shape::lazy_flag_unrolled_v0:
    return 0;
  case string_helper_shape::lazy_flag_reverse_v1:
    return 1;
  case string_helper_shape::lazy_cached_pointer_v3:
    return 2;
  default:
    return -1;
  }
}

bool is_annotation_user(const llvm::User *user) {
  const auto *global = llvm::dyn_cast<llvm::GlobalVariable>(user);
  return global != nullptr && global->getName() == "llvm.global.annotations";
}

bool is_string_like_global(const llvm::GlobalVariable &global) {
  if (!global.hasInitializer()) {
    return false;
  }

  const auto *data =
      llvm::dyn_cast<llvm::ConstantDataSequential>(global.getInitializer());
  return data != nullptr && data->isCString();
}

bool is_supported_string_global(const llvm::GlobalVariable &global,
                                std::size_t min_string_length) {
  if (!is_string_like_global(global) || !global.isConstant() ||
      global.isThreadLocal()) {
    return false;
  }

  if (!(global.hasPrivateLinkage() || global.hasInternalLinkage())) {
    return false;
  }

  if (global.getName().starts_with("llvm.")) {
    return false;
  }

  if (global.hasSection() && global.getSection() == "llvm.metadata") {
    return false;
  }

  const auto *data =
      llvm::cast<llvm::ConstantDataSequential>(global.getInitializer());
  return data->getNumElements() >= min_string_length;
}

void add_unique_function(llvm::SmallVectorImpl<const llvm::Function *> &functions,
                         const llvm::Function *function) {
  if (function != nullptr && llvm::find(functions, function) == functions.end()) {
    functions.push_back(function);
  }
}

void add_use_kind(llvm::SmallVectorImpl<string_use_kind> &observed_kinds,
                  string_use_kind kind) {
  if (llvm::find(observed_kinds, kind) == observed_kinds.end()) {
    observed_kinds.push_back(kind);
  }
}

std::string to_string(string_use_kind kind) {
  switch (kind) {
  case string_use_kind::call_argument:
    return "call_argument";
  case string_use_kind::compare_call_operand:
    return "compare_call_operand";
  case string_use_kind::select_operand:
    return "select_operand";
  case string_use_kind::phi_operand:
    return "phi_operand";
  case string_use_kind::return_operand:
    return "return_operand";
  case string_use_kind::address_materialization:
    return "address_materialization";
  case string_use_kind::forwarded_pointer_load:
    return "forwarded_pointer_load";
  case string_use_kind::escaped_address:
    return "escaped_address";
  case string_use_kind::generic_operand:
    return "generic_operand";
  case string_use_kind::non_function_use:
    return "non_function_use";
  }

  return "generic_operand";
}

bool operand_references_global(llvm::Value *operand,
                               const llvm::GlobalVariable &global) {
  if (operand == nullptr) {
    return false;
  }

  llvm::Value *underlying = llvm::getUnderlyingObject(operand);
  return underlying == &global;
}

bool is_local_constant_forwarding_global(const llvm::GlobalVariable &global) {
  return global.hasInitializer() && global.isConstant() &&
         !global.isThreadLocal() && global.hasLocalLinkage();
}

bool is_local_forwarding_alias(const llvm::GlobalAlias &alias) {
  return alias.hasLocalLinkage();
}

bool operand_references_value(const llvm::Value *operand, const llvm::Value &value) {
  if (operand == nullptr) {
    return false;
  }

  if (operand == &value) {
    return true;
  }

  if (const auto *global = llvm::dyn_cast<llvm::GlobalVariable>(&value)) {
    return operand_references_global(const_cast<llvm::Value *>(operand), *global);
  }

  llvm::Value *underlying = llvm::getUnderlyingObject(const_cast<llvm::Value *>(operand));
  return underlying == &value;
}

bool collect_forwarded_pointer_load_uses(const llvm::Value &value,
                                         const llvm::Instruction &instruction,
                                         bool is_protected,
                                         string_use_summary &summary) {
  if (!llvm::isa<llvm::GetElementPtrInst>(instruction) &&
      !llvm::isa<llvm::BitCastInst>(instruction)) {
    return false;
  }

  bool matched_forwarding_operand = false;
  for (llvm::Value *operand : instruction.operands()) {
    if (operand_references_value(operand, value)) {
      matched_forwarding_operand = true;
      break;
    }
  }

  if (!matched_forwarding_operand) {
    return false;
  }

  bool handled = false;
  for (const llvm::User *forward_user : instruction.users()) {
    const auto *load = llvm::dyn_cast<llvm::LoadInst>(forward_user);
    if (load == nullptr || !load->getType()->isPointerTy()) {
      continue;
    }

    handled = true;
    add_use_kind(summary.observed_kinds, string_use_kind::forwarded_pointer_load);
    if (is_protected) {
      summary.has_forwarded_pointer_load = true;
    }
  }

  return handled;
}

bool has_forwarded_pointer_table_use(const llvm::Value &value,
                                     protected_function_seed_lookup get_seed,
                                     llvm::DenseSet<const llvm::User *> &visited) {
  for (const llvm::User *user : value.users()) {
    if (!visited.insert(user).second || is_annotation_user(user)) {
      continue;
    }

    if (const auto *instruction = llvm::dyn_cast<llvm::Instruction>(user)) {
      const llvm::Function *function = instruction->getFunction();
      if (function == nullptr || !get_seed(function->getName()).has_value()) {
        continue;
      }

      if (const auto *load = llvm::dyn_cast<llvm::LoadInst>(instruction)) {
        if (load->getType()->isPointerTy() &&
            operand_references_value(load->getPointerOperand(), value)) {
          return true;
        }
      }

      if (!llvm::isa<llvm::GetElementPtrInst>(instruction) &&
          !llvm::isa<llvm::BitCastInst>(instruction)) {
        continue;
      }

      for (const llvm::User *forward_user : instruction->users()) {
        const auto *load = llvm::dyn_cast<llvm::LoadInst>(forward_user);
        if (load != nullptr && load->getType()->isPointerTy()) {
          return true;
        }
      }
      continue;
    }

    if (const auto *forwarding_global = llvm::dyn_cast<llvm::GlobalVariable>(user)) {
      if (is_local_constant_forwarding_global(*forwarding_global) &&
          has_forwarded_pointer_table_use(*forwarding_global, get_seed, visited)) {
        return true;
      }
      continue;
    }

    if (const auto *forwarding_alias = llvm::dyn_cast<llvm::GlobalAlias>(user)) {
      if (is_local_forwarding_alias(*forwarding_alias) &&
          has_forwarded_pointer_table_use(*forwarding_alias, get_seed, visited)) {
        return true;
      }
      continue;
    }

    if (const auto *constant = llvm::dyn_cast<llvm::Constant>(user)) {
      if (has_forwarded_pointer_table_use(*constant, get_seed, visited)) {
        return true;
      }
    }
  }

  return false;
}

bool is_compare_like_call(const llvm::CallBase &call) {
  const llvm::Function *callee = call.getCalledFunction();
  if (callee == nullptr) {
    return false;
  }

  const llvm::StringRef name = callee->getName();
  return name == "bcmp" || name == "memcmp" || name == "strcmp" ||
         name == "strncmp";
}

classified_string_use classify_instruction_use(llvm::Instruction &instruction,
                                               unsigned operand_index) {
  classified_string_use use;
  use.instruction = &instruction;
  use.operand_index = operand_index;

  if (const auto *call = llvm::dyn_cast<llvm::CallBase>(&instruction)) {
    use.kind = is_compare_like_call(*call) ? string_use_kind::compare_call_operand
                                           : string_use_kind::call_argument;
    use.rewriteable = !call->isInlineAsm();
    use.inline_candidate = use.kind == string_use_kind::compare_call_operand;
    return use;
  }

  if (llvm::isa<llvm::SelectInst>(instruction)) {
    use.kind = string_use_kind::select_operand;
    use.rewriteable = true;
    return use;
  }

  if (llvm::isa<llvm::PHINode>(instruction)) {
    use.kind = string_use_kind::phi_operand;
    use.rewriteable = true;
    return use;
  }

  if (llvm::isa<llvm::ReturnInst>(instruction)) {
    use.kind = string_use_kind::return_operand;
    use.rewriteable = true;
    return use;
  }

  if (llvm::isa<llvm::StoreInst>(instruction)) {
    use.kind = string_use_kind::escaped_address;
    use.rewriteable = true;
    return use;
  }

  if (llvm::isa<llvm::GetElementPtrInst>(instruction) ||
      llvm::isa<llvm::BitCastInst>(instruction) ||
      llvm::isa<llvm::PtrToIntInst>(instruction) ||
      llvm::isa<llvm::IntToPtrInst>(instruction)) {
    use.kind = string_use_kind::address_materialization;
    use.rewriteable = true;
    return use;
  }

  use.kind = string_use_kind::generic_operand;
  use.rewriteable = true;
  return use;
}

void collect_string_users(const llvm::Value &value, const llvm::GlobalVariable &global,
                          protected_function_seed_lookup get_seed,
                          llvm::DenseSet<const llvm::User *> &visited,
                          string_use_summary &summary) {
  for (const llvm::User *user : value.users()) {
    if (!visited.insert(user).second) {
      continue;
    }

    if (is_annotation_user(user)) {
      continue;
    }

    if (const auto *instruction = llvm::dyn_cast<llvm::Instruction>(user)) {
      const llvm::Function *function = instruction->getFunction();
      const bool is_protected =
          function != nullptr && get_seed(function->getName()).has_value();
      if (is_protected) {
        add_unique_function(summary.protected_functions, function);
      } else {
        add_unique_function(summary.unprotected_functions, function);
      }

      bool matched_operand = false;
      for (unsigned operand_index = 0; operand_index < instruction->getNumOperands();
           ++operand_index) {
        if (!operand_references_global(instruction->getOperand(operand_index), global)) {
          continue;
        }

        matched_operand = true;
        classified_string_use classified =
            classify_instruction_use(*const_cast<llvm::Instruction *>(instruction),
                                     operand_index);
        add_use_kind(summary.observed_kinds, classified.kind);

        if (!is_protected) {
          continue;
        }

        if (!classified.rewriteable) {
          summary.has_lazy_blockers = true;
          continue;
        }

        summary.protected_uses.push_back(std::move(classified));
      }

      const bool handled_forwarded_load =
          !matched_operand && value.getType()->isPointerTy() &&
          collect_forwarded_pointer_load_uses(value, *instruction, is_protected,
                                              summary);
      if (is_protected && !matched_operand && !handled_forwarded_load) {
        summary.has_lazy_blockers = true;
      }
      continue;
    }

    if (const auto *forwarding_global = llvm::dyn_cast<llvm::GlobalVariable>(user)) {
      if (is_local_constant_forwarding_global(*forwarding_global)) {
        collect_string_users(*forwarding_global, global, get_seed, visited, summary);
        continue;
      }

      summary.has_non_function_use = true;
      add_use_kind(summary.observed_kinds, string_use_kind::non_function_use);
      continue;
    }

    if (const auto *forwarding_alias = llvm::dyn_cast<llvm::GlobalAlias>(user)) {
      if (is_local_forwarding_alias(*forwarding_alias)) {
        collect_string_users(*forwarding_alias, global, get_seed, visited, summary);
        continue;
      }

      summary.has_non_function_use = true;
      add_use_kind(summary.observed_kinds, string_use_kind::non_function_use);
      continue;
    }

    if (const auto *constant = llvm::dyn_cast<llvm::Constant>(user)) {
      collect_string_users(*constant, global, get_seed, visited, summary);
      continue;
    }

    summary.has_non_function_use = true;
    add_use_kind(summary.observed_kinds, string_use_kind::non_function_use);
  }
}

std::uint64_t hash_string(llvm::StringRef text, std::uint64_t seed) {
  constexpr std::uint64_t kOffsetBasis = 1469598103934665603ULL;
  constexpr std::uint64_t kPrime = 1099511628211ULL;

  std::uint64_t hash = kOffsetBasis ^ seed;
  for (const char byte : text) {
    hash ^= static_cast<unsigned char>(byte);
    hash *= kPrime;
  }

  return hash;
}

std::uint64_t mix_seed(std::uint64_t seed, std::uint64_t salt) {
  seed ^= salt + 0x9e3779b97f4a7c15ULL + (seed << 6) + (seed >> 2);
  return seed;
}

std::uint8_t derive_key_byte_constant(std::uint64_t seed, std::size_t index) {
  const std::uint64_t mixed =
      seed ^ (0x9e3779b97f4a7c15ULL + static_cast<std::uint64_t>(index) * 131ULL);
  std::uint8_t byte =
      static_cast<std::uint8_t>((mixed >> ((index % 8) * 8)) & 0xffU);
  if (byte == 0) {
    byte = static_cast<std::uint8_t>(0xa5U ^ (index * 17U));
  }

  return byte;
}

llvm::Function *get_or_create_cfg_state_placeholder(llvm::Module &module,
                                                    llvm::StringRef name) {
  if (llvm::Function *existing = module.getFunction(name)) {
    return existing;
  }

  llvm::FunctionType *type =
      llvm::FunctionType::get(llvm::Type::getInt32Ty(module.getContext()), false);
  return llvm::Function::Create(type, llvm::GlobalValue::ExternalLinkage, name,
                                module);
}

llvm::Value *create_cfg_state_placeholder_call(llvm::IRBuilder<> &builder,
                                               llvm::Module &module,
                                               bool expected_state) {
  llvm::Function *placeholder = get_or_create_cfg_state_placeholder(
      module, expected_state ? kExpectedCfgStatePlaceholderName
                             : kCfgStatePlaceholderName);
  return builder.CreateCall(placeholder);
}

std::string sanitize_name(llvm::StringRef name) {
  std::string result;
  result.reserve(name.size());
  for (const char ch : name) {
    if ((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
        (ch >= '0' && ch <= '9')) {
      result.push_back(ch);
    } else {
      result.push_back('_');
    }
  }

  return result;
}

std::string make_decoder_name(llvm::StringRef global_name, llvm::StringRef prefix) {
  return (prefix + sanitize_name(global_name)).str();
}

std::size_t get_string_length(const llvm::GlobalVariable &global) {
  const auto *data =
      llvm::cast<llvm::ConstantDataSequential>(global.getInitializer());
  return data->getNumElements();
}

bool is_inline_eligible(const llvm::GlobalVariable &global,
                        const string_use_summary &summary) {
  if (!summary.unprotected_functions.empty() || summary.has_non_function_use ||
      summary.has_lazy_blockers || summary.protected_uses.empty()) {
    return false;
  }

  if (get_string_length(global) > 16) {
    return false;
  }

  return llvm::all_of(summary.protected_uses, [](const classified_string_use &use) {
    return use.inline_candidate;
  });
}

bool should_inline_stack_decode(const llvm::GlobalVariable &global,
                                const string_use_summary &summary) {
  return is_inline_eligible(global, summary) && get_string_length(global) <= 8 &&
         summary.protected_uses.size() <= 2;
}

bool is_high_security_level(protection_level level) {
  return level == protection_level::strong ||
         level == protection_level::strong_vm;
}

classified_string_candidate classify_candidate(llvm::GlobalVariable &global,
                                               protected_function_seed_lookup get_seed,
                                               protected_function_level_lookup get_level,
                                               const string_encoding_options &options,
                                               std::uint64_t module_seed) {
  classified_string_candidate candidate;
  candidate.global = &global;
  candidate.result.global_name = global.getName().str();

  if (!is_string_like_global(global)) {
    candidate.result.detail = "not a cstring global";
    return candidate;
  }

  if (!is_supported_string_global(global, options.min_string_length)) {
    candidate.result.detail = "unsupported string global kind";
    return candidate;
  }

  candidate.seed = hash_string(global.getName(), module_seed);

  llvm::DenseSet<const llvm::User *> visited;
  collect_string_users(global, global, get_seed, visited, candidate.summary);
  llvm::DenseSet<const llvm::User *> forwarded_visited;
  candidate.summary.has_forwarded_pointer_load =
      has_forwarded_pointer_table_use(global, get_seed, forwarded_visited);
  if (candidate.summary.has_forwarded_pointer_load) {
    add_use_kind(candidate.summary.observed_kinds,
                 string_use_kind::forwarded_pointer_load);
  }

  candidate.result.protected_use_count = candidate.summary.protected_uses.size();
  candidate.result.unprotected_use_count = candidate.summary.unprotected_functions.size();
  candidate.result.inline_eligible = is_inline_eligible(global, candidate.summary);
  candidate.result.inline_detail =
      candidate.result.inline_eligible
          ? "short compare-like string eligible for later inline decode"
          : "not selected for inline decode in current phase";
  candidate.result.key_schedule = string_key_schedule_kind::seeded_byte_xor_v0;
  candidate.result.merge_group = -1;

  for (string_use_kind kind : candidate.summary.observed_kinds) {
    candidate.result.use_kinds.push_back(to_string(kind));
  }

  for (const llvm::Function *function : candidate.summary.protected_functions) {
    const std::optional<std::uint64_t> seed = get_seed(function->getName());
    if (seed.has_value()) {
      candidate.seed = mix_seed(candidate.seed, *seed);
      candidate.seed = mix_seed(candidate.seed,
                                hash_string(function->getName(), *seed));
    }

    const std::optional<protection_level> level = get_level(function->getName());
    if (level.has_value() && is_high_security_level(*level)) {
      candidate.has_high_security_use = true;
    }
    if (level.has_value() && *level == protection_level::strong_vm) {
      candidate.has_strong_vm_use = true;
    }
  }

  candidate.seed =
      mix_seed(candidate.seed, static_cast<std::uint64_t>(get_string_length(global)));
  candidate.seed = mix_seed(
      candidate.seed,
      static_cast<std::uint64_t>(candidate.summary.protected_uses.size() + 1));
  if (candidate.seed == 0) {
    candidate.seed = 0xa55aa55aa55aa55aULL;
  }

  return candidate;
}

string_key_schedule_kind select_key_schedule(string_helper_shape shape) {
  switch (shape) {
  case string_helper_shape::lazy_flag_unrolled_v0:
  case string_helper_shape::lazy_flag_reverse_v1:
  case string_helper_shape::lazy_counter_chunked_v2:
  case string_helper_shape::lazy_cached_pointer_v3:
    return string_key_schedule_kind::cfg_path_byte_xor_v2;
  default:
    return string_key_schedule_kind::seeded_byte_xor_v0;
  }
}

string_strategy_plan select_strategy(const classified_string_candidate &candidate,
                                     const string_encoding_options &options) {
  string_strategy_plan plan;
  plan.global = candidate.global;
  plan.seed = candidate.seed;
  plan.result = candidate.result;

  const auto select_inline_stack_decode = [&]() {
    plan.result.applied = true;
    plan.result.mode = string_encoding_mode::inline_stack_decode;
    plan.result.strategy_kind = string_strategy_kind::inline_stack_decode;
    plan.result.helper_shape = string_helper_shape::none;
    plan.result.key_schedule = string_key_schedule_kind::cfg_path_byte_xor_v2;
    plan.result.merge_group = -1;
    plan.result.rewritten_use_count = candidate.summary.protected_uses.size();
    plan.result.detail = std::to_string(plan.result.rewritten_use_count) +
                         " inline stack decode use(s)";
    plan.result.inline_detail =
        "short compare-like string selected for stack decode";
    plan.inline_uses = candidate.summary.protected_uses;
  };

  const auto skip_strong_vm_global_plaintext = [&](llvm::StringRef detail) {
    plan.result.detail = detail.str();
    plan.result.fallback_reason = "strong_vm_no_global_plaintext";
  };

  if (candidate.global == nullptr) {
    return plan;
  }

  if (candidate.summary.protected_functions.empty()) {
    plan.result.detail = "not referenced by protected function";
    return plan;
  }

  if (candidate.summary.has_non_function_use) {
    plan.result.detail = "has non-function use";
    return plan;
  }

  const bool is_strong_vm_candidate = candidate.has_strong_vm_use;
  if (is_strong_vm_candidate &&
      should_inline_stack_decode(*candidate.global, candidate.summary)) {
    select_inline_stack_decode();
    return plan;
  }

  if (!candidate.summary.unprotected_functions.empty()) {
    if (is_strong_vm_candidate &&
        (!options.allow_ctor_fallback ||
         !options.strong_vm_allow_global_plaintext ||
         !options.strong_vm_allow_ctor_fallback)) {
      skip_strong_vm_global_plaintext(
          "strong_vm_no_global_plaintext: shared with unprotected function");
      return plan;
    }

    if (!options.allow_ctor_fallback) {
      plan.result.detail = "shared with unprotected function";
      return plan;
    }

    plan.result.applied = true;
    plan.result.mode = string_encoding_mode::global_ctor;
    plan.result.strategy_kind = string_strategy_kind::helper_global_ctor;
    plan.result.helper_shape = string_helper_shape::ctor_unrolled_v0;
    plan.result.key_schedule = string_key_schedule_kind::seeded_byte_xor_v0;
    plan.result.detail = "ctor fallback due to unprotected use";
    plan.result.fallback_reason = "shared_with_unprotected_function";
    return plan;
  }

  if (candidate.summary.has_forwarded_pointer_load) {
    if (is_strong_vm_candidate &&
        (!options.allow_ctor_fallback ||
         !options.strong_vm_allow_global_plaintext ||
         !options.strong_vm_allow_ctor_fallback)) {
      skip_strong_vm_global_plaintext(
          "strong_vm_no_global_plaintext: forwarded pointer table use");
      return plan;
    }

    plan.result.applied = true;
    plan.result.mode = string_encoding_mode::global_ctor;
    plan.result.strategy_kind = string_strategy_kind::helper_global_ctor;
    plan.result.helper_shape = string_helper_shape::ctor_unrolled_v0;
    plan.result.key_schedule = string_key_schedule_kind::seeded_byte_xor_v0;
    plan.result.detail = "ctor fallback due to forwarded pointer table use";
    plan.result.fallback_reason = "forwarded_pointer_table_use";
    return plan;
  }

  if (should_inline_stack_decode(*candidate.global, candidate.summary)) {
    select_inline_stack_decode();
    return plan;
  }

  const bool lazy_decode_allowed =
      !is_strong_vm_candidate ||
      (options.strong_vm_allow_global_plaintext &&
       options.strong_vm_allow_lazy_decode);
  if (options.prefer_lazy_decode && lazy_decode_allowed &&
      !candidate.summary.has_lazy_blockers &&
      !candidate.summary.protected_uses.empty()) {
    plan.result.applied = true;
    plan.result.mode = string_encoding_mode::lazy_decode;
    plan.result.strategy_kind = string_strategy_kind::helper_lazy_decode;
    plan.result.helper_shape = string_helper_shape::lazy_flag_unrolled_v0;
    plan.result.key_schedule = select_key_schedule(plan.result.helper_shape);
    plan.isolate_lazy_helper = candidate.has_high_security_use;
    plan.result.merge_group =
        plan.isolate_lazy_helper ? -1
                                 : merge_group_for_shape(plan.result.helper_shape);
    plan.result.rewritten_use_count = candidate.summary.protected_uses.size();
    plan.result.detail = std::to_string(plan.result.rewritten_use_count) +
                         (plan.isolate_lazy_helper ? " isolated lazy use(s)"
                                                   : " lazy use(s)");
    plan.lazy_uses = candidate.summary.protected_uses;
    return plan;
  }

  const bool ctor_fallback_allowed =
      options.allow_ctor_fallback &&
      (!is_strong_vm_candidate ||
       (options.strong_vm_allow_global_plaintext &&
        options.strong_vm_allow_ctor_fallback));
  if (!ctor_fallback_allowed) {
    if (is_strong_vm_candidate) {
      skip_strong_vm_global_plaintext(
          candidate.summary.has_lazy_blockers
              ? "strong_vm_no_global_plaintext: unsupported lazy use pattern"
              : "strong_vm_no_global_plaintext: no local string strategy");
      return plan;
    }

    plan.result.detail = candidate.summary.has_lazy_blockers
                             ? "unsupported lazy use pattern"
                             : "no supported lazy uses";
    return plan;
  }

  plan.result.applied = true;
  plan.result.mode = string_encoding_mode::global_ctor;
  plan.result.strategy_kind = string_strategy_kind::helper_global_ctor;
  plan.result.helper_shape = string_helper_shape::ctor_unrolled_v0;
  plan.result.key_schedule = string_key_schedule_kind::seeded_byte_xor_v0;
  plan.result.detail = candidate.summary.has_lazy_blockers
                           ? "ctor fallback due to unsupported lazy use"
                           : "ctor fallback";
  plan.result.fallback_reason = candidate.summary.has_lazy_blockers
                                    ? "unsupported_lazy_use_pattern"
                                    : "lazy_decode_not_selected";
  return plan;
}

llvm::SmallVector<llvm::GlobalVariable *, 16>
discover_string_candidates(llvm::Module &module);

std::vector<classified_string_candidate>
classify_candidates(llvm::Module &module, protected_function_seed_lookup get_seed,
                    protected_function_level_lookup get_level,
                    const string_encoding_options &options,
                    std::uint64_t module_seed) {
  std::vector<classified_string_candidate> candidates;
  const llvm::SmallVector<llvm::GlobalVariable *, 16> globals =
      discover_string_candidates(module);
  candidates.reserve(globals.size());
  for (llvm::GlobalVariable *global : globals) {
    if (global != nullptr) {
      candidates.push_back(
          classify_candidate(*global, get_seed, get_level, options, module_seed));
    }
  }

  return candidates;
}

std::vector<string_strategy_plan>
select_plans(const std::vector<classified_string_candidate> &candidates,
             const string_encoding_options &options) {
  std::vector<string_strategy_plan> plans;
  plans.reserve(candidates.size());
  for (const classified_string_candidate &candidate : candidates) {
    plans.push_back(select_strategy(candidate, options));
  }

  return plans;
}

void diversify_lazy_helper_shapes(std::vector<string_strategy_plan> &plans,
                                  std::uint64_t module_seed) {
  constexpr string_helper_shape kShapes[] = {
      string_helper_shape::lazy_flag_unrolled_v0,
      string_helper_shape::lazy_flag_reverse_v1,
      string_helper_shape::lazy_cached_pointer_v3,
  };
  constexpr string_helper_shape kHighSecurityShapes[] = {
      string_helper_shape::lazy_flag_unrolled_v0,
      string_helper_shape::lazy_flag_reverse_v1,
  };

  std::vector<string_strategy_plan *> lazy_plans;
  lazy_plans.reserve(plans.size());
  for (string_strategy_plan &plan : plans) {
    if (plan.result.strategy_kind == string_strategy_kind::helper_lazy_decode &&
        plan.result.applied) {
      lazy_plans.push_back(&plan);
    }
  }

  if (lazy_plans.empty()) {
    return;
  }

  const std::size_t start_index = module_seed % std::size(kShapes);
  for (std::size_t index = 0; index < lazy_plans.size(); ++index) {
    string_strategy_plan &plan = *lazy_plans[index];
    if (plan.isolate_lazy_helper) {
      const std::size_t shape_index =
          (index + (plan.seed % std::size(kHighSecurityShapes))) %
          std::size(kHighSecurityShapes);
      plan.result.helper_shape = kHighSecurityShapes[shape_index];
    } else {
      const std::size_t shape_index =
          (start_index + index + (plan.seed % std::size(kShapes))) %
          std::size(kShapes);
      plan.result.helper_shape = kShapes[shape_index];
    }
    plan.result.key_schedule = select_key_schedule(plan.result.helper_shape);
    plan.result.merge_group =
        plan.isolate_lazy_helper ? -1
                                 : merge_group_for_shape(plan.result.helper_shape);
  }
}

void apply_string_encoding_limit(std::vector<string_strategy_plan> &plans,
                                 const string_encoding_options &options) {
  std::size_t encoded_count = 0;
  for (string_strategy_plan &plan : plans) {
    if (!plan.result.applied) {
      continue;
    }

    if (encoded_count >= options.max_strings_per_module) {
      plan.result.mode = string_encoding_mode::skipped;
      plan.result.strategy_kind = string_strategy_kind::none;
      plan.result.helper_shape = string_helper_shape::none;
      plan.result.key_schedule = string_key_schedule_kind::seeded_byte_xor_v0;
      plan.result.merge_group = -1;
      plan.result.descriptor_index = -1;
      plan.result.applied = false;
      plan.result.rewritten_use_count = 0;
      plan.result.detail = "max_strings_per_module reached";
      plan.lazy_uses.clear();
      plan.inline_uses.clear();
      continue;
    }

    ++encoded_count;
  }
}

std::uint64_t descriptor_order_key(const string_strategy_plan &plan,
                                   std::uint64_t module_seed) {
  const std::uint64_t merge_group =
      static_cast<std::uint64_t>(plan.result.merge_group + 1);
  return mix_seed(mix_seed(module_seed, merge_group), plan.seed);
}

void assign_lazy_descriptor_indices(std::vector<string_strategy_plan> &plans,
                                    std::uint64_t module_seed) {
  llvm::DenseMap<int, std::vector<std::size_t>> groups;
  for (std::size_t index = 0; index < plans.size(); ++index) {
    string_strategy_plan &plan = plans[index];
    if (plan.result.mode != string_encoding_mode::lazy_decode ||
        !plan.result.applied || plan.result.merge_group < 0) {
      plan.result.descriptor_index = -1;
      continue;
    }

    groups[plan.result.merge_group].push_back(index);
  }

  for (auto &group_entry : groups) {
    auto &indices = group_entry.second;
    std::sort(indices.begin(), indices.end(),
              [&](std::size_t lhs, std::size_t rhs) {
                const std::uint64_t lhs_key =
                    descriptor_order_key(plans[lhs], module_seed);
                const std::uint64_t rhs_key =
                    descriptor_order_key(plans[rhs], module_seed);
                if (lhs_key != rhs_key) {
                  return lhs_key < rhs_key;
                }

                if (plans[lhs].seed != plans[rhs].seed) {
                  return plans[lhs].seed < plans[rhs].seed;
                }

                return plans[lhs].result.global_name <
                       plans[rhs].result.global_name;
              });

    for (std::size_t table_index = 0; table_index < indices.size(); ++table_index) {
      plans[indices[table_index]].result.descriptor_index =
          static_cast<int>(table_index);
    }
  }
}

void encode_global_initializer(llvm::GlobalVariable &global, std::uint64_t seed) {
  const auto *data =
      llvm::cast<llvm::ConstantDataSequential>(global.getInitializer());

  llvm::SmallVector<std::uint8_t, 32> encoded_bytes;
  encoded_bytes.reserve(data->getNumElements());
  for (std::size_t index = 0; index < data->getNumElements(); ++index) {
    const std::uint8_t byte =
        static_cast<std::uint8_t>(data->getElementAsInteger(index));
    encoded_bytes.push_back(byte ^ derive_key_byte_constant(seed, index));
  }

  global.setConstant(false);
  global.setInitializer(
      llvm::ConstantDataArray::get(global.getContext(), encoded_bytes));
}

llvm::Value *create_string_byte_pointer(llvm::IRBuilder<> &builder,
                                        llvm::GlobalVariable &global,
                                        llvm::Value *index_value) {
  llvm::LLVMContext &context = builder.getContext();
  llvm::Type *i64_type = llvm::Type::getInt64Ty(context);
  return builder.CreateInBoundsGEP(
      global.getValueType(), &global,
      {llvm::ConstantInt::get(i64_type, 0),
       builder.CreateZExtOrTrunc(index_value, i64_type)});
}

void emit_unrolled_decode(llvm::IRBuilder<> &builder, llvm::GlobalVariable &global,
                          std::uint64_t seed, bool reverse) {
  llvm::Type *i8_type = llvm::Type::getInt8Ty(builder.getContext());
  const std::size_t length = get_string_length(global);

  for (std::size_t iteration = 0; iteration < length; ++iteration) {
    const std::size_t index = reverse ? (length - 1 - iteration) : iteration;
    llvm::Value *pointer = create_string_byte_pointer(
        builder, global, llvm::ConstantInt::get(llvm::Type::getInt64Ty(builder.getContext()), index));
    llvm::Value *loaded = builder.CreateLoad(i8_type, pointer);
    llvm::Value *decoded = builder.CreateXor(
        loaded,
        llvm::ConstantInt::get(i8_type, derive_key_byte_constant(seed, index)));
    builder.CreateStore(decoded, pointer);
  }
}

llvm::Function *create_ctor_decoder(llvm::Module &module, llvm::GlobalVariable &global,
                                    std::uint64_t seed) {
  llvm::LLVMContext &context = module.getContext();
  llvm::FunctionType *type =
      llvm::FunctionType::get(llvm::Type::getVoidTy(context), false);
  llvm::Function *decoder = llvm::Function::Create(
      type, llvm::GlobalValue::InternalLinkage,
      make_decoder_name(global.getName(), "__obf_decode_"), module);

  llvm::BasicBlock *entry = llvm::BasicBlock::Create(context, "entry", decoder);
  llvm::IRBuilder<> builder(entry);
  emit_unrolled_decode(builder, global, seed, false);
  builder.CreateRetVoid();
  return decoder;
}
llvm::Value *create_runtime_byte_pointer(llvm::IRBuilder<> &builder,
                                         llvm::Value *base_pointer,
                                         llvm::Value *index_value) {
  llvm::Type *i8_type = llvm::Type::getInt8Ty(builder.getContext());
  llvm::Type *i64_type = llvm::Type::getInt64Ty(builder.getContext());
  return builder.CreateInBoundsGEP(i8_type, base_pointer,
                                   builder.CreateZExtOrTrunc(index_value, i64_type));
}

llvm::Value *emit_seeded_key_byte_runtime(llvm::IRBuilder<> &builder,
                                          llvm::Value *seed_value,
                                          llvm::Value *index_value) {
  llvm::LLVMContext &context = builder.getContext();
  llvm::Type *i64_type = llvm::Type::getInt64Ty(context);
  llvm::Type *i8_type = llvm::Type::getInt8Ty(context);

  llvm::Value *index64 = builder.CreateZExtOrTrunc(index_value, i64_type);
  llvm::Value *mixed = builder.CreateXor(
      seed_value,
      builder.CreateAdd(llvm::ConstantInt::get(i64_type, 0x9e3779b97f4a7c15ULL),
                        builder.CreateMul(index64, llvm::ConstantInt::get(i64_type, 131))));
  llvm::Value *shift = builder.CreateMul(
      builder.CreateAnd(index64, llvm::ConstantInt::get(i64_type, 7)),
      llvm::ConstantInt::get(i64_type, 8));
  llvm::Value *shifted = builder.CreateLShr(mixed, shift);
  llvm::Value *key_byte = builder.CreateTrunc(shifted, i8_type);
  llvm::Value *fallback = builder.CreateTrunc(
      builder.CreateXor(llvm::ConstantInt::get(i64_type, 0xa5),
                        builder.CreateMul(index64, llvm::ConstantInt::get(i64_type, 17))),
      i8_type);
  return builder.CreateSelect(
      builder.CreateICmpEQ(key_byte, llvm::ConstantInt::get(i8_type, 0)), fallback,
      key_byte);
}

llvm::Value *emit_cfg_state_mask_byte_runtime(llvm::IRBuilder<> &builder,
                                              llvm::Value *cfg_state_value,
                                              llvm::Value *expected_state_value,
                                              llvm::Value *index_value) {
  llvm::LLVMContext &context = builder.getContext();
  llvm::Type *i8_type = llvm::Type::getInt8Ty(context);
  llvm::Type *i32_type = llvm::Type::getInt32Ty(context);
  llvm::Type *i64_type = llvm::Type::getInt64Ty(context);

  llvm::Value *cfg_state32 = builder.CreateZExtOrTrunc(cfg_state_value, i32_type);
  llvm::Value *expected_state32 =
      builder.CreateZExtOrTrunc(expected_state_value, i32_type);
  llvm::Value *state_delta =
      builder.CreateXor(cfg_state32, expected_state32, "obf.str.state.delta");
  llvm::Value *delta_is_zero = builder.CreateICmpEQ(
      state_delta, llvm::ConstantInt::get(i32_type, 0), "obf.str.state.match");

  llvm::Value *delta64 = builder.CreateZExt(state_delta, i64_type);
  llvm::Value *index64 = builder.CreateZExtOrTrunc(index_value, i64_type);
  llvm::Value *mixed = builder.CreateXor(
      delta64,
      builder.CreateAdd(llvm::ConstantInt::get(i64_type, 0x7f4a7c159e3779b9ULL),
                        builder.CreateMul(index64,
                                          llvm::ConstantInt::get(i64_type, 257))),
      "obf.str.state.mix");
  llvm::Value *shift = builder.CreateMul(
      builder.CreateAnd(index64, llvm::ConstantInt::get(i64_type, 7)),
      llvm::ConstantInt::get(i64_type, 8));
  llvm::Value *shifted = builder.CreateLShr(mixed, shift, "obf.str.state.shift");
  llvm::Value *raw_mask = builder.CreateTrunc(shifted, i8_type, "obf.str.state.raw");
  llvm::Value *forced_mask = builder.CreateOr(
      raw_mask, llvm::ConstantInt::get(i8_type, 1), "obf.str.state.mask");
  return builder.CreateSelect(delta_is_zero, llvm::ConstantInt::get(i8_type, 0),
                              forced_mask, "obf.str.state.key");
}

llvm::Value *emit_path_key_byte_runtime(llvm::IRBuilder<> &builder,
                                        llvm::Value *seed_value,
                                        llvm::Value *index_value,
                                        llvm::Value *cfg_state_value,
                                        llvm::Value *expected_state_value) {
  llvm::Value *base_key =
      emit_seeded_key_byte_runtime(builder, seed_value, index_value);
  llvm::Value *state_key = emit_cfg_state_mask_byte_runtime(
      builder, cfg_state_value, expected_state_value, index_value);
  return builder.CreateXor(base_key, state_key, "obf.str.key");
}

descriptor_layout get_descriptor_layout(string_helper_shape shape) {
  switch (shape) {
  case string_helper_shape::lazy_flag_unrolled_v0:
    return {.base_index = 2, .state_index = 0, .length_index = 1, .seed_index = 3};
  case string_helper_shape::lazy_flag_reverse_v1:
    return {.base_index = 1, .state_index = 2, .length_index = 3, .seed_index = 0};
  case string_helper_shape::lazy_cached_pointer_v3:
    return {.base_index = 3, .state_index = 1, .length_index = 0, .seed_index = 2};
  default:
    return {};
  }
}

llvm::StructType *get_string_descriptor_type(llvm::LLVMContext &context,
                                             string_helper_shape shape) {
  llvm::Type *ptr_type = llvm::PointerType::getUnqual(context);
  llvm::Type *i64_type = llvm::Type::getInt64Ty(context);
  switch (shape) {
  case string_helper_shape::lazy_flag_unrolled_v0:
    return llvm::StructType::get(ptr_type, i64_type, ptr_type, i64_type);
  case string_helper_shape::lazy_flag_reverse_v1:
    return llvm::StructType::get(i64_type, ptr_type, ptr_type, i64_type);
  case string_helper_shape::lazy_cached_pointer_v3:
    return llvm::StructType::get(i64_type, ptr_type, i64_type, ptr_type);
  default:
    return llvm::StructType::get(ptr_type, ptr_type, i64_type, i64_type);
  }
}

llvm::Value *load_descriptor_field(llvm::IRBuilder<> &builder, llvm::Value *descriptor,
                                   string_helper_shape shape, unsigned field_index,
                                   llvm::Type *field_type) {
  llvm::StructType *descriptor_type =
      get_string_descriptor_type(builder.getContext(), shape);
  llvm::Value *field_ptr = builder.CreateInBoundsGEP(
      descriptor_type, descriptor,
      {llvm::ConstantInt::get(llvm::Type::getInt64Ty(builder.getContext()), 0),
       llvm::ConstantInt::get(llvm::Type::getInt32Ty(builder.getContext()), field_index)});
  return builder.CreateLoad(field_type, field_ptr);
}

llvm::Constant *create_descriptor_initializer(llvm::LLVMContext &context,
                                              const string_strategy_plan &plan,
                                              llvm::GlobalVariable &state_global) {
  llvm::StructType *descriptor_type =
      get_string_descriptor_type(context, plan.result.helper_shape);
  const descriptor_layout layout = get_descriptor_layout(plan.result.helper_shape);

  llvm::SmallVector<llvm::Constant *, 4> fields(4, nullptr);
  fields[layout.base_index] = llvm::ConstantExpr::getPointerBitCastOrAddrSpaceCast(
      plan.global, llvm::PointerType::getUnqual(context));
  fields[layout.state_index] = llvm::ConstantExpr::getPointerBitCastOrAddrSpaceCast(
      &state_global, llvm::PointerType::getUnqual(context));
  fields[layout.length_index] = llvm::ConstantInt::get(
      llvm::Type::getInt64Ty(context), get_string_length(*plan.global));
  fields[layout.seed_index] =
      llvm::ConstantInt::get(llvm::Type::getInt64Ty(context), plan.seed);

  return llvm::ConstantStruct::get(descriptor_type, fields);
}

llvm::Constant *create_descriptor_table_ptr(llvm::GlobalVariable &table,
                                            std::size_t index) {
  llvm::LLVMContext &context = table.getContext();
  llvm::Type *i64_type = llvm::Type::getInt64Ty(context);
  llvm::ArrayType *array_type = llvm::cast<llvm::ArrayType>(table.getValueType());
  llvm::Constant *indices[] = {llvm::ConstantInt::get(i64_type, 0),
                               llvm::ConstantInt::get(i64_type, index)};
  return llvm::ConstantExpr::getGetElementPtr(
      array_type, &table, indices);
}

llvm::Function *create_flag_family_helper(llvm::Module &module,
                                          llvm::StringRef name,
                                          bool reverse) {
  if (llvm::Function *existing = module.getFunction(name)) {
    return existing;
  }

  llvm::LLVMContext &context = module.getContext();
  llvm::Type *ptr_type = llvm::PointerType::getUnqual(context);
  llvm::Type *i1_type = llvm::Type::getInt1Ty(context);
  llvm::Type *i32_type = llvm::Type::getInt32Ty(context);
  llvm::Type *i64_type = llvm::Type::getInt64Ty(context);
  const string_helper_shape shape = reverse ? string_helper_shape::lazy_flag_reverse_v1
                                            : string_helper_shape::lazy_flag_unrolled_v0;
  const descriptor_layout layout = get_descriptor_layout(shape);
  llvm::FunctionType *type =
      llvm::FunctionType::get(ptr_type, {ptr_type, i32_type, i32_type}, false);
  llvm::Function *decoder = llvm::Function::Create(
      type, llvm::GlobalValue::InternalLinkage, name, module);

  auto arg_it = decoder->arg_begin();
  llvm::Argument *descriptor = &*arg_it++;
  descriptor->setName("desc");
  llvm::Argument *cfg_state = &*arg_it++;
  cfg_state->setName("cfg_state");
  llvm::Argument *expected_state = &*arg_it++;
  expected_state->setName("expected_state");

  llvm::BasicBlock *entry = llvm::BasicBlock::Create(context, "entry", decoder);
  llvm::BasicBlock *decode = llvm::BasicBlock::Create(context, "decode", decoder);
  llvm::BasicBlock *loop = llvm::BasicBlock::Create(context, "loop", decoder);
  llvm::BasicBlock *body = llvm::BasicBlock::Create(context, "body", decoder);
  llvm::BasicBlock *finalize = llvm::BasicBlock::Create(context, "finalize", decoder);
  llvm::BasicBlock *done = llvm::BasicBlock::Create(context, "done", decoder);

  llvm::IRBuilder<> builder(entry);
  llvm::Value *state_raw =
      load_descriptor_field(builder, descriptor, shape, layout.state_index, ptr_type);
  llvm::Value *state_ptr = builder.CreatePointerCast(
      state_raw, llvm::PointerType::getUnqual(context));
  llvm::Value *already_decoded = builder.CreateLoad(i1_type, state_ptr);
  builder.CreateCondBr(already_decoded, done, decode);

  builder.SetInsertPoint(decode);
  llvm::Value *base_ptr =
      load_descriptor_field(builder, descriptor, shape, layout.base_index, ptr_type);
  llvm::Value *length =
      load_descriptor_field(builder, descriptor, shape, layout.length_index, i64_type);
  llvm::Value *seed =
      load_descriptor_field(builder, descriptor, shape, layout.seed_index, i64_type);
  builder.CreateBr(loop);

  builder.SetInsertPoint(loop);
  llvm::PHINode *index = builder.CreatePHI(i64_type, 2, "idx");
  index->addIncoming(llvm::ConstantInt::get(i64_type, 0), decode);
  llvm::Value *in_bounds = builder.CreateICmpULT(index, length);
  builder.CreateCondBr(in_bounds, body, finalize);

  builder.SetInsertPoint(body);
  llvm::Value *effective_index = index;
  if (reverse) {
    effective_index = builder.CreateSub(
        builder.CreateSub(length, llvm::ConstantInt::get(i64_type, 1)), index);
  }
  llvm::Value *pointer = create_runtime_byte_pointer(builder, base_ptr, effective_index);
  llvm::Value *loaded = builder.CreateLoad(llvm::Type::getInt8Ty(context), pointer);
  llvm::Value *decoded = builder.CreateXor(
      loaded, emit_path_key_byte_runtime(builder, seed, effective_index, cfg_state,
                                         expected_state));
  builder.CreateStore(decoded, pointer);
  llvm::Value *next_index =
      builder.CreateAdd(index, llvm::ConstantInt::get(i64_type, 1));
  index->addIncoming(next_index, body);
  builder.CreateBr(loop);

  builder.SetInsertPoint(finalize);
  builder.CreateStore(llvm::ConstantInt::getTrue(context), state_ptr);
  builder.CreateBr(done);

  builder.SetInsertPoint(done);
  llvm::Value *result_ptr =
      load_descriptor_field(builder, descriptor, shape, layout.base_index, ptr_type);
  builder.CreateRet(result_ptr);
  return decoder;
}

llvm::Function *get_or_create_flag_family_helper(llvm::Module &module,
                                                 bool reverse) {
  const llvm::StringRef name =
      reverse ? "__obf_family_flag_reverse_v1" : "__obf_family_flag_v0";
  return create_flag_family_helper(module, name, reverse);
}

llvm::Function *create_cached_family_helper(llvm::Module &module,
                                            llvm::StringRef name) {
  if (llvm::Function *existing = module.getFunction(name)) {
    return existing;
  }

  llvm::LLVMContext &context = module.getContext();
  llvm::Type *ptr_type = llvm::PointerType::getUnqual(context);
  llvm::Type *i32_type = llvm::Type::getInt32Ty(context);
  llvm::Type *i64_type = llvm::Type::getInt64Ty(context);
  constexpr string_helper_shape shape = string_helper_shape::lazy_cached_pointer_v3;
  const descriptor_layout layout = get_descriptor_layout(shape);
  llvm::FunctionType *type =
      llvm::FunctionType::get(ptr_type, {ptr_type, i32_type, i32_type}, false);
  llvm::Function *decoder = llvm::Function::Create(
      type, llvm::GlobalValue::InternalLinkage, name, module);

  auto arg_it = decoder->arg_begin();
  llvm::Argument *descriptor = &*arg_it++;
  descriptor->setName("desc");
  llvm::Argument *cfg_state = &*arg_it++;
  cfg_state->setName("cfg_state");
  llvm::Argument *expected_state = &*arg_it++;
  expected_state->setName("expected_state");

  llvm::BasicBlock *entry = llvm::BasicBlock::Create(context, "entry", decoder);
  llvm::BasicBlock *decode = llvm::BasicBlock::Create(context, "decode", decoder);
  llvm::BasicBlock *loop = llvm::BasicBlock::Create(context, "loop", decoder);
  llvm::BasicBlock *body = llvm::BasicBlock::Create(context, "body", decoder);
  llvm::BasicBlock *finalize = llvm::BasicBlock::Create(context, "finalize", decoder);
  llvm::BasicBlock *done = llvm::BasicBlock::Create(context, "done", decoder);

  llvm::IRBuilder<> builder(entry);
  llvm::Value *cache_raw =
      load_descriptor_field(builder, descriptor, shape, layout.state_index, ptr_type);
  llvm::Value *cache_ptr = builder.CreatePointerCast(
      cache_raw, llvm::PointerType::getUnqual(context));
  llvm::Value *cached = builder.CreateLoad(ptr_type, cache_ptr);
  llvm::Value *is_cached = builder.CreateICmpNE(
      cached, llvm::ConstantPointerNull::get(cast<llvm::PointerType>(ptr_type)));
  builder.CreateCondBr(is_cached, done, decode);

  builder.SetInsertPoint(decode);
  llvm::Value *base_ptr =
      load_descriptor_field(builder, descriptor, shape, layout.base_index, ptr_type);
  llvm::Value *length =
      load_descriptor_field(builder, descriptor, shape, layout.length_index, i64_type);
  llvm::Value *seed =
      load_descriptor_field(builder, descriptor, shape, layout.seed_index, i64_type);
  builder.CreateBr(loop);

  builder.SetInsertPoint(loop);
  llvm::PHINode *index = builder.CreatePHI(i64_type, 2, "idx");
  index->addIncoming(llvm::ConstantInt::get(i64_type, 0), decode);
  llvm::Value *in_bounds = builder.CreateICmpULT(index, length);
  builder.CreateCondBr(in_bounds, body, finalize);

  builder.SetInsertPoint(body);
  llvm::Value *pointer = create_runtime_byte_pointer(builder, base_ptr, index);
  llvm::Value *loaded = builder.CreateLoad(llvm::Type::getInt8Ty(context), pointer);
  llvm::Value *decoded = builder.CreateXor(
      loaded,
      emit_path_key_byte_runtime(builder, seed, index, cfg_state, expected_state));
  builder.CreateStore(decoded, pointer);
  llvm::Value *next_index =
      builder.CreateAdd(index, llvm::ConstantInt::get(i64_type, 1));
  index->addIncoming(next_index, body);
  builder.CreateBr(loop);

  builder.SetInsertPoint(finalize);
  builder.CreateStore(base_ptr, cache_ptr);
  builder.CreateBr(done);

  builder.SetInsertPoint(done);
  llvm::PHINode *result = builder.CreatePHI(ptr_type, 2);
  result->addIncoming(cached, entry);
  result->addIncoming(base_ptr, finalize);
  builder.CreateRet(result);
  return decoder;
}

llvm::Function *get_or_create_cached_family_helper(llvm::Module &module) {
  constexpr llvm::StringRef name = "__obf_family_cached_v3";
  return create_cached_family_helper(module, name);
}

llvm::GlobalVariable *create_lazy_state_global(llvm::Module &module,
                                               const string_strategy_plan &plan) {
  llvm::LLVMContext &context = module.getContext();
  if (plan.result.helper_shape == string_helper_shape::lazy_cached_pointer_v3) {
    llvm::Type *ptr_type = llvm::PointerType::getUnqual(context);
    return new llvm::GlobalVariable(
        module, ptr_type, false, llvm::GlobalValue::InternalLinkage,
        llvm::ConstantPointerNull::get(cast<llvm::PointerType>(ptr_type)),
        make_decoder_name(plan.global->getName(), "__obf_cached_"));
  }

  return new llvm::GlobalVariable(
      module, llvm::Type::getInt1Ty(context), false,
      llvm::GlobalValue::InternalLinkage, llvm::ConstantInt::getFalse(context),
      make_decoder_name(plan.global->getName(), "__obf_decoded_"));
}

llvm::Function *get_or_create_lazy_family_helper(llvm::Module &module,
                                                 string_helper_shape shape) {
  switch (shape) {
  case string_helper_shape::lazy_flag_reverse_v1:
    return get_or_create_flag_family_helper(module, true);
  case string_helper_shape::lazy_cached_pointer_v3:
    return get_or_create_cached_family_helper(module);
  case string_helper_shape::lazy_flag_unrolled_v0:
  default:
    return get_or_create_flag_family_helper(module, false);
  }
}

llvm::Function *create_isolated_lazy_helper(llvm::Module &module,
                                            const string_strategy_plan &plan) {
  const std::string helper_name =
      make_decoder_name(plan.global->getName(), "__obf_lazy_") +
      "_" + to_string(plan.result.helper_shape);
  switch (plan.result.helper_shape) {
  case string_helper_shape::lazy_flag_reverse_v1:
    return create_flag_family_helper(module, helper_name, true);
  case string_helper_shape::lazy_cached_pointer_v3:
    return create_cached_family_helper(module, helper_name);
  case string_helper_shape::lazy_flag_unrolled_v0:
  default:
    return create_flag_family_helper(module, helper_name, false);
  }
}

void rewrite_lazy_uses(llvm::Function &family_helper, llvm::Constant *descriptor_ptr,
                       llvm::ArrayRef<classified_string_use> uses) {
  llvm::Module *module = family_helper.getParent();
  if (module == nullptr) {
    return;
  }

  for (const classified_string_use &use : uses) {
    if (use.instruction == nullptr) {
      continue;
    }

    if (auto *phi = llvm::dyn_cast<llvm::PHINode>(use.instruction)) {
      llvm::BasicBlock *incoming_block = phi->getIncomingBlock(use.operand_index);
      if (incoming_block == nullptr) {
        continue;
      }

      llvm::Instruction *insert_before = incoming_block->getTerminator();
      if (insert_before == nullptr) {
        continue;
      }

      llvm::IRBuilder<> builder(insert_before);
      llvm::Value *cfg_state =
          create_cfg_state_placeholder_call(builder, *module, false);
      llvm::Value *expected_state =
          create_cfg_state_placeholder_call(builder, *module, true);
      llvm::CallInst *decoded_ptr = builder.CreateCall(
          &family_helper, {descriptor_ptr, cfg_state, expected_state});
      phi->setIncomingValue(use.operand_index, decoded_ptr);
      continue;
    }

    llvm::IRBuilder<> builder(use.instruction);
    llvm::Value *cfg_state = create_cfg_state_placeholder_call(builder, *module, false);
    llvm::Value *expected_state =
        create_cfg_state_placeholder_call(builder, *module, true);
    llvm::CallInst *decoded_ptr =
        builder.CreateCall(&family_helper, {descriptor_ptr, cfg_state, expected_state});
    use.instruction->setOperand(use.operand_index, decoded_ptr);
  }
}

llvm::AllocaInst *create_entry_buffer(llvm::Function &function, llvm::Type *buffer_type,
                                      llvm::StringRef name) {
  llvm::BasicBlock &entry = function.getEntryBlock();
  llvm::Instruction *insert_before = &*entry.getFirstInsertionPt();
  llvm::IRBuilder<> builder(insert_before);
  return builder.CreateAlloca(buffer_type, nullptr, name);
}

void emit_stack_decode_stores(llvm::IRBuilder<> &builder, llvm::GlobalVariable &global,
                              std::uint64_t seed, llvm::AllocaInst &buffer,
                              llvm::Value *cfg_state_value,
                              llvm::Value *expected_state_value) {
  llvm::LLVMContext &context = builder.getContext();
  llvm::Type *i64_type = llvm::Type::getInt64Ty(context);
  llvm::Type *i8_type = llvm::Type::getInt8Ty(context);
  const auto *array_type = llvm::cast<llvm::ArrayType>(buffer.getAllocatedType());
  for (std::size_t index = 0; index < array_type->getNumElements(); ++index) {
    llvm::Value *src = create_string_byte_pointer(
        builder, global, llvm::ConstantInt::get(i64_type, index));
    llvm::Value *dst = builder.CreateInBoundsGEP(
        buffer.getAllocatedType(), &buffer,
        {llvm::ConstantInt::get(i64_type, 0), llvm::ConstantInt::get(i64_type, index)});
    llvm::Value *loaded = builder.CreateLoad(i8_type, src);
    llvm::Value *decoded = builder.CreateXor(
        loaded,
        emit_path_key_byte_runtime(builder,
                                   llvm::ConstantInt::get(i64_type, seed),
                                   llvm::ConstantInt::get(i64_type, index),
                                   cfg_state_value, expected_state_value));
    builder.CreateStore(decoded, dst);
  }
}

void emit_stack_zero_stores(llvm::IRBuilder<> &builder, llvm::AllocaInst &buffer) {
  llvm::LLVMContext &context = builder.getContext();
  llvm::Type *i64_type = llvm::Type::getInt64Ty(context);
  llvm::Type *i8_type = llvm::Type::getInt8Ty(context);
  const auto *array_type = llvm::cast<llvm::ArrayType>(buffer.getAllocatedType());
  for (std::size_t index = 0; index < array_type->getNumElements(); ++index) {
    llvm::Value *dst = builder.CreateInBoundsGEP(
        buffer.getAllocatedType(), &buffer,
        {llvm::ConstantInt::get(i64_type, 0), llvm::ConstantInt::get(i64_type, index)});
    builder.CreateStore(llvm::ConstantInt::get(i8_type, 0), dst);
  }
}

void rewrite_inline_stack_uses(llvm::GlobalVariable &global, std::uint64_t seed,
                               llvm::ArrayRef<classified_string_use> uses) {
  if (uses.empty()) {
    return;
  }

  llvm::LLVMContext &context = global.getContext();
  llvm::Type *i64_type = llvm::Type::getInt64Ty(context);
  llvm::ArrayType *buffer_type =
      llvm::ArrayType::get(llvm::Type::getInt8Ty(context), get_string_length(global));

  for (const classified_string_use &use : uses) {
    if (use.instruction == nullptr) {
      continue;
    }

    llvm::Function *function = use.instruction->getFunction();
    if (function == nullptr) {
      continue;
    }

    llvm::AllocaInst *buffer =
        create_entry_buffer(*function, buffer_type, "obf.inline.str");
    llvm::IRBuilder<> before_builder(use.instruction);
    llvm::Module *module = function->getParent();
    if (module == nullptr) {
      continue;
    }

    llvm::Value *cfg_state =
        create_cfg_state_placeholder_call(before_builder, *module, false);
    llvm::Value *expected_state =
        create_cfg_state_placeholder_call(before_builder, *module, true);
    emit_stack_decode_stores(before_builder, global, seed, *buffer, cfg_state,
                             expected_state);

    llvm::Value *decoded_ptr = before_builder.CreateInBoundsGEP(
        buffer_type, buffer,
        {llvm::ConstantInt::get(i64_type, 0), llvm::ConstantInt::get(i64_type, 0)});
    use.instruction->setOperand(use.operand_index, decoded_ptr);

    if (llvm::Instruction *next = use.instruction->getNextNode()) {
      llvm::IRBuilder<> after_builder(next);
      emit_stack_zero_stores(after_builder, *buffer);
    }
  }
}

llvm::SmallVector<llvm::GlobalVariable *, 16>
discover_string_candidates(llvm::Module &module) {
  llvm::SmallVector<llvm::GlobalVariable *, 16> globals;
  for (llvm::GlobalVariable &global : module.globals()) {
    if (is_string_like_global(global)) {
      globals.push_back(&global);
    }
  }

  return globals;
}

llvm::GlobalVariable *create_standalone_descriptor_global(
    llvm::Module &module, const string_strategy_plan &plan,
    llvm::GlobalVariable &state_global) {
  llvm::StructType *descriptor_type =
      get_string_descriptor_type(module.getContext(), plan.result.helper_shape);
  return new llvm::GlobalVariable(
      module, descriptor_type, true, llvm::GlobalValue::InternalLinkage,
      create_descriptor_initializer(module.getContext(), plan, state_global),
      make_decoder_name(plan.global->getName(), "__obf_desc_"));
}

std::vector<string_encoding_result> build_string_results(
    llvm::Module &module, protected_function_seed_lookup get_seed,
    protected_function_level_lookup get_level,
    const string_encoding_options &options, std::uint64_t module_seed,
    bool apply_changes) {
  std::vector<classified_string_candidate> candidates =
      classify_candidates(module, get_seed, get_level, options, module_seed);
  std::vector<string_strategy_plan> plans = select_plans(candidates, options);
  diversify_lazy_helper_shapes(plans, module_seed);
  apply_string_encoding_limit(plans, options);
  assign_lazy_descriptor_indices(plans, module_seed);

  std::vector<string_encoding_result> results;
  results.reserve(plans.size());

  std::vector<llvm::GlobalVariable *> state_globals(plans.size(), nullptr);
  std::vector<llvm::Constant *> descriptor_ptrs(plans.size(), nullptr);

  if (apply_changes) {
    llvm::DenseMap<int, std::vector<std::size_t>> groups;
    for (std::size_t index = 0; index < plans.size(); ++index) {
      string_strategy_plan &plan = plans[index];
      if (plan.result.mode != string_encoding_mode::lazy_decode ||
          !plan.result.applied) {
        continue;
      }

      state_globals[index] = create_lazy_state_global(module, plan);
      if (plan.result.merge_group < 0) {
        continue;
      }
      groups[plan.result.merge_group].push_back(index);
    }

    for (auto &group_entry : groups) {
      auto &indices = group_entry.second;
      std::sort(indices.begin(), indices.end(), [&](std::size_t lhs, std::size_t rhs) {
        return plans[lhs].result.descriptor_index <
               plans[rhs].result.descriptor_index;
      });

      const string_helper_shape table_shape = plans[indices.front()].result.helper_shape;
      llvm::StructType *descriptor_type =
          get_string_descriptor_type(module.getContext(), table_shape);

      llvm::SmallVector<llvm::Constant *, 8> initializers;
      initializers.reserve(indices.size());
      for (std::size_t table_index = 0; table_index < indices.size(); ++table_index) {
        const std::size_t plan_index = indices[table_index];
        initializers.push_back(create_descriptor_initializer(
            module.getContext(), plans[plan_index], *state_globals[plan_index]));
      }

      llvm::ArrayType *table_type =
          llvm::ArrayType::get(descriptor_type, initializers.size());
      llvm::GlobalVariable *table = new llvm::GlobalVariable(
          module, table_type, true, llvm::GlobalValue::InternalLinkage,
          llvm::ConstantArray::get(table_type, initializers),
          "__obf_desc_table_" + std::to_string(group_entry.first));

      for (std::size_t plan_index : indices) {
        descriptor_ptrs[plan_index] =
            create_descriptor_table_ptr(*table, plans[plan_index].result.descriptor_index);
      }
    }

    for (std::size_t index = 0; index < plans.size(); ++index) {
      string_strategy_plan &plan = plans[index];
      if (plan.result.mode != string_encoding_mode::lazy_decode ||
          !plan.result.applied || descriptor_ptrs[index] != nullptr ||
          state_globals[index] == nullptr) {
        continue;
      }

      llvm::GlobalVariable *descriptor =
          create_standalone_descriptor_global(module, plan, *state_globals[index]);
      descriptor_ptrs[index] = descriptor;
    }
  }

  for (std::size_t plan_index = 0; plan_index < plans.size(); ++plan_index) {
    string_strategy_plan &plan = plans[plan_index];
    if (plan.global == nullptr) {
      continue;
    }

    if (apply_changes && plan.result.applied) {
      encode_global_initializer(*plan.global, plan.seed);
      if (plan.result.mode == string_encoding_mode::inline_stack_decode) {
        rewrite_inline_stack_uses(*plan.global, plan.seed, plan.inline_uses);
      } else if (plan.result.mode == string_encoding_mode::lazy_decode) {
        llvm::Function *family_helper = plan.isolate_lazy_helper
                                            ? create_isolated_lazy_helper(module, plan)
                                            : get_or_create_lazy_family_helper(
                                                  module, plan.result.helper_shape);
        rewrite_lazy_uses(*family_helper, descriptor_ptrs[plan_index], plan.lazy_uses);
      } else if (plan.result.mode == string_encoding_mode::global_ctor) {
        llvm::Function *decoder =
            create_ctor_decoder(module, *plan.global, plan.seed);
        llvm::appendToGlobalCtors(module, decoder, options.ctor_priority);
      }
    }

    results.push_back(std::move(plan.result));
  }

  return results;
}

} // namespace

std::string to_string(string_encoding_mode mode) {
  switch (mode) {
  case string_encoding_mode::skipped:
    return "skipped";
  case string_encoding_mode::global_ctor:
    return "global_ctor";
  case string_encoding_mode::lazy_decode:
    return "lazy_decode";
  case string_encoding_mode::inline_stack_decode:
    return "inline_stack_decode";
  }

  return "skipped";
}

std::string to_string(string_strategy_kind kind) {
  switch (kind) {
  case string_strategy_kind::none:
    return "none";
  case string_strategy_kind::helper_global_ctor:
    return "helper_global_ctor";
  case string_strategy_kind::helper_lazy_decode:
    return "helper_lazy_decode";
  case string_strategy_kind::inline_stack_decode:
    return "inline_stack_decode";
  }

  return "none";
}

std::string to_string(string_helper_shape shape) {
  switch (shape) {
  case string_helper_shape::none:
    return "none";
  case string_helper_shape::ctor_unrolled_v0:
    return "ctor_unrolled_v0";
  case string_helper_shape::lazy_flag_unrolled_v0:
    return "lazy_flag_unrolled_v0";
  case string_helper_shape::lazy_flag_reverse_v1:
    return "lazy_flag_reverse_v1";
  case string_helper_shape::lazy_counter_chunked_v2:
    return "lazy_counter_chunked_v2";
  case string_helper_shape::lazy_cached_pointer_v3:
    return "lazy_cached_pointer_v3";
  }

  return "none";
}

std::string to_string(string_key_schedule_kind schedule) {
  switch (schedule) {
  case string_key_schedule_kind::seeded_byte_xor_v0:
    return "seeded_byte_xor_v0";
  case string_key_schedule_kind::mixed_runtime_byte_xor_v1:
    return "mixed_runtime_byte_xor_v1";
  case string_key_schedule_kind::cfg_path_byte_xor_v2:
    return "cfg_path_byte_xor_v2";
  }

  return "seeded_byte_xor_v0";
}

std::vector<string_encoding_result>
analyze_string_encoding(const llvm::Module &module,
                        protected_function_seed_lookup get_seed,
                        protected_function_level_lookup get_level,
                        const string_encoding_options &options,
                        std::uint64_t module_seed) {
  llvm::Module &mutable_module = const_cast<llvm::Module &>(module);
  return build_string_results(mutable_module, get_seed, get_level, options,
                              module_seed, false);
}

std::vector<string_encoding_result>
run_string_encoding(llvm::Module &module,
                    protected_function_seed_lookup get_seed,
                    protected_function_level_lookup get_level,
                    const string_encoding_options &options,
                    std::uint64_t module_seed) {
  return build_string_results(module, get_seed, get_level, options, module_seed,
                              true);
}

} // namespace obf
