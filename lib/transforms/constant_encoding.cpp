#include "obf/transforms/constant_encoding.h"

#include "obf/analysis/annotation_utils.h"
#include "obf/support/auth_encoding.h"
#include "obf/support/generated_names.h"
#include "obf/support/stable_hash.h"
#include "obf/transforms/mba.h"

#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/IR/Attributes.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace obf {

namespace {

struct keyed_pool_use {
  llvm::Instruction* instruction = nullptr;
  unsigned operand_index = 0;
  llvm::Function* function = nullptr;
  llvm::IntegerType* type = nullptr;
  llvm::APInt value;
};

struct keyed_pool_entry {
  llvm::IntegerType* type = nullptr;
  llvm::APInt value;
  std::size_t offset = 0;
};

struct keyed_pool_plan {
  llvm::SmallVector<keyed_pool_entry, 8> entries;
  llvm::SmallVector<keyed_pool_use, 8> uses;
  std::size_t byte_length = 0;
  std::uint64_t pool_id = 0;
};

struct keyed_pool_payload {
  auth::ConstantPoolAuthMetadata metadata;
  auth::StringTag tag{};
  llvm::SmallVector<std::uint8_t, 64> ciphertext;
};

struct keyed_pool_table_summary {
  llvm::SmallVector<llvm::Function*, 4> protected_functions;
  bool has_unprotected_use = false;
  bool has_non_function_use = false;
};

struct keyed_pool_table_use {
  llvm::Instruction* instruction = nullptr;
  unsigned operand_index = 0;
  llvm::Function* function = nullptr;
};

struct keyed_pool_table_plan {
  llvm::GlobalVariable* global = nullptr;
  llvm::SmallVector<keyed_pool_entry, 8> entries;
  llvm::SmallVector<keyed_pool_table_use, 8> uses;
  std::size_t byte_length = 0;
  std::uint64_t pool_id = 0;
};

enum class planned_constant_strategy {
  none,
  mba_inline,
  keyed_pool,
};

struct planned_constant_use {
  llvm::Instruction* instruction = nullptr;
  unsigned operand_index = 0;
  llvm::Function* function = nullptr;
  llvm::IntegerType* type = nullptr;
  llvm::APInt value;
  planned_constant_strategy strategy = planned_constant_strategy::none;
};

bool is_trivial_constant(const llvm::ConstantInt& constant) {
  return constant.isZero() || constant.isOne() || constant.isMinusOne();
}

bool is_supported_instruction(const llvm::Instruction& instruction) {
  return llvm::isa<llvm::BinaryOperator>(instruction) || llvm::isa<llvm::ICmpInst>(instruction) ||
         llvm::isa<llvm::SelectInst>(instruction) || llvm::isa<llvm::ReturnInst>(instruction) ||
         llvm::isa<llvm::StoreInst>(instruction) || llvm::isa<llvm::CallBase>(instruction);
}

bool is_auto_inline_instruction(const llvm::Instruction& instruction) {
  return llvm::isa<llvm::BinaryOperator>(instruction) || llvm::isa<llvm::ICmpInst>(instruction) ||
         llvm::isa<llvm::SelectInst>(instruction);
}

bool is_large_constant_type(const llvm::IntegerType& type) { return type.getBitWidth() > 32; }

std::size_t get_storage_bytes(const llvm::APInt& value) {
  return std::max<std::size_t>(1, value.getBitWidth() / 8);
}

bool is_supported_constant_operand(const llvm::Instruction& instruction,
                                   unsigned operand_index,
                                   const llvm::ConstantInt& constant,
                                   const constant_encoding_options& options) {
  if (!is_supported_instruction(instruction) || is_trivial_constant(constant) ||
      constant.getBitWidth() < options.min_bit_width) {
    return false;
  }

  if (const auto* call = llvm::dyn_cast<llvm::CallBase>(&instruction)) {
    if (operand_index >= call->arg_size()) { return false; }

    if (call->paramHasAttr(operand_index, llvm::Attribute::ImmArg)) { return false; }

    if (const llvm::Function* callee = call->getCalledFunction()) {
      if (callee->isIntrinsic()) { return false; }
    }

    return true;
  }

  return true;
}

void add_unique_function(llvm::SmallVectorImpl<llvm::Function*>& functions,
                         llvm::Function* function) {
  if (function == nullptr) { return; }
  if (std::find(functions.begin(), functions.end(), function) != functions.end()) { return; }
  functions.push_back(function);
}

bool constant_references_value(const llvm::Constant* constant, const llvm::Value& value) {
  if (constant == &value) { return true; }

  for (const llvm::Value* operand : constant->operands()) {
    if (operand == &value) { return true; }
    const auto* operand_constant = llvm::dyn_cast<llvm::Constant>(operand);
    if (operand_constant != nullptr && constant_references_value(operand_constant, value)) {
      return true;
    }
  }

  return false;
}

bool operand_references_value(const llvm::Value* operand, const llvm::Value& value) {
  if (operand == nullptr) { return false; }
  if (operand == &value) { return true; }

  const auto* operand_constant = llvm::dyn_cast<llvm::Constant>(operand);
  return operand_constant != nullptr && constant_references_value(operand_constant, value);
}

llvm::Value* materialize_constant_expression(llvm::Value* value, llvm::Instruction* insert_before) {
  auto* expression = llvm::dyn_cast<llvm::ConstantExpr>(value);
  if (expression == nullptr) { return value; }

  llvm::Instruction* materialized = expression->getAsInstruction();
  materialized->insertBefore(insert_before->getIterator());
  for (unsigned operand_index = 0; operand_index < materialized->getNumOperands();
       ++operand_index) {
    materialized->setOperand(
        operand_index,
        materialize_constant_expression(materialized->getOperand(operand_index), materialized));
  }

  return materialized;
}

bool expand_constant_expressions_referencing_global(llvm::Function& function,
                                                    const llvm::GlobalVariable& global) {
  llvm::SmallVector<llvm::Instruction*, 64> instructions;
  for (llvm::BasicBlock& block : function) {
    for (llvm::Instruction& instruction : block) { instructions.push_back(&instruction); }
  }

  bool changed = false;
  for (llvm::Instruction* instruction : instructions) {
    if (instruction == nullptr) { continue; }

    if (auto* phi = llvm::dyn_cast<llvm::PHINode>(instruction)) {
      for (unsigned incoming_index = 0; incoming_index < phi->getNumIncomingValues();
           ++incoming_index) {
        auto* constant = llvm::dyn_cast<llvm::Constant>(phi->getIncomingValue(incoming_index));
        if (constant == nullptr || !constant_references_value(constant, global)) { continue; }

        llvm::Instruction* insert_before = phi->getIncomingBlock(incoming_index)->getTerminator();
        phi->setIncomingValue(incoming_index,
                              materialize_constant_expression(constant, insert_before));
        changed = true;
      }
      continue;
    }

    for (unsigned operand_index = 0; operand_index < instruction->getNumOperands();
         ++operand_index) {
      auto* constant = llvm::dyn_cast<llvm::Constant>(instruction->getOperand(operand_index));
      if (constant == nullptr || !constant_references_value(constant, global)) { continue; }

      instruction->setOperand(operand_index,
                              materialize_constant_expression(constant, instruction));
      changed = true;
    }
  }

  return changed;
}

void collect_keyed_pool_table_users(const llvm::Value& value,
                                    protected_constant_function_seed_lookup get_seed,
                                    llvm::DenseSet<const llvm::User*>& visited,
                                    keyed_pool_table_summary& summary) {
  for (const llvm::User* user : value.users()) {
    if (!visited.insert(user).second || is_annotation_user(user)) { continue; }

    if (const auto* instruction = llvm::dyn_cast<llvm::Instruction>(user)) {
      llvm::Function* function = const_cast<llvm::Function*>(instruction->getFunction());
      if (function != nullptr && get_seed(function->getName()).has_value()) {
        add_unique_function(summary.protected_functions, function);
      } else {
        summary.has_unprotected_use = true;
      }
      continue;
    }

    if (llvm::isa<llvm::GlobalVariable>(user) || llvm::isa<llvm::GlobalAlias>(user)) {
      summary.has_non_function_use = true;
      continue;
    }

    if (const auto* constant = llvm::dyn_cast<llvm::Constant>(user)) {
      collect_keyed_pool_table_users(*constant, get_seed, visited, summary);
      continue;
    }

    summary.has_non_function_use = true;
  }
}

bool extract_keyed_pool_table_entries(const llvm::GlobalVariable& global,
                                      const constant_encoding_options& options,
                                      llvm::SmallVectorImpl<keyed_pool_entry>& entries,
                                      std::size_t& byte_length) {
  if (!global.hasInitializer() || !global.isConstant() || global.isThreadLocal() ||
      !global.hasLocalLinkage()) {
    return false;
  }

  auto* array_type = llvm::dyn_cast<llvm::ArrayType>(global.getValueType());
  if (array_type == nullptr || array_type->getNumElements() < 2) { return false; }

  auto* element_type = llvm::dyn_cast<llvm::IntegerType>(array_type->getElementType());
  if (element_type == nullptr || element_type->getBitWidth() < options.min_bit_width ||
      element_type->getBitWidth() % 8 != 0) {
    return false;
  }

  entries.clear();
  byte_length = 0;

  if (const auto* data = llvm::dyn_cast<llvm::ConstantDataSequential>(global.getInitializer())) {
    if (!data->getElementType()->isIntegerTy(element_type->getBitWidth()) || data->isString()) {
      return false;
    }

    for (std::uint64_t index = 0; index < data->getNumElements(); ++index) {
      const llvm::APInt value = data->getElementAsAPInt(index);
      entries.push_back({.type = element_type, .value = value, .offset = byte_length});
      byte_length += get_storage_bytes(value);
    }
    return !entries.empty();
  }

  const auto* array = llvm::dyn_cast<llvm::ConstantArray>(global.getInitializer());
  if (array == nullptr) { return false; }

  for (llvm::Value* operand : array->operands()) {
    const auto* constant = llvm::dyn_cast<llvm::ConstantInt>(operand);
    if (constant == nullptr || constant->getType() != element_type) { return false; }

    entries.push_back({.type = element_type, .value = constant->getValue(), .offset = byte_length});
    byte_length += get_storage_bytes(constant->getValue());
  }

  return !entries.empty();
}

void collect_direct_keyed_pool_table_uses(llvm::GlobalVariable& global,
                                          protected_constant_function_seed_lookup get_seed,
                                          llvm::SmallVectorImpl<keyed_pool_table_use>& uses) {
  for (llvm::User* user : global.users()) {
    if (is_annotation_user(user)) { continue; }

    auto* instruction = llvm::dyn_cast<llvm::Instruction>(user);
    if (instruction == nullptr) { continue; }

    llvm::Function* function = instruction->getFunction();
    if (function == nullptr || !get_seed(function->getName()).has_value()) { continue; }

    for (unsigned operand_index = 0; operand_index < instruction->getNumOperands(); ++operand_index) {
      if (!operand_references_value(instruction->getOperand(operand_index), global)) { continue; }

      uses.push_back({.instruction = instruction, .operand_index = operand_index, .function = function});
    }
  }
}

llvm::APInt derive_key(unsigned bit_width, std::uint64_t seed) {
  llvm::APInt key(bit_width, seed, false, true);
  if (key.isZero()) { key = llvm::APInt(bit_width, 0x5aU); }
  return key;
}

std::uint64_t derive_opaque_seed(const llvm::Function& function, std::uint64_t seed) {
  seed = mix_seed(seed, stable_hash_string(function.getName()));
  if (seed == 0) { seed = 0x5aa55aa55aa55aa5ULL; }
  return seed;
}

mba::builder_context derive_inline_opaque_context(llvm::Function* function,
                                                  const mba::builder_context& base_context,
                                                  llvm::StringRef prefix,
                                                  std::uint64_t seed_base) {
  if (function == nullptr) {
    mba::builder_context context = base_context;
    context.seed_base = mix_seed(seed_base, stable_hash_string(prefix));
    return context;
  }

  mba::builder_context context = mba::get_or_create_builder_context(*function, prefix, seed_base);
  context.depth = base_context.depth;
  return context;
}

llvm::Value* create_inline_opaque_integer(llvm::IRBuilder<>& builder,
                                          llvm::Function* function,
                                          llvm::IntegerType* type,
                                          const llvm::APInt& value,
                                          const mba::builder_context& base_context,
                                          llvm::StringRef prefix,
                                          std::uint64_t seed_base,
                                          std::uint64_t salt,
                                          llvm::StringRef name) {
  mba::builder_context context =
      derive_inline_opaque_context(function, base_context, prefix, seed_base);
  return mba::create_opaque_integer(builder, type, context, value, salt, name);
}

llvm::Value* build_opaque_mask(llvm::IRBuilder<>& builder,
                               std::uint64_t opaque_seed_base,
                               llvm::IntegerType* type,
                               const llvm::APInt& key,
                               const mba::builder_context& mba_context,
                               std::uint64_t salt) {
  llvm::Function* function =
      builder.GetInsertBlock() != nullptr ? builder.GetInsertBlock()->getParent() : nullptr;
  const llvm::APInt base_seed(type->getBitWidth(),
                              opaque_seed_base,
                              /*isSigned=*/false,
                              /*implicitTrunc=*/true);
  llvm::Value* typed_seed = create_inline_opaque_integer(builder,
                                                         function,
                                                         type,
                                                         base_seed,
                                                         mba_context,
                                                         "obf.const.seed",
                                                         opaque_seed_base,
                                                         salt ^ 0x55aa55aaULL,
                                                         "obf.const.seed");
  const llvm::APInt delta = key ^ base_seed;
  llvm::Value* opaque_delta = create_inline_opaque_integer(builder,
                                                           function,
                                                           type,
                                                           delta,
                                                           mba_context,
                                                           "obf.const.mask.delta",
                                                           mix_seed(opaque_seed_base, 0xd3110a7aULL),
                                                           salt ^ 0x6b1d2c39ULL,
                                                           "obf.const.mask.delta");
  return mba::create_xor(builder,
                         typed_seed,
                         opaque_delta,
                         mba_context,
                         salt,
                         "obf.const.mask");
}

constant_encoding_result analyze_impl(const llvm::Function& function,
                                      const constant_encoding_options& options) {
  if (function.isDeclaration()) { return {.encoded_count = 0, .detail = "declaration"}; }

  if (options.mode == constant_protection_mode::off) {
    return {.encoded_count = 0, .detail = "constant protection mode is off"};
  }

  if (options.max_constants_per_function == 0) {
    return {.encoded_count = 0, .detail = "max_constants_per_function is zero"};
  }

  std::size_t encoded_count = 0;
  for (const llvm::BasicBlock& block : function) {
    for (const llvm::Instruction& instruction : block) {
      for (unsigned operand_index = 0; operand_index < instruction.getNumOperands();
           ++operand_index) {
        const auto* constant =
            llvm::dyn_cast<llvm::ConstantInt>(instruction.getOperand(operand_index));
        if (constant == nullptr ||
            !is_supported_constant_operand(instruction, operand_index, *constant, options)) {
          continue;
        }

        ++encoded_count;
        if (encoded_count >= options.max_constants_per_function) {
          return {.encoded_count = encoded_count,
                  .detail = std::to_string(encoded_count) + " constant(s) available"};
        }
      }
    }
  }

  if (encoded_count == 0) {
    return {.encoded_count = 0, .detail = "no eligible integer constants"};
  }

  return {.encoded_count = encoded_count,
          .detail = std::to_string(encoded_count) + " constant(s) available"};
}

std::uint64_t derive_keyed_pool_module_id(const llvm::Module& module) {
  std::uint64_t module_id = stable_hash_string(module.getName(), 0x636f6e73745f6d31ULL);
  if (module_id == 0) { module_id = 0x434f4e53544d4f31ULL; }
  return module_id;
}

void append_apint_bytes(llvm::SmallVectorImpl<std::uint8_t>& bytes, const llvm::APInt& value) {
  const std::size_t storage_bytes = get_storage_bytes(value);
  bytes.resize(bytes.size() + storage_bytes);
  std::memcpy(bytes.end() - storage_bytes, value.getRawData(), storage_bytes);
}

llvm::Constant* create_byte_array_constant(llvm::LLVMContext& context,
                                           llvm::ArrayRef<std::uint8_t> bytes) {
  return llvm::ConstantDataArray::get(context, bytes);
}

llvm::StructType* get_keyed_pool_descriptor_type(llvm::LLVMContext& context) {
  llvm::Type* ptr_type = llvm::PointerType::getUnqual(context);
  llvm::Type* i32_ptr_type = llvm::PointerType::getUnqual(context);
  llvm::Type* i64_type = llvm::Type::getInt64Ty(context);
  llvm::Type* i32_type = llvm::Type::getInt32Ty(context);
  llvm::ArrayType* nonce_type =
      llvm::ArrayType::get(llvm::Type::getInt8Ty(context), auth::kStringNonceBytes);
  llvm::ArrayType* tag_type =
      llvm::ArrayType::get(llvm::Type::getInt8Ty(context), auth::kStringTagBytes);
  return llvm::StructType::get(ptr_type,
                               ptr_type,
                               ptr_type,
                               i32_ptr_type,
                               i64_type,
                               i64_type,
                               i64_type,
                               i32_type,
                               i32_type,
                               nonce_type,
                               tag_type);
}

llvm::FunctionCallee get_keyed_pool_runtime_decoder(llvm::Module& module) {
  llvm::LLVMContext& context = module.getContext();
  llvm::Type* ptr_type = llvm::PointerType::getUnqual(context);
  llvm::Type* i64_type = llvm::Type::getInt64Ty(context);
  llvm::FunctionType* type = llvm::FunctionType::get(ptr_type, {ptr_type, i64_type}, false);
  return module.getOrInsertFunction(auth::kRuntimeConstantPoolDecodeSymbolV1, type);
}

llvm::GlobalVariable* create_keyed_pool_ciphertext_global(llvm::Module& module,
                                                          const keyed_pool_plan& plan,
                                                          const keyed_pool_payload& payload,
                                                          std::uint64_t seed) {
  const std::string name = make_unique_obf_symbol_name(
      module, "__obf_const_pool", "ciphertext", seed ^ plan.pool_id ^ 0xc011ULL);
  return new llvm::GlobalVariable(module,
                                  llvm::ArrayType::get(llvm::Type::getInt8Ty(module.getContext()),
                                                       payload.ciphertext.size()),
                                  true,
                                  llvm::GlobalValue::InternalLinkage,
                                  create_byte_array_constant(module.getContext(), payload.ciphertext),
                                  name);
}

llvm::GlobalVariable* create_keyed_pool_build_key_global(llvm::Module& module,
                                                         std::uint64_t seed,
                                                         std::uint64_t pool_id) {
  const auth::BuildKey build_key = auth::DeriveBuildKey(seed);
  const std::string name =
      make_unique_obf_symbol_name(module, "__obf_const_build_key", "build_key", seed ^ pool_id);
  return new llvm::GlobalVariable(module,
                                  llvm::ArrayType::get(llvm::Type::getInt8Ty(module.getContext()),
                                                       build_key.size()),
                                  true,
                                  llvm::GlobalValue::InternalLinkage,
                                  llvm::ConstantDataArray::get(module.getContext(), build_key),
                                  name);
}

llvm::GlobalVariable* create_keyed_pool_destination_global(llvm::Module& module,
                                                           const keyed_pool_payload& payload,
                                                           std::uint64_t seed,
                                                           std::uint64_t pool_id) {
  const std::string name =
      make_unique_obf_symbol_name(module, "__obf_const_buf", "pool", seed ^ pool_id ^ 0xb0f1ULL);
  return new llvm::GlobalVariable(module,
                                  llvm::ArrayType::get(llvm::Type::getInt8Ty(module.getContext()),
                                                       payload.ciphertext.size()),
                                  false,
                                  llvm::GlobalValue::InternalLinkage,
                                  llvm::ConstantAggregateZero::get(
                                      llvm::ArrayType::get(llvm::Type::getInt8Ty(module.getContext()),
                                                           payload.ciphertext.size())),
                                  name);
}

llvm::GlobalVariable* create_keyed_pool_state_global(llvm::Module& module,
                                                     std::uint64_t seed,
                                                     std::uint64_t pool_id) {
  const std::string name =
      make_unique_obf_symbol_name(module, "__obf_const_state", "pool", seed ^ pool_id ^ 0x57a7eULL);
  return new llvm::GlobalVariable(module,
                                  llvm::Type::getInt32Ty(module.getContext()),
                                  false,
                                  llvm::GlobalValue::InternalLinkage,
                                  llvm::ConstantInt::get(llvm::Type::getInt32Ty(module.getContext()), 0),
                                  name);
}

llvm::GlobalVariable* create_keyed_pool_descriptor_global(llvm::Module& module,
                                                          const keyed_pool_payload& payload,
                                                          llvm::GlobalVariable& destination,
                                                          llvm::GlobalVariable& ciphertext,
                                                          llvm::GlobalVariable& build_key,
                                                          llvm::GlobalVariable& state,
                                                          std::uint64_t seed,
                                                          std::uint64_t pool_id) {
  llvm::LLVMContext& context = module.getContext();
  llvm::StructType* descriptor_type = get_keyed_pool_descriptor_type(context);
  llvm::Type* ptr_type = llvm::PointerType::getUnqual(context);
  llvm::SmallVector<llvm::Constant*, 11> fields;
  fields.push_back(llvm::ConstantExpr::getPointerBitCastOrAddrSpaceCast(&destination, ptr_type));
  fields.push_back(llvm::ConstantExpr::getPointerBitCastOrAddrSpaceCast(&ciphertext, ptr_type));
  fields.push_back(llvm::ConstantExpr::getPointerBitCastOrAddrSpaceCast(&build_key, ptr_type));
  fields.push_back(llvm::ConstantExpr::getPointerBitCastOrAddrSpaceCast(&state, ptr_type));
  fields.push_back(llvm::ConstantInt::get(llvm::Type::getInt64Ty(context), payload.metadata.length));
  fields.push_back(llvm::ConstantInt::get(llvm::Type::getInt64Ty(context), payload.metadata.module_id));
  fields.push_back(llvm::ConstantInt::get(llvm::Type::getInt64Ty(context), payload.metadata.pool_id));
  fields.push_back(llvm::ConstantInt::get(llvm::Type::getInt32Ty(context), payload.metadata.version));
  fields.push_back(llvm::ConstantInt::get(llvm::Type::getInt32Ty(context), payload.metadata.flags));
  fields.push_back(create_byte_array_constant(context, payload.metadata.nonce));
  fields.push_back(create_byte_array_constant(context, payload.tag));
  const std::string name =
      make_unique_obf_symbol_name(module, "__obf_const_desc", "pool", seed ^ pool_id ^ 0xd35cULL);
  return new llvm::GlobalVariable(module,
                                  descriptor_type,
                                  true,
                                  llvm::GlobalValue::InternalLinkage,
                                  llvm::ConstantStruct::get(descriptor_type, fields),
                                  name);
}

llvm::Function* create_keyed_pool_helper(llvm::Module& module,
                                         llvm::GlobalVariable& descriptor,
                                         llvm::GlobalVariable& destination,
                                         std::uint64_t trusted_length,
                                         std::uint64_t seed) {
  const std::string name =
      make_unique_obf_symbol_name(module, "__obf_const_pool_decode", "pool", seed ^ trusted_length);
  if (llvm::Function* existing = module.getFunction(name)) { return existing; }

  llvm::LLVMContext& context = module.getContext();
  llvm::Type* ptr_type = llvm::PointerType::getUnqual(context);
  llvm::Type* i32_type = llvm::Type::getInt32Ty(context);
  llvm::FunctionType* type = llvm::FunctionType::get(ptr_type, false);
  llvm::Function* helper =
      llvm::Function::Create(type, llvm::GlobalValue::InternalLinkage, name, module);

  llvm::BasicBlock* entry = llvm::BasicBlock::Create(context, "entry", helper);
  llvm::BasicBlock* fast_path = llvm::BasicBlock::Create(context, "fast_path", helper);
  llvm::BasicBlock* slow_path = llvm::BasicBlock::Create(context, "slow_path", helper);
  llvm::BasicBlock* merge = llvm::BasicBlock::Create(context, "merge", helper);

  llvm::IRBuilder<> builder(entry);
  llvm::StructType* descriptor_type = get_keyed_pool_descriptor_type(context);
  llvm::Value* descriptor_ptr =
      builder.CreatePointerCast(&descriptor, llvm::PointerType::getUnqual(context));
  llvm::Value* state_addr = builder.CreateStructGEP(descriptor_type, descriptor_ptr, 3,
                                                    "obf.const.pool.state.addr");
  llvm::Value* state_ptr = builder.CreateLoad(ptr_type, state_addr, "obf.const.pool.state.ptr");
  llvm::Value* loaded_state = builder.CreateLoad(i32_type, state_ptr, "obf.const.pool.state");
  llvm::Value* is_decoded = builder.CreateICmpEQ(
      loaded_state,
      llvm::ConstantInt::get(i32_type, auth::kConstantPoolStateDecoded),
      "obf.const.pool.decoded");
  builder.CreateCondBr(is_decoded, fast_path, slow_path);

  builder.SetInsertPoint(fast_path);
  llvm::Value* destination_ptr =
      builder.CreatePointerCast(&destination, llvm::PointerType::getUnqual(context));
  builder.CreateBr(merge);

  builder.SetInsertPoint(slow_path);
  llvm::Value* decoded = builder.CreateCall(
      get_keyed_pool_runtime_decoder(module),
      {builder.CreatePointerCast(descriptor_ptr, ptr_type),
       llvm::ConstantInt::get(llvm::Type::getInt64Ty(context), trusted_length)});
  builder.CreateBr(merge);

  builder.SetInsertPoint(merge);
  llvm::PHINode* result = builder.CreatePHI(ptr_type, 2, "obf.const.pool.result");
  result->addIncoming(destination_ptr, fast_path);
  result->addIncoming(decoded, slow_path);
  builder.CreateRet(result);
  return helper;
}

llvm::Value* build_integer_from_pool_entry(llvm::IRBuilder<>& builder,
                                           llvm::Function& helper,
                                           llvm::IntegerType* type,
                                           std::size_t offset) {
  llvm::LLVMContext& context = builder.getContext();
  llvm::Value* base = builder.CreateCall(&helper, {}, "obf.const.pool.base");
  llvm::Value* byte_ptr = builder.CreateInBoundsGEP(
      llvm::Type::getInt8Ty(context),
      base,
      llvm::ConstantInt::get(llvm::Type::getInt64Ty(context), offset),
      "obf.const.pool.ptr");
  llvm::Value* typed_ptr = builder.CreatePointerCast(
      byte_ptr, llvm::PointerType::getUnqual(type), "obf.const.pool.typed_ptr");
  return builder.CreateLoad(type, typed_ptr, "obf.const.pool.load");
}

std::optional<std::size_t> find_entry_offset(const keyed_pool_plan& plan,
                                             llvm::IntegerType* type,
                                             const llvm::APInt& value) {
  for (const keyed_pool_entry& entry : plan.entries) {
    if (entry.type == type && entry.value == value) { return entry.offset; }
  }
  return std::nullopt;
}

std::uint64_t derive_keyed_pool_id_from_entries(llvm::ArrayRef<keyed_pool_entry> entries,
                                                std::uint64_t seed) {
  std::uint64_t pool_id = mix_seed(seed, static_cast<std::uint64_t>(entries.size() + 1));
  for (const keyed_pool_entry& entry : entries) {
    pool_id = mix_seed(pool_id, static_cast<std::uint64_t>(entry.type->getBitWidth()));
    pool_id = mix_seed(pool_id, entry.value.getLimitedValue());
  }
  if (pool_id == 0) { pool_id = 0x434f4e5354504f31ULL; }
  return pool_id;
}

keyed_pool_payload build_keyed_pool_payload(llvm::ArrayRef<keyed_pool_entry> entries,
                                            std::size_t byte_length,
                                            std::uint64_t pool_id,
                                            std::uint64_t module_id,
                                            std::uint64_t seed) {
  keyed_pool_payload payload;
  llvm::SmallVector<std::uint8_t, 64> plaintext;
  plaintext.reserve(byte_length);
  for (const keyed_pool_entry& entry : entries) {
    append_apint_bytes(plaintext, entry.value);
  }

  const auth::BuildKey build_key = auth::DeriveBuildKey(seed);
  const auth::Blake2sDigest function_key = auth::DeriveFunctionKey(build_key, module_id, 0);
  const auth::Blake2sDigest pool_key =
      auth::DeriveSiteKey(function_key, auth::kDomainConstant, pool_id);
  const auth::Blake2sDigest enc_key = auth::DeriveLabeledKey(pool_key, auth::kDomainEnc);
  const auth::Blake2sDigest mac_key = auth::DeriveLabeledKey(pool_key, auth::kDomainMac);

  payload.metadata.version = auth::kConstantPoolDescriptorVersionV1;
  payload.metadata.flags = auth::kConstantPoolAuthFlagTrapOnFailure;
  payload.metadata.length = plaintext.size();
  payload.metadata.module_id = module_id;
  payload.metadata.pool_id = pool_id;
  payload.metadata.nonce = auth::DeriveStringNonce(pool_key);

  payload.ciphertext.resize(plaintext.size());
  auth::XorStringPayload(payload.ciphertext, plaintext, enc_key, payload.metadata.nonce);
  payload.tag = auth::ComputeConstantPoolTag(mac_key, payload.metadata, payload.ciphertext);
  return payload;
}

std::size_t apply_mba_inline_uses(llvm::ArrayRef<planned_constant_use> uses,
                                  const constant_encoding_options& options,
                                  std::uint64_t seed) {
  llvm::DenseMap<llvm::Function*, std::uint64_t> function_opaque_seeds;
  llvm::DenseMap<llvm::Function*, mba::builder_context> mba_contexts;
  llvm::DenseMap<llvm::Function*, std::uint64_t> function_local_seeds;
  llvm::DenseMap<llvm::Function*, std::size_t> function_encoded_counts;
  std::size_t encoded_count = 0;

  for (const planned_constant_use& use : uses) {
    if (use.strategy != planned_constant_strategy::mba_inline || use.instruction == nullptr ||
        use.function == nullptr || use.type == nullptr) {
      continue;
    }

    std::size_t& function_encoded = function_encoded_counts[use.function];
    if (function_encoded >= options.max_constants_per_function) { continue; }

    std::uint64_t& opaque_seed_base = function_opaque_seeds[use.function];
    if (opaque_seed_base == 0) { opaque_seed_base = derive_opaque_seed(*use.function, seed); }

    mba::builder_context& mba_context = mba_contexts[use.function];
    if (mba_context.entropy_anchor == nullptr) {
      mba_context = mba::get_or_create_builder_context(
          *use.function, "obf.const.mba", opaque_seed_base);
      mba_context.depth = options.mba_depth;
    }

    std::uint64_t& local_seed = function_local_seeds[use.function];
    if (local_seed == 0) { local_seed = seed; }
    local_seed = mix_seed(local_seed, static_cast<std::uint64_t>(function_encoded + 1));

    const llvm::APInt key = derive_key(use.type->getBitWidth(), local_seed);
    const llvm::APInt encoded = use.value ^ key;

    llvm::IRBuilder<> builder(use.instruction);
    llvm::Value* mask = build_opaque_mask(builder,
                                          opaque_seed_base,
                                          use.type,
                                          key,
                                          mba_context,
                                          local_seed ^
                                              static_cast<std::uint64_t>(use.operand_index + 1));
    llvm::Value* opaque_encoded = create_inline_opaque_integer(
        builder,
        use.function,
        use.type,
        encoded,
        mba_context,
        "obf.const.encoded",
        mix_seed(opaque_seed_base, 0xe0c0de01ULL),
        local_seed ^ 0x9f4a7c1500b5ULL,
        "obf.const.encoded");
    llvm::Value* decoded = mba::create_xor(builder,
                                           opaque_encoded,
                                           mask,
                                           mba_context,
                                           local_seed ^ 0xd6e8feb86659fd93ULL,
                                           "obf.const");
    use.instruction->setOperand(use.operand_index, decoded);
    ++function_encoded;
    ++encoded_count;
  }

  return encoded_count;
}

std::optional<keyed_pool_plan> build_keyed_pool_plan_for_type(
    llvm::Type* key,
    keyed_pool_plan& source,
    const constant_encoding_options& options,
    std::uint64_t seed) {
  if (source.uses.size() < 2) { return std::nullopt; }

  llvm::DenseMap<llvm::Function*, std::size_t> per_function_counts;
  keyed_pool_plan plan;
  for (const keyed_pool_use& use : source.uses) {
    if (use.function == nullptr) { continue; }

    std::size_t& function_count = per_function_counts[use.function];
    if (function_count >= options.max_constants_per_function) { continue; }
    ++function_count;
    plan.uses.push_back(use);
  }

  if (plan.uses.size() < 2) { return std::nullopt; }

  llvm::SmallVector<std::pair<llvm::IntegerType*, llvm::APInt>, 8> unique_values;
  for (const keyed_pool_use& use : plan.uses) {
    const auto existing = llvm::find_if(unique_values, [&](const auto& candidate) {
      return candidate.first == use.type && candidate.second == use.value;
    });
    if (existing == unique_values.end()) { unique_values.push_back({use.type, use.value}); }
  }

  plan.entries.clear();
  plan.byte_length = 0;
  for (const auto& unique_value : unique_values) {
    const std::size_t offset = plan.byte_length;
    const std::size_t width = get_storage_bytes(unique_value.second);
    plan.entries.push_back({.type = unique_value.first, .value = unique_value.second, .offset = offset});
    plan.byte_length += width;
  }

  if (plan.entries.empty()) { return std::nullopt; }

  plan.pool_id = derive_keyed_pool_id_from_entries(
      plan.entries,
      seed ^ static_cast<std::uint64_t>(llvm::cast<llvm::IntegerType>(key)->getScalarSizeInBits()));
  return plan;
}

bool should_use_keyed_pool_for_site(const planned_constant_use& use,
                                    constant_protection_mode mode,
                                    std::size_t site_count_for_value) {
  if (mode == constant_protection_mode::keyed_pool) { return true; }
  if (mode == constant_protection_mode::auto_mode) {
    return site_count_for_value > 1 || is_large_constant_type(*use.type) ||
           !is_auto_inline_instruction(*use.instruction);
  }
  if (mode == constant_protection_mode::all) {
    return site_count_for_value > 1 || is_large_constant_type(*use.type);
  }
  return false;
}

llvm::SmallVector<planned_constant_use, 32> collect_planned_constant_uses(
    llvm::Module& module,
    protected_constant_function_seed_lookup get_seed,
    const constant_encoding_options& options) {
  llvm::SmallVector<planned_constant_use, 32> uses;
  llvm::DenseMap<llvm::Function*, std::size_t> per_function_counts;
  llvm::DenseMap<llvm::Type*, llvm::DenseMap<llvm::APInt, std::size_t>> site_counts;

  for (llvm::Function& function : module) {
    const std::optional<std::uint64_t> function_seed = get_seed(function.getName());
    if (!function_seed.has_value()) { continue; }

    for (llvm::BasicBlock& block : function) {
      for (llvm::Instruction& instruction : block) {
        for (unsigned operand_index = 0; operand_index < instruction.getNumOperands();
             ++operand_index) {
          auto* constant = llvm::dyn_cast<llvm::ConstantInt>(instruction.getOperand(operand_index));
          if (constant == nullptr ||
              !is_supported_constant_operand(instruction, operand_index, *constant, options)) {
            continue;
          }

          std::size_t& function_count = per_function_counts[&function];
          if (function_count >= options.max_constants_per_function) { continue; }
          ++function_count;

          auto* type = llvm::cast<llvm::IntegerType>(constant->getType());
          uses.push_back({.instruction = &instruction,
                          .operand_index = operand_index,
                          .function = &function,
                          .type = type,
                          .value = constant->getValue(),
                          .strategy = planned_constant_strategy::none});
          ++site_counts[type][constant->getValue()];
        }
      }
    }
  }

  for (planned_constant_use& use : uses) {
    const std::size_t site_count_for_value = site_counts[use.type][use.value];
    use.strategy = should_use_keyed_pool_for_site(use, options.mode, site_count_for_value)
                       ? planned_constant_strategy::keyed_pool
                       : planned_constant_strategy::mba_inline;
  }

  return uses;
}

llvm::DenseMap<llvm::Type*, keyed_pool_plan> build_keyed_pool_plans_from_uses(
    llvm::ArrayRef<planned_constant_use> uses) {
  llvm::DenseMap<llvm::Type*, keyed_pool_plan> plans;
  for (const planned_constant_use& use : uses) {
    if (use.strategy != planned_constant_strategy::keyed_pool) { continue; }

    keyed_pool_plan& plan = plans[use.type];
    plan.uses.push_back({.instruction = use.instruction,
                         .operand_index = use.operand_index,
                         .function = use.function,
                         .type = use.type,
                         .value = use.value});
  }
  return plans;
}

std::optional<keyed_pool_table_plan> build_keyed_pool_table_plan(
    llvm::GlobalVariable& global,
    protected_constant_function_seed_lookup get_seed,
    const constant_encoding_options& options,
    std::uint64_t seed) {
  keyed_pool_table_summary summary;
  llvm::DenseSet<const llvm::User*> visited;
  collect_keyed_pool_table_users(global, get_seed, visited, summary);
  if (summary.has_unprotected_use || summary.has_non_function_use || summary.protected_functions.empty()) {
    return std::nullopt;
  }

  keyed_pool_table_plan plan;
  plan.global = &global;
  if (!extract_keyed_pool_table_entries(global, options, plan.entries, plan.byte_length)) {
    return std::nullopt;
  }

  for (llvm::Function* function : summary.protected_functions) {
    if (function != nullptr) { expand_constant_expressions_referencing_global(*function, global); }
  }
  collect_direct_keyed_pool_table_uses(global, get_seed, plan.uses);
  if (plan.uses.empty()) { return std::nullopt; }

  plan.pool_id = derive_keyed_pool_id_from_entries(
      plan.entries, seed ^ stable_hash_string(global.getName(), 0x7461626c655f7031ULL));
  return plan;
}

void rewrite_keyed_pool_table_use(llvm::Instruction& instruction,
                                  unsigned operand_index,
                                  llvm::GlobalVariable& global,
                                  llvm::Function& helper) {
  llvm::IRBuilder<> builder(&instruction);
  llvm::Value* operand = instruction.getOperand(operand_index);
  llvm::Value* rewritten = nullptr;

  if (operand == &global) {
    rewritten = builder.CreateCall(&helper, {}, "obf.const.pool.base");
  } else if (auto* gep = llvm::dyn_cast<llvm::GetElementPtrInst>(operand)) {
    if (gep->getPointerOperand() == &global) {
      llvm::Value* base = builder.CreateCall(&helper, {}, "obf.const.pool.base");
      llvm::SmallVector<llvm::Value*, 8> indices;
      indices.reserve(gep->getNumIndices());
      for (llvm::Value* index : gep->indices()) { indices.push_back(index); }
      rewritten = builder.CreateInBoundsGEP(
          gep->getSourceElementType(), base, indices, "obf.const.pool.gep");
    }
  }

  if (rewritten == nullptr && operand_references_value(operand, global)) {
    rewritten = builder.CreateCall(&helper, {}, "obf.const.pool.base");
  }

  if (rewritten != nullptr) { instruction.setOperand(operand_index, rewritten); }
}

}  // namespace

constant_encoding_result analyze_constant_encoding(const llvm::Function& function,
                                                   const constant_encoding_options& options,
                                                   std::uint64_t) {
  return analyze_impl(function, options);
}

constant_encoding_result run_constant_encoding(llvm::Function& function,
                                               const constant_encoding_options& options,
                                               std::uint64_t seed) {
  if (options.mode == constant_protection_mode::off ||
      options.mode == constant_protection_mode::keyed_pool ||
      options.mode == constant_protection_mode::auto_mode ||
      options.mode == constant_protection_mode::all) {
    return {.encoded_count = 0,
            .detail = options.mode == constant_protection_mode::off
                          ? "constant protection mode is off"
                          : "selected constant protection mode requires module execution"};
  }

  const constant_encoding_result analysis = analyze_impl(function, options);
  if (analysis.encoded_count == 0) { return analysis; }

  std::size_t encoded_count = 0;
  std::uint64_t local_seed = seed;
  const std::uint64_t opaque_seed_base = derive_opaque_seed(function, seed);

  llvm::SmallVector<llvm::Instruction*, 64> original_instructions;
  for (llvm::BasicBlock& block : function) {
    for (llvm::Instruction& instruction : block) { original_instructions.push_back(&instruction); }
  }

  const mba::builder_context mba_context = [&] {
    mba::builder_context ctx =
        mba::get_or_create_builder_context(function, "obf.const.mba", opaque_seed_base);
    ctx.depth = options.mba_depth;
    return ctx;
  }();

  for (llvm::Instruction* instruction : original_instructions) {
    if (instruction == nullptr || encoded_count >= options.max_constants_per_function) { continue; }

    for (unsigned operand_index = 0; operand_index < instruction->getNumOperands();
         ++operand_index) {
      if (encoded_count >= options.max_constants_per_function) { break; }

      auto* constant = llvm::dyn_cast<llvm::ConstantInt>(instruction->getOperand(operand_index));
      if (constant == nullptr ||
          !is_supported_constant_operand(*instruction, operand_index, *constant, options)) {
        continue;
      }

      local_seed = mix_seed(local_seed, static_cast<std::uint64_t>(encoded_count + 1));
      const llvm::APInt key = derive_key(constant->getBitWidth(), local_seed);
      const llvm::APInt encoded = constant->getValue() ^ key;

      llvm::IRBuilder<> builder(instruction);
      llvm::Value* mask =
          build_opaque_mask(builder,
                            opaque_seed_base,
                            llvm::cast<llvm::IntegerType>(constant->getType()),
                            key,
                            mba_context,
                            local_seed ^ static_cast<std::uint64_t>(operand_index + 1));
      llvm::Value* decoded = mba::create_xor(builder,
                                             llvm::ConstantInt::get(constant->getType(), encoded),
                                             mask,
                                             mba_context,
                                             local_seed ^ 0xd6e8feb86659fd93ULL,
                                             "obf.const");
      instruction->setOperand(operand_index, decoded);
      ++encoded_count;
    }
  }

  return {.encoded_count = encoded_count,
          .detail = std::to_string(encoded_count) + " constant(s) encoded"};
}

constant_encoding_result run_constant_encoding(llvm::Module& module,
                                               protected_constant_function_seed_lookup get_seed,
                                               const constant_encoding_options& options,
                                               std::uint64_t seed) {
  if (options.mode != constant_protection_mode::keyed_pool &&
      options.mode != constant_protection_mode::auto_mode &&
      options.mode != constant_protection_mode::all) {
    return {.encoded_count = 0,
            .detail = "module constant encoding is only used for keyed_pool, auto, or all"};
  }

  llvm::SmallVector<planned_constant_use, 32> uses =
      collect_planned_constant_uses(module, get_seed, options);
  llvm::DenseMap<llvm::Type*, keyed_pool_plan> plans = build_keyed_pool_plans_from_uses(uses);

  llvm::SmallVector<keyed_pool_table_plan, 8> table_plans;
  for (llvm::GlobalVariable& global : module.globals()) {
    std::optional<keyed_pool_table_plan> plan =
        build_keyed_pool_table_plan(global, get_seed, options, seed);
    if (plan.has_value()) { table_plans.push_back(std::move(*plan)); }
  }

  std::size_t encoded_count = 0;
  const std::uint64_t module_id = derive_keyed_pool_module_id(module);

  encoded_count += apply_mba_inline_uses(uses, options, seed);

  for (auto& entry : plans) {
    std::optional<keyed_pool_plan> planned =
        build_keyed_pool_plan_for_type(entry.first, entry.second, options, seed);
    if (!planned.has_value()) { continue; }

    keyed_pool_plan& plan = *planned;
    const keyed_pool_payload payload =
        build_keyed_pool_payload(plan.entries, plan.byte_length, plan.pool_id, module_id, seed);
    llvm::GlobalVariable* ciphertext =
        create_keyed_pool_ciphertext_global(module, plan, payload, seed);
    llvm::GlobalVariable* build_key =
        create_keyed_pool_build_key_global(module, seed, plan.pool_id);
    llvm::GlobalVariable* destination =
        create_keyed_pool_destination_global(module, payload, seed, plan.pool_id);
    llvm::GlobalVariable* state = create_keyed_pool_state_global(module, seed, plan.pool_id);
    llvm::GlobalVariable* descriptor = create_keyed_pool_descriptor_global(
        module, payload, *destination, *ciphertext, *build_key, *state, seed, plan.pool_id);
    llvm::Function* helper =
        create_keyed_pool_helper(module, *descriptor, *destination, payload.metadata.length, seed ^ plan.pool_id);

    for (const keyed_pool_use& use : plan.uses) {
      const std::optional<std::size_t> offset = find_entry_offset(plan, use.type, use.value);
      if (!offset.has_value()) { continue; }

      llvm::IRBuilder<> builder(use.instruction);
      llvm::Value* decoded = build_integer_from_pool_entry(builder, *helper, use.type, *offset);
      use.instruction->setOperand(use.operand_index, decoded);
      ++encoded_count;
    }
  }

  for (keyed_pool_table_plan& plan : table_plans) {
    if (plan.global == nullptr) { continue; }

    keyed_pool_plan payload_plan;
    payload_plan.entries = plan.entries;
    payload_plan.byte_length = plan.byte_length;
    payload_plan.pool_id = plan.pool_id;

    const keyed_pool_payload payload =
        build_keyed_pool_payload(plan.entries, plan.byte_length, plan.pool_id, module_id, seed);
    llvm::GlobalVariable* ciphertext =
        create_keyed_pool_ciphertext_global(module, payload_plan, payload, seed);
    llvm::GlobalVariable* build_key =
        create_keyed_pool_build_key_global(module, seed, plan.pool_id);
    llvm::GlobalVariable* destination =
        create_keyed_pool_destination_global(module, payload, seed, plan.pool_id);
    llvm::GlobalVariable* state = create_keyed_pool_state_global(module, seed, plan.pool_id);
    llvm::GlobalVariable* descriptor = create_keyed_pool_descriptor_global(
        module, payload, *destination, *ciphertext, *build_key, *state, seed, plan.pool_id);
    llvm::Function* helper = create_keyed_pool_helper(
        module, *descriptor, *destination, payload.metadata.length, seed ^ plan.pool_id);

    for (const keyed_pool_table_use& use : plan.uses) {
      if (use.instruction == nullptr) { continue; }
      rewrite_keyed_pool_table_use(*use.instruction, use.operand_index, *plan.global, *helper);
      ++encoded_count;
    }
  }

  if (encoded_count == 0) {
    return {.encoded_count = 0, .detail = "no eligible keyed constant pools"};
  }

  return {.encoded_count = encoded_count,
          .detail = std::to_string(encoded_count) + " constant(s) pooled"};
}

}  // namespace obf
