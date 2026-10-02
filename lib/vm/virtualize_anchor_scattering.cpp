#include "obf/vm/internal/virtualize_anchor_scattering.h"

#include "obf/vm/virtualize_internal.h"

#include "llvm/ADT/STLExtras.h"
#include "llvm/ADT/StringExtras.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Intrinsics.h"
#include "llvm/IR/Metadata.h"
#include "llvm/Support/ErrorHandling.h"

#include <algorithm>
#include <limits>
#include <numeric>
#include <string>
#include <vector>

namespace obf::vm {

namespace {

constexpr llvm::StringLiteral anchor_encoding_metadata = "obf.vm.anchor.encoding";

std::uint32_t bytecode_anchor_length(const llvm::GlobalVariable& anchor) {
  const auto* array_type = llvm::dyn_cast<llvm::ArrayType>(anchor.getValueType());
  if (array_type == nullptr || !array_type->getElementType()->isIntegerTy(8) ||
      array_type->getNumElements() == 0 ||
      array_type->getNumElements() > std::numeric_limits<std::uint32_t>::max() ||
      !anchor.hasInitializer()) {
    llvm::report_fatal_error("vm bytecode anchor must be an initialized nonempty i8 array");
  }
  return static_cast<std::uint32_t>(array_type->getNumElements());
}

void validate_anchor_encoding(const bytecode_anchor_encoding& encoding, std::uint32_t length) {
  if (length == 0 || encoding.stride == 0 || encoding.bias >= length ||
      std::gcd(encoding.stride, length) != 1) {
    llvm::report_fatal_error("malformed vm bytecode anchor encoding: non-bijective placement");
  }
}

llvm::GlobalVariable* clone_bytecode_anchor(llvm::GlobalVariable& source, const llvm::Twine& name) {
  auto* clone = new llvm::GlobalVariable(*source.getParent(),
                                         source.getValueType(),
                                         source.isConstant(),
                                         llvm::GlobalValue::PrivateLinkage,
                                         source.getInitializer(),
                                         name,
                                         nullptr,
                                         source.getThreadLocalMode(),
                                         source.getAddressSpace(),
                                         source.isExternallyInitialized());
  clone->copyAttributesFrom(&source);
  clone->setLinkage(llvm::GlobalValue::PrivateLinkage);
  clone->copyMetadata(&source, 0);
  return clone;
}

std::vector<std::uint8_t> canonical_anchor_bytes(const llvm::GlobalVariable& anchor,
                                                 std::uint32_t length) {
  const bool is_encoded = anchor.getMetadata(anchor_encoding_metadata) != nullptr;
  const bytecode_anchor_encoding encoding = get_bytecode_anchor_encoding(anchor);
  const llvm::Constant* initializer = anchor.getInitializer();
  std::vector<std::uint8_t> canonical(length);
  for (std::uint32_t offset = 0; offset < length; ++offset) {
    const std::uint32_t physical =
        is_encoded ? physical_bytecode_offset(encoding, offset, length) : offset;
    const auto* byte =
        llvm::dyn_cast_or_null<llvm::ConstantInt>(initializer->getAggregateElement(physical));
    if (byte == nullptr || !byte->getType()->isIntegerTy(8)) {
      llvm::report_fatal_error("vm bytecode anchor initializer contains a non-byte constant");
    }
    canonical[offset] = static_cast<std::uint8_t>(byte->getZExtValue()) ^
                        (is_encoded ? bytecode_anchor_mask(encoding, offset) : 0);
  }
  return canonical;
}

void encode_bytecode_anchor(llvm::GlobalVariable& anchor,
                            llvm::ArrayRef<std::uint8_t> canonical,
                            llvm::Constant* canonical_initializer,
                            std::vector<std::uint8_t>& physical,
                            llvm::SmallVectorImpl<llvm::Constant*>& used_initializers,
                            std::uint64_t bytecode_seed,
                            std::uint64_t salt,
                            std::uint32_t ordinal) {
  const auto length = static_cast<std::uint32_t>(canonical.size());
  const std::uint64_t site_seed = mix_seed(
      bytecode_seed, salt ^ ((static_cast<std::uint64_t>(ordinal) + 1) * 0x9e3779b97f4a7c15ULL));
  for (std::uint64_t attempt = 0;; ++attempt) {
    const std::uint64_t seed = mix_seed(site_seed, 0x27310000ULL + attempt);
    bytecode_anchor_encoding encoding;
    if (length > 1) {
      encoding.stride =
          1U + static_cast<std::uint32_t>(mix_seed(seed, 0x27310001ULL) % (length - 1U));
      while (std::gcd(encoding.stride, length) != 1) {
        encoding.stride = encoding.stride == length - 1U ? 1U : encoding.stride + 1U;
      }
      encoding.bias = static_cast<std::uint32_t>(mix_seed(seed, 0x27310002ULL) % length);
    }
    encoding.mask_seed = mix_seed(seed, 0x27310003ULL);
    for (std::uint32_t offset = 0; offset < length; ++offset) {
      physical[physical_bytecode_offset(encoding, offset, length)] =
          canonical[offset] ^ bytecode_anchor_mask(encoding, offset);
    }
    llvm::Constant* initializer = llvm::ConstantDataArray::get(anchor.getContext(), physical);
    // Constant uniquing makes equality exact without a second payload comparison.
    if ((length > 1 && initializer == canonical_initializer) ||
        llvm::is_contained(used_initializers, initializer)) {
      if (attempt == std::numeric_limits<std::uint64_t>::max()) {
        llvm::report_fatal_error("vm bytecode anchor encoding exhausted distinct payloads");
      }
      continue;
    }
    anchor.setInitializer(initializer);
    llvm::LLVMContext& context = anchor.getContext();
    anchor.setMetadata(
        anchor_encoding_metadata,
        llvm::MDNode::get(context,
                          {llvm::ConstantAsMetadata::get(llvm::ConstantInt::get(
                               llvm::Type::getInt32Ty(context), encoding.stride)),
                           llvm::ConstantAsMetadata::get(llvm::ConstantInt::get(
                               llvm::Type::getInt32Ty(context), encoding.bias)),
                           llvm::ConstantAsMetadata::get(llvm::ConstantInt::get(
                               llvm::Type::getInt64Ty(context), encoding.mask_seed))}));
    used_initializers.push_back(initializer);
    return;
  }
}

}  // namespace

bytecode_anchor_encoding get_bytecode_anchor_encoding(const llvm::GlobalVariable& anchor) {
  const llvm::MDNode* metadata = anchor.getMetadata(anchor_encoding_metadata);
  if (metadata == nullptr) { return {}; }
  if (metadata->getNumOperands() != 3) {
    llvm::report_fatal_error("malformed vm bytecode anchor encoding: expected three operands");
  }
  const auto integer_operand = [&](unsigned index, unsigned bits) {
    const auto* constant =
        llvm::dyn_cast_or_null<llvm::ConstantAsMetadata>(metadata->getOperand(index).get());
    const auto* integer =
        constant == nullptr ? nullptr : llvm::dyn_cast<llvm::ConstantInt>(constant->getValue());
    if (integer == nullptr || !integer->getType()->isIntegerTy(bits)) {
      llvm::report_fatal_error("malformed vm bytecode anchor encoding: invalid integer operand");
    }
    return integer->getZExtValue();
  };
  const bytecode_anchor_encoding encoding{
      .stride = static_cast<std::uint32_t>(integer_operand(0, 32)),
      .bias = static_cast<std::uint32_t>(integer_operand(1, 32)),
      .mask_seed = integer_operand(2, 64)};
  validate_anchor_encoding(encoding, bytecode_anchor_length(anchor));
  return encoding;
}

std::uint32_t physical_bytecode_offset(const bytecode_anchor_encoding& encoding,
                                       std::uint32_t logical_offset,
                                       std::uint32_t length) {
  if (length == 0 || logical_offset >= length) {
    llvm::report_fatal_error("vm bytecode anchor logical offset is outside its payload");
  }
  return static_cast<std::uint32_t>(
      (static_cast<std::uint64_t>(logical_offset) * encoding.stride + encoding.bias) % length);
}

std::uint8_t bytecode_anchor_mask(const bytecode_anchor_encoding& encoding,
                                  std::uint32_t logical_offset) {
  return static_cast<std::uint8_t>(
      mix_seed(encoding.mask_seed, static_cast<std::uint64_t>(logical_offset) + 1));
}

std::uint64_t derive_vm_opaque_seed(std::uint64_t decision_seed,
                                    const llvm::Function& function,
                                    const bytecode_program& program) {
  std::uint64_t seed = stable_hash_string(function.getName());
  seed ^= static_cast<std::uint64_t>(program.instructions.size()) * 0x9e3779b97f4a7c15ULL;
  seed ^= static_cast<std::uint64_t>(program.slots.size()) << 32;
  if (decision_seed != 0) { seed = mix_seed(seed, decision_seed); }
  if (seed == 0) { seed = 0x6a09e667f3bcc909ULL; }

  return seed;
}

std::uint64_t derive_vm_return_key(std::uint64_t decision_seed,
                                   const llvm::Function& function,
                                   const bytecode_program& program) {
  return mix_seed(derive_vm_opaque_seed(decision_seed, function, program), 0xdeadbeefcafebabeULL);
}

llvm::Value* build_hidden_token_seed(llvm::IRBuilder<>& builder,
                                     llvm::Argument* hidden_token_arg,
                                     std::uint64_t canonical_seed,
                                     llvm::ArrayRef<std::uint64_t> valid_tokens,
                                     const mba::builder_context& mba_context,
                                     std::uint64_t salt,
                                     llvm::StringRef name) {
  if (hidden_token_arg == nullptr) { return builder.getInt64(canonical_seed); }

  llvm::Value* hidden_token = hidden_token_arg;
  if (hidden_token->getType() != builder.getInt64Ty()) {
    hidden_token =
        builder.CreateZExtOrTrunc(hidden_token, builder.getInt64Ty(), "obf.vm.token.cast");
  }

  llvm::Value* admitted = builder.getFalse();
  for (std::size_t token_index = 0; token_index < valid_tokens.size(); ++token_index) {
    llvm::Value* token_const =
        mba::create_opaque_integer(builder,
                                   builder.getInt64Ty(),
                                   mba_context,
                                   llvm::APInt(64, valid_tokens[token_index]),
                                   salt + static_cast<std::uint64_t>(token_index) * 8 + 1,
                                   (name + ".token").str());
    llvm::Value* match = builder.CreateICmpEQ(hidden_token, token_const, (name + ".match").str());
    admitted = builder.CreateOr(admitted, match, (name + ".admitted").str());
  }

  llvm::Function* function = builder.GetInsertBlock()->getParent();
  auto* admitted_block =
      llvm::BasicBlock::Create(builder.getContext(), "obf.vm.token.accept", function);
  auto* rejected_block =
      llvm::BasicBlock::Create(builder.getContext(), "obf.vm.token.reject", function);
  builder.CreateCondBr(admitted, admitted_block, rejected_block);

  llvm::IRBuilder<> rejected_builder(rejected_block);
  rejected_builder.CreateCall(
      llvm::Intrinsic::getOrInsertDeclaration(function->getParent(), llvm::Intrinsic::trap));
  rejected_builder.CreateUnreachable();

  // Only admitted callers can initialize the canonical bytecode state.
  builder.SetInsertPoint(admitted_block);
  return mba::create_opaque_integer(builder,
                                    builder.getInt64Ty(),
                                    mba_context,
                                    llvm::APInt(64, canonical_seed),
                                    salt + 2,
                                    name.empty() ? "obf.vm.token.seed" : name);
}

llvm::GlobalVariable* clone_bytecode_global_for_subhelper(llvm::GlobalVariable* bytecode_global,
                                                          std::uint32_t subhelper_index) {
  if (bytecode_global == nullptr) { return nullptr; }
  // The initializer and metadata remain paired even if the source was encoded already.
  (void)get_bytecode_anchor_encoding(*bytecode_global);
  return clone_bytecode_anchor(*bytecode_global,
                               bytecode_global->getName() + "_h" + llvm::Twine(subhelper_index));
}

std::uint32_t select_bytecode_anchor_real_count(std::uint64_t bytecode_size,
                                                std::uint64_t bytecode_seed,
                                                std::uint64_t salt) {
  if (bytecode_size < 48) { return 1; }

  std::uint32_t max_real_count = 4;
  if (bytecode_size < 160) {
    max_real_count = 2;
  } else if (bytecode_size < 512) {
    max_real_count = 3;
  } else {
    max_real_count = 8;
  }

  if (max_real_count <= 2) { return 2; }
  const std::uint64_t selector = mix_seed(bytecode_seed, 0x27100001ULL ^ salt);
  return 2U + static_cast<std::uint32_t>(selector % (max_real_count - 1U));
}

std::uint32_t select_bytecode_anchor_decoy_count(std::uint64_t bytecode_size,
                                                 std::uint64_t bytecode_seed,
                                                 std::uint64_t salt,
                                                 std::uint32_t real_count) {
  if (bytecode_size < 32 || real_count == 0) { return 0; }
  const std::uint32_t max_decoys = bytecode_size < 128 ? 1U : bytecode_size < 512 ? 3U : 8U;
  const std::uint64_t selector = mix_seed(bytecode_seed, 0x27200001ULL ^ salt);
  return 1U + static_cast<std::uint32_t>(selector % max_decoys);
}

llvm::SmallVector<llvm::GlobalVariable*, 8>
build_bytecode_anchor_globals(llvm::GlobalVariable* bytecode_global,
                              std::uint64_t bytecode_seed,
                              std::uint64_t salt,
                              std::uint32_t& out_real_count,
                              std::uint32_t& out_decoy_count) {
  llvm::SmallVector<llvm::GlobalVariable*, 8> anchors;
  out_real_count = 0;
  out_decoy_count = 0;
  if (bytecode_global == nullptr) { return anchors; }

  const std::uint32_t bytecode_size = bytecode_anchor_length(*bytecode_global);
  const std::vector<std::uint8_t> canonical =
      canonical_anchor_bytes(*bytecode_global, bytecode_size);
  llvm::Constant* canonical_initializer =
      llvm::ConstantDataArray::get(bytecode_global->getContext(), canonical);
  std::vector<std::uint8_t> physical(bytecode_size);
  llvm::SmallVector<llvm::Constant*, 17> used_initializers;
  // A fresh subhelper clone has no users. Reencode it, but never change a base
  // whose existing decoders already embed its physical offsets and masks.
  if (bytecode_global->getMetadata(anchor_encoding_metadata) == nullptr ||
      bytecode_global->use_empty()) {
    if (bytecode_global->getMetadata(anchor_encoding_metadata) != nullptr) {
      used_initializers.push_back(bytecode_global->getInitializer());
    }
    encode_bytecode_anchor(*bytecode_global,
                           canonical,
                           canonical_initializer,
                           physical,
                           used_initializers,
                           bytecode_seed,
                           salt,
                           0);
  } else {
    used_initializers.push_back(bytecode_global->getInitializer());
  }
  const std::uint32_t real_count =
      select_bytecode_anchor_real_count(bytecode_size, bytecode_seed, salt);
  const std::uint32_t decoy_count =
      select_bytecode_anchor_decoy_count(bytecode_size, bytecode_seed, salt ^ 0x100ULL, real_count);

  llvm::Module* module = bytecode_global->getParent();
  get_or_create_pointer_constant_cell(*module, *bytecode_global);

  llvm::SmallVector<llvm::GlobalVariable*, 4> real_clones;
  for (std::uint32_t anchor_index = 1; anchor_index < real_count; ++anchor_index) {
    const std::uint64_t name_seed =
        mix_seed(bytecode_seed, salt ^ (0x27110000ULL + static_cast<std::uint64_t>(anchor_index)));
    auto* clone = clone_bytecode_anchor(*bytecode_global,
                                        bytecode_global->getName() + "_a" +
                                            llvm::utohexstr(name_seed & 0xffffffffULL));
    encode_bytecode_anchor(*clone,
                           canonical,
                           canonical_initializer,
                           physical,
                           used_initializers,
                           bytecode_seed,
                           salt,
                           anchor_index);
    real_clones.push_back(clone);
    get_or_create_pointer_constant_cell(*module, *clone);
  }

  llvm::SmallVector<llvm::GlobalVariable*, 4> decoys;
  for (std::uint32_t slot = 0; slot < decoy_count; ++slot) {
    const std::uint64_t name_seed =
        mix_seed(bytecode_seed, salt ^ (0x27210000ULL + static_cast<std::uint64_t>(slot)));
    auto* decoy = clone_bytecode_anchor(*bytecode_global,
                                        bytecode_global->getName() + "_d" +
                                            llvm::utohexstr(name_seed & 0xffffffffULL));
    encode_bytecode_anchor(*decoy,
                           canonical,
                           canonical_initializer,
                           physical,
                           used_initializers,
                           bytecode_seed,
                           salt,
                           real_count + slot);
    decoys.push_back(decoy);
    get_or_create_pointer_constant_cell(*module, *decoy);
  }

  anchors.push_back(bytecode_global);
  for (std::uint32_t index = 0; index < std::max(real_clones.size(), decoys.size()); ++index) {
    if (index < decoys.size()) { anchors.push_back(decoys[index]); }
    if (index < real_clones.size()) { anchors.push_back(real_clones[index]); }
  }

  out_real_count = real_count;
  out_decoy_count = decoy_count;
  return anchors;
}

void annotate_bytecode_anchor_scattering(llvm::Function& function,
                                         std::uint32_t real_count,
                                         std::uint32_t decoy_count) {
  if (real_count > 1) { function.addFnAttr("vm.bytecode.anchor.scattered"); }
  if (decoy_count > 0) { function.addFnAttr("vm.bytecode.anchor.decoys"); }
  function.addFnAttr("vm.bytecode.anchor.count." + std::to_string(real_count + decoy_count));
  function.addFnAttr("vm.bytecode.anchor.real." + std::to_string(real_count));
  function.addFnAttr("vm.bytecode.anchor.decoy." + std::to_string(decoy_count));
}

vm_state_layout build_vm_state_layout(llvm::LLVMContext& context,
                                      llvm::Type* return_type,
                                      const bytecode_program& program) {
  vm_state_layout layout;
  llvm::SmallVector<llvm::Type*, 64> fields;
  fields.push_back(llvm::Type::getInt64Ty(context));
  fields.push_back(llvm::Type::getInt32Ty(context));
  fields.push_back(llvm::Type::getInt32Ty(context));
  fields.push_back(llvm::Type::getInt64Ty(context));
  if (!return_type->isVoidTy()) {
    layout.return_value_field = static_cast<std::uint32_t>(fields.size());
    fields.push_back(return_type);
  }

  layout.slot_fields.resize(program.slots.size());
  for (std::size_t slot_index = 0; slot_index < program.slots.size(); ++slot_index) {
    for (std::uint32_t cell_index = 0; cell_index < vm_slot_rotation_cell_count; ++cell_index) {
      layout.slot_fields[slot_index][cell_index] = static_cast<std::uint32_t>(fields.size());
      fields.push_back(const_cast<llvm::Type*>(program.slots[slot_index].type));
    }
  }

  layout.type = llvm::StructType::get(context, fields);
  return layout;
}

llvm::Value* create_state_field_ptr(llvm::IRBuilder<>& builder,
                                    const vm_state_layout& layout,
                                    llvm::Value* state_storage,
                                    std::uint32_t field_index,
                                    llvm::StringRef name) {
  return builder.CreateStructGEP(layout.type, state_storage, field_index, name);
}

slot_storage build_state_slot_storage(llvm::IRBuilder<>& builder,
                                      const vm_state_layout& layout,
                                      llvm::Value* state_storage,
                                      const bytecode_program& program,
                                      llvm::StringRef name_prefix) {
  slot_storage slots;
  slots.reserve(program.slots.size());
  for (std::size_t slot_index = 0; slot_index < program.slots.size(); ++slot_index) {
    slot_cells cells;
    cells.reserve(vm_slot_rotation_cell_count);
    for (std::uint32_t cell_index = 0; cell_index < vm_slot_rotation_cell_count; ++cell_index) {
      cells.push_back(create_state_field_ptr(
          builder,
          layout,
          state_storage,
          layout.slot_fields[slot_index][cell_index],
          (name_prefix + ".slot." + llvm::Twine(slot_index) + "." + llvm::Twine(cell_index))
              .str()));
    }
    slots.push_back(std::move(cells));
  }
  return slots;
}

llvm::Value* build_hidden_token_storage_value(llvm::IRBuilder<>& builder,
                                              llvm::Argument* hidden_token_arg,
                                              std::uint64_t fallback_seed) {
  if (hidden_token_arg == nullptr) { return builder.getInt64(fallback_seed); }
  llvm::Value* token = hidden_token_arg;
  if (token->getType() != builder.getInt64Ty()) {
    token = builder.CreateZExtOrTrunc(token, builder.getInt64Ty(), "obf.vm.island.token.cast");
  }
  return token;
}

std::uint64_t derive_vm_bytecode_seed(std::uint64_t decision_seed,
                                      const llvm::Function& function,
                                      const bytecode_program& program) {
  std::uint64_t seed = derive_vm_opaque_seed(decision_seed, function, program);
  seed = mix_seed(seed, 0x6eed0e9da4d94a4fULL);
  return seed == 0 ? 0x4f1bbcdc6762d5f1ULL : seed;
}

}  // namespace obf::vm
