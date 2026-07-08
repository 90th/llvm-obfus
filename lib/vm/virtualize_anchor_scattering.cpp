#include "obf/vm/internal/virtualize_anchor_scattering.h"

#include "obf/vm/virtualize_internal.h"

#include "llvm/ADT/StringExtras.h"
#include "llvm/IR/Constants.h"

#include <algorithm>
#include <string>

namespace obf::vm {

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

  llvm::Value* selected = mba::entangle_value(
      builder, hidden_token, mba_context, salt ^ 0xabcddcbaULL, (name + ".fallback").str());
  for (std::size_t token_index = 0; token_index < valid_tokens.size(); ++token_index) {
    llvm::Value* token_const =
        mba::create_opaque_integer(builder,
                                   builder.getInt64Ty(),
                                   mba_context,
                                   llvm::APInt(64, valid_tokens[token_index]),
                                   salt + static_cast<std::uint64_t>(token_index) * 8 + 1,
                                   (name + ".token").str());
    llvm::Value* seed_const =
        mba::create_opaque_integer(builder,
                                   builder.getInt64Ty(),
                                   mba_context,
                                   llvm::APInt(64, canonical_seed),
                                   salt + static_cast<std::uint64_t>(token_index) * 8 + 2,
                                   (name + ".seed").str());
    llvm::Value* match = builder.CreateICmpEQ(hidden_token, token_const, (name + ".match").str());
    selected = builder.CreateSelect(
        match, seed_const, selected, name.empty() ? "obf.vm.token.seed" : name);
  }

  return selected;
}

llvm::GlobalVariable* clone_bytecode_global_for_subhelper(llvm::GlobalVariable* bytecode_global,
                                                          std::uint32_t subhelper_index) {
  if (bytecode_global == nullptr) { return nullptr; }
  llvm::Module* module = bytecode_global->getParent();
  auto* clone = new llvm::GlobalVariable(*module,
                                         bytecode_global->getValueType(),
                                         true,
                                         llvm::GlobalValue::PrivateLinkage,
                                         bytecode_global->getInitializer(),
                                         bytecode_global->getName().str() + "_h" +
                                             std::to_string(subhelper_index));
  clone->setUnnamedAddr(llvm::GlobalValue::UnnamedAddr::Global);
  return clone;
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

  auto* array_type = llvm::dyn_cast<llvm::ArrayType>(bytecode_global->getValueType());
  if (array_type == nullptr || bytecode_global->getInitializer() == nullptr) {
    anchors.push_back(bytecode_global);
    out_real_count = 1;
    return anchors;
  }

  const std::uint64_t bytecode_size = array_type->getNumElements();
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
    auto* clone = new llvm::GlobalVariable(*module,
                                           bytecode_global->getValueType(),
                                           true,
                                           llvm::GlobalValue::PrivateLinkage,
                                           bytecode_global->getInitializer(),
                                           bytecode_global->getName().str() + "_a" +
                                               llvm::utohexstr(name_seed & 0xffffffffULL));
    clone->setUnnamedAddr(llvm::GlobalValue::UnnamedAddr::Global);
    real_clones.push_back(clone);
    get_or_create_pointer_constant_cell(*module, *clone);
  }

  llvm::SmallVector<llvm::GlobalVariable*, 4> decoys;
  const std::uint32_t interleave_count = std::max(real_count - 1U, decoy_count);
  for (std::uint32_t slot = 0; slot < interleave_count; ++slot) {
    if (slot < real_clones.size()) {
      if (slot < decoy_count) {
        const std::uint64_t name_seed =
            mix_seed(bytecode_seed, salt ^ (0x27210000ULL + static_cast<std::uint64_t>(slot)));
        auto* decoy = new llvm::GlobalVariable(*module,
                                               bytecode_global->getValueType(),
                                               true,
                                               llvm::GlobalValue::PrivateLinkage,
                                               bytecode_global->getInitializer(),
                                               bytecode_global->getName().str() + "_d" +
                                                   llvm::utohexstr(name_seed & 0xffffffffULL));
        decoy->setUnnamedAddr(llvm::GlobalValue::UnnamedAddr::Global);
        decoys.push_back(decoy);
        get_or_create_pointer_constant_cell(*module, *decoy);
      }
    } else if (slot < decoy_count) {
      const std::uint64_t name_seed =
          mix_seed(bytecode_seed, salt ^ (0x27210000ULL + static_cast<std::uint64_t>(slot)));
      auto* decoy = new llvm::GlobalVariable(*module,
                                             bytecode_global->getValueType(),
                                             true,
                                             llvm::GlobalValue::PrivateLinkage,
                                             bytecode_global->getInitializer(),
                                             bytecode_global->getName().str() + "_d" +
                                                 llvm::utohexstr(name_seed & 0xffffffffULL));
      decoy->setUnnamedAddr(llvm::GlobalValue::UnnamedAddr::Global);
      decoys.push_back(decoy);
      get_or_create_pointer_constant_cell(*module, *decoy);
    }
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
