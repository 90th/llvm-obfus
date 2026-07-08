#include "obf/plugin/internal/plugin_vm_resolvers.h"

#include "obf/plugin/internal/plugin_vm_binding_prep.h"

#include "obf/plugin/obfuscator_plugin_internal.h"

#include "obf/support/mba_config_builder.h"
#include "obf/support/stable_hash.h"
#include "obf/transforms/mba.h"

#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Intrinsics.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"

namespace obf {

vm_resolver_shape select_vm_resolver_shape(protection_level level) {
  if (level == protection_level::strong_vm) { return vm_resolver_shape::local_always_decode; }

  return vm_resolver_shape::cached_sentinel_global;
}

vm_seed_resolver_shape select_vm_seed_resolver_shape(protection_level level) {
  if (level == protection_level::strong_vm) {
    return vm_seed_resolver_shape::local_inline_resolver;
  }

  return vm_seed_resolver_shape::shared_switch_resolver;
}

vm_pointer_materialization_shape
select_vm_pointer_materialization_shape(protection_level level,
                                        unsigned bit_width,
                                        llvm::Function& interface_function,
                                        std::uint64_t seed_base,
                                        llvm::StringRef prefix) {
  std::uint64_t selector = stable_hash_string(interface_function.getName());
  selector = mix_vm_handshake_seed(selector, seed_base);
  selector = mix_vm_handshake_seed(selector, stable_hash_string(prefix));

  if (level == protection_level::strong_vm) {
    if (bit_width < 32) { return vm_pointer_materialization_shape::add_sub_bias; }
    switch (selector % 2) {
      case 0:
        return vm_pointer_materialization_shape::split_xor_chunks;
      case 1:
      default:
        return vm_pointer_materialization_shape::add_sub_bias;
    }
  }

  switch (selector % 3) {
    case 1:
      return vm_pointer_materialization_shape::split_xor_chunks;
    case 2:
      return vm_pointer_materialization_shape::add_sub_bias;
    case 0:
    default:
      return vm_pointer_materialization_shape::direct_ptrtoint;
  }
}

namespace {

llvm::Value* build_vm_target_token_mask(llvm::IRBuilder<>& builder,
                                        llvm::Function& owner,
                                        llvm::Value* hidden_token,
                                        llvm::IntegerType* ptr_int_type,
                                        const llvm::APInt& salt,
                                        llvm::StringRef name_prefix,
                                        std::uint64_t token_seed,
                                        std::uint64_t salt_base,
                                        std::uint32_t mba_depth) {
  llvm::Value* token_int = hidden_token;
  if (token_int->getType() != ptr_int_type) {
    token_int =
        builder.CreateZExtOrTrunc(token_int, ptr_int_type, name_prefix.str() + ".token.cast");
  }

  token_int = mba::entangle_value(
      builder,
      token_int,
      mba::builder_context{.entropy_anchor = mba::get_or_create_entropy_anchor(*owner.getParent()),
                           .seed_base = token_seed ^ salt.getLimitedValue(),
                           .depth = mba_depth},
      salt_base + token_seed,
      name_prefix.str() + ".token");
  auto* expected_token_const = llvm::ConstantInt::get(ptr_int_type,
                                                      llvm::APInt(ptr_int_type->getBitWidth(),
                                                                  token_seed,
                                                                  /*isSigned=*/false,
                                                                  /*implicitTrunc=*/true));
  auto* token_delta =
      builder.CreateXor(token_int, expected_token_const, name_prefix.str() + ".token.delta");
  auto* salt_const = llvm::ConstantInt::get(ptr_int_type, salt);
  return builder.CreateXor(token_delta, salt_const, name_prefix.str() + ".token.mask");
}

}  // namespace

llvm::Value* build_encoded_vm_target_value(llvm::IRBuilder<>& builder,
                                           std::uint64_t decision_seed,
                                           protection_level level,
                                           llvm::Function& owner,
                                           llvm::Function& interface_function,
                                           llvm::Function& implementation_function,
                                           llvm::GlobalVariable& target_seed_global,
                                           llvm::GlobalVariable& decode_key_global,
                                           llvm::Value* hidden_token,
                                           const llvm::APInt& key,
                                           const llvm::APInt& salt,
                                           llvm::StringRef prefix,
                                           vm_seed_resolver_shape seed_resolver_shape,
                                           std::uint64_t token_seed,
                                           std::uint64_t token_salt_base,
                                           std::uint32_t mba_depth) {
  auto* ptr_int_type = llvm::cast<llvm::IntegerType>(target_seed_global.getValueType());
  auto* resolve_key =
      builder.CreateLoad(ptr_int_type, &decode_key_global, prefix.str() + ".target.key");
  llvm::Value* target_int = decode_virtualized_target_seed(
      builder,
      decision_seed,
      level,
      owner,
      prefix,
      interface_function,
      implementation_function,
      target_seed_global,
      resolve_key,
      derive_vm_target_seed_mask(decision_seed, interface_function, ptr_int_type),
      seed_resolver_shape,
      token_seed,
      mba_depth);

  llvm::Value* token_mask = build_vm_target_token_mask(builder,
                                                       owner,
                                                       hidden_token,
                                                       ptr_int_type,
                                                       salt,
                                                       (prefix + ".target").str(),
                                                       token_seed,
                                                       token_salt_base,
                                                       mba_depth);
  llvm::Value* token_bound_key =
      builder.CreateXor(resolve_key, token_mask, prefix.str() + ".target.key.bound");
  return mba::create_xor(
      builder,
      target_int,
      token_bound_key,
      mba::builder_context{.entropy_anchor = mba::get_or_create_entropy_anchor(*owner.getParent()),
                           .seed_base = token_seed ^ key.getLimitedValue() ^ salt.getLimitedValue(),
                           .depth = mba_depth},
      token_salt_base + token_seed + 0x100ULL,
      prefix.str() + ".resolved");
}

llvm::Value* decode_encoded_vm_target_value(llvm::IRBuilder<>& builder,
                                            llvm::Function& owner,
                                            llvm::GlobalVariable& decode_key_global,
                                            llvm::Value* encoded_target,
                                            llvm::Value* hidden_token,
                                            const llvm::APInt& key,
                                            const llvm::APInt& salt,
                                            llvm::StringRef prefix,
                                            std::uint64_t token_seed,
                                            std::uint64_t decode_salt_base,
                                            std::uint32_t mba_depth) {
  auto* ptr_int_type = llvm::cast<llvm::IntegerType>(decode_key_global.getValueType());
  auto* opaque_key = builder.CreateLoad(ptr_int_type, &decode_key_global, prefix.str() + ".key");
  llvm::Value* token_mask = build_vm_target_token_mask(builder,
                                                       owner,
                                                       hidden_token,
                                                       ptr_int_type,
                                                       salt,
                                                       (prefix + ".decode").str(),
                                                       token_seed,
                                                       decode_salt_base,
                                                       mba_depth);
  llvm::Value* token_bound_key =
      builder.CreateXor(opaque_key, token_mask, prefix.str() + ".key.bound");
  return mba::create_xor(
      builder,
      encoded_target,
      token_bound_key,
      mba::builder_context{.entropy_anchor = mba::get_or_create_entropy_anchor(*owner.getParent()),
                           .seed_base = token_seed ^ key.getLimitedValue() ^ salt.getLimitedValue(),
                           .depth = mba_depth},
      decode_salt_base + token_seed + 0x100ULL,
      prefix.str() + ".decoded");
}

llvm::APInt derive_vm_target_key(std::uint64_t decision_seed,
                                 const llvm::Function& function,
                                 llvm::IntegerType* ptr_int_type) {
  std::uint64_t key_word = stable_hash_string(function.getName());
  key_word ^= static_cast<std::uint64_t>(ptr_int_type->getBitWidth()) << 32;
  if (decision_seed != 0) { key_word = mix_vm_handshake_seed(key_word, decision_seed); }
  return llvm::APInt(ptr_int_type->getBitWidth(),
                     key_word == 0 ? 0xa55aa55aULL : key_word,
                     /*isSigned=*/false,
                     /*implicitTrunc=*/true);
}

llvm::APInt derive_vm_target_sentinel(const llvm::APInt& key) { return ~key; }

llvm::APInt derive_vm_target_seed_mask(std::uint64_t decision_seed,
                                       const llvm::Function& function,
                                       llvm::IntegerType* ptr_int_type) {
  std::uint64_t mask_word = stable_hash_string(function.getName());
  mask_word = mix_vm_handshake_seed(
      mask_word, 0x7c6ef372fe94f82aULL ^ static_cast<std::uint64_t>(ptr_int_type->getBitWidth()));
  if (decision_seed != 0) { mask_word = mix_vm_handshake_seed(mask_word, decision_seed); }
  return llvm::APInt(ptr_int_type->getBitWidth(),
                     mask_word == 0 ? 0x6a09e667f3bcc909ULL : mask_word,
                     /*isSigned=*/false,
                     /*implicitTrunc=*/true);
}

std::uint64_t derive_vm_target_salt(std::uint64_t decision_seed, llvm::StringRef function_name) {
  std::uint64_t salt = stable_hash_string(function_name) * 0x9E3779B97F4A7C15ULL;
  if (decision_seed != 0) { salt = mix_vm_handshake_seed(salt, decision_seed); }
  return salt == 0 ? 0xC6EF3720ULL : salt;
}

llvm::GlobalVariable* get_or_create_vm_target_global(llvm::Function& function,
                                                     std::uint64_t decision_seed,
                                                     llvm::StringRef global_name) {
  llvm::Module* module = function.getParent();
  if (module == nullptr) { return nullptr; }

  auto* ptr_int_type = get_vm_pointer_int_type(function);
  if (ptr_int_type == nullptr) { return nullptr; }
  const llvm::APInt key = derive_vm_target_key(decision_seed, function, ptr_int_type);
  const llvm::APInt sentinel = derive_vm_target_sentinel(key);

  if (llvm::GlobalVariable* existing = module->getNamedGlobal(global_name)) { return existing; }

  auto* target_global = new llvm::GlobalVariable(*module,
                                                 ptr_int_type,
                                                 false,
                                                 llvm::GlobalValue::PrivateLinkage,
                                                 llvm::ConstantInt::get(ptr_int_type, sentinel),
                                                 global_name);
  return target_global;
}

llvm::GlobalVariable*
get_or_create_vm_target_seed_global(llvm::Function& interface_function,
                                    std::uint64_t decision_seed,
                                    llvm::Function& implementation_function,
                                    llvm::StringRef global_name,
                                    llvm::StringRef seed_case_function_name,
                                    llvm::IntegerType* ptr_int_type,
                                    vm_seed_resolver_shape seed_resolver_shape,
                                    std::uint32_t mba_depth) {
  llvm::Module* module = interface_function.getParent();
  if (module == nullptr) { return nullptr; }

  if (llvm::GlobalVariable* existing = module->getNamedGlobal(global_name)) {
    if (seed_resolver_shape == vm_seed_resolver_shape::shared_switch_resolver) {
      ensure_vm_target_seed_resolver_case(interface_function,
                                          decision_seed,
                                          implementation_function,
                                          seed_case_function_name,
                                          ptr_int_type,
                                          mba_depth);
    }
    return existing;
  }

  auto* target_seed_global = new llvm::GlobalVariable(*module,
                                                      ptr_int_type,
                                                      false,
                                                      llvm::GlobalValue::PrivateLinkage,
                                                      llvm::ConstantInt::get(ptr_int_type, 0),
                                                      global_name);
  target_seed_global->setDSOLocal(true);
  if (seed_resolver_shape == vm_seed_resolver_shape::shared_switch_resolver) {
    ensure_vm_target_seed_resolver_case(interface_function,
                                        decision_seed,
                                        implementation_function,
                                        seed_case_function_name,
                                        ptr_int_type,
                                        mba_depth);
  }

  llvm::Function* seed_init = get_or_create_vm_target_seed_init_function(*module);
  llvm::BasicBlock& entry_block = seed_init->getEntryBlock();
  llvm::IRBuilder<> builder(entry_block.getTerminator());

  llvm::Value* interface_int =
      builder.CreatePtrToInt(&interface_function, ptr_int_type, global_name.str() + ".iface");
  llvm::Value* share_base = builder.CreateXor(
      interface_int,
      llvm::ConstantInt::get(
          ptr_int_type,
          derive_vm_target_seed_mask(decision_seed, interface_function, ptr_int_type)),
      global_name.str() + ".base");
  builder.CreateStore(share_base, target_seed_global);
  return target_seed_global;
}

llvm::Function* get_or_create_vm_target_seed_init_function(llvm::Module& module) {
  constexpr llvm::StringRef init_name = "__obf_vm_seed_ctor";
  if (llvm::Function* existing = module.getFunction(init_name)) { return existing; }

  auto* init_type = llvm::FunctionType::get(llvm::Type::getVoidTy(module.getContext()), false);
  auto* init_function =
      llvm::Function::Create(init_type, llvm::GlobalValue::PrivateLinkage, init_name, module);
  init_function->setDSOLocal(true);

  llvm::BasicBlock* entry = llvm::BasicBlock::Create(module.getContext(), "entry", init_function);
  llvm::IRBuilder<> builder(entry);
  builder.CreateRetVoid();
  llvm::appendToGlobalCtors(module, init_function, 0);
  return init_function;
}

llvm::Function* get_or_create_vm_target_seed_resolver(llvm::Module& module,
                                                      llvm::IntegerType* ptr_int_type) {
  constexpr llvm::StringRef resolver_name = "__obf_vm_seed_resolve";
  if (llvm::Function* existing = module.getFunction(resolver_name)) { return existing; }

  auto* resolver_type =
      llvm::FunctionType::get(ptr_int_type, {ptr_int_type, ptr_int_type}, /*isVarArg=*/false);
  auto* resolver = llvm::Function::Create(
      resolver_type, llvm::GlobalValue::PrivateLinkage, resolver_name, module);
  resolver->setDSOLocal(true);
  resolver->addFnAttr(llvm::Attribute::NoInline);

  auto arg_it = resolver->arg_begin();
  llvm::Argument* key_arg = &*arg_it++;
  llvm::Argument* base_arg = &*arg_it;
  key_arg->setName("obf.target.key");
  base_arg->setName("obf.share.base");

  llvm::BasicBlock* entry = llvm::BasicBlock::Create(module.getContext(), "entry", resolver);
  llvm::BasicBlock* miss = llvm::BasicBlock::Create(module.getContext(), "miss", resolver);
  llvm::IRBuilder<> entry_builder(entry);
  entry_builder.CreateSwitch(key_arg, miss);

  llvm::IRBuilder<> miss_builder(miss);
  miss_builder.CreateUnreachable();
  return resolver;
}

llvm::Function* get_or_create_vm_target_seed_case_resolver(llvm::Function& interface_function,
                                                           std::uint64_t decision_seed,
                                                           llvm::Function& implementation_function,
                                                           llvm::StringRef resolver_name,
                                                           llvm::IntegerType* ptr_int_type,
                                                           std::uint32_t mba_depth) {
  llvm::Module* module = interface_function.getParent();
  if (module == nullptr) { return nullptr; }

  if (llvm::Function* existing = module->getFunction(resolver_name)) { return existing; }

  auto* resolver_type =
      llvm::FunctionType::get(ptr_int_type, {ptr_int_type, ptr_int_type}, /*isVarArg=*/false);
  auto* resolver = llvm::Function::Create(
      resolver_type, llvm::GlobalValue::PrivateLinkage, resolver_name, *module);
  resolver->setDSOLocal(true);
  resolver->addFnAttr(llvm::Attribute::NoInline);

  auto arg_it = resolver->arg_begin();
  llvm::Argument* key_arg = &*arg_it++;
  llvm::Argument* base_arg = &*arg_it;
  key_arg->setName("obf.target.key");
  base_arg->setName("obf.share.base");

  llvm::BasicBlock* entry = llvm::BasicBlock::Create(module->getContext(), "entry", resolver);
  llvm::IRBuilder<> builder(entry);
  const llvm::APInt key = derive_vm_target_key(decision_seed, interface_function, ptr_int_type);
  mba_config resolve_cfg;
  resolve_cfg.depth = mba_depth;
  auto resolve_context =
      obf::support::make_mba_context(*resolver,
                                     (interface_function.getName() + ".obf.seed").str(),
                                     key.getLimitedValue() ^ 0x63f000ULL,
                                     resolve_cfg);

  llvm::Value* target_int = builder.CreatePtrToInt(
      &implementation_function, ptr_int_type, interface_function.getName() + ".obf.seed.target");
  llvm::Value* masked_target =
      mba::create_xor(builder,
                      target_int,
                      key_arg,
                      resolve_context,
                      0x63f100ULL + key.getLimitedValue(),
                      (interface_function.getName() + ".obf.seed.target.masked").str());
  llvm::Value* resolved_target =
      mba::create_xor(builder,
                      masked_target,
                      key_arg,
                      resolve_context,
                      0x63f200ULL + key.getLimitedValue(),
                      (interface_function.getName() + ".obf.seed.target.real").str());
  llvm::Value* share_value =
      mba::create_add(builder,
                      resolved_target,
                      base_arg,
                      resolve_context,
                      0x63f300ULL + key.getLimitedValue(),
                      (interface_function.getName() + ".obf.seed.share").str());
  builder.CreateRet(share_value);
  return resolver;
}

void ensure_vm_target_seed_resolver_case(llvm::Function& interface_function,
                                         std::uint64_t decision_seed,
                                         llvm::Function& implementation_function,
                                         llvm::StringRef resolver_name,
                                         llvm::IntegerType* ptr_int_type,
                                         std::uint32_t mba_depth) {
  llvm::Module* module = interface_function.getParent();
  if (module == nullptr) { return; }

  llvm::Function* resolver = get_or_create_vm_target_seed_resolver(*module, ptr_int_type);
  auto* dispatch = llvm::dyn_cast<llvm::SwitchInst>(resolver->getEntryBlock().getTerminator());
  if (dispatch == nullptr) { llvm_unreachable("vm seed resolver missing dispatch switch"); }

  const llvm::APInt key = derive_vm_target_key(decision_seed, interface_function, ptr_int_type);
  auto* key_const = llvm::ConstantInt::get(ptr_int_type, key);
  llvm::Function* case_resolver =
      get_or_create_vm_target_seed_case_resolver(interface_function,
                                                 decision_seed,
                                                 implementation_function,
                                                 resolver_name,
                                                 ptr_int_type,
                                                 mba_depth);
  if (case_resolver == nullptr) { return; }
  for (const auto& entry : dispatch->cases()) {
    if (entry.getCaseValue()->getValue() == key) { return; }
  }

  llvm::BasicBlock* case_block =
      llvm::BasicBlock::Create(module->getContext(),
                               (interface_function.getName() + ".obf.seed.case").str(),
                               resolver,
                               dispatch->getDefaultDest());
  dispatch->addCase(llvm::cast<llvm::ConstantInt>(key_const), case_block);

  llvm::IRBuilder<> builder(case_block);
  llvm::Argument* key_arg = resolver->getArg(0);
  llvm::Argument* base_arg = resolver->getArg(1);
  llvm::Value* share_value =
      builder.CreateCall(case_resolver->getFunctionType(),
                         case_resolver,
                         {key_arg, base_arg},
                         (interface_function.getName() + ".obf.seed.share").str());
  builder.CreateRet(share_value);
}

llvm::GlobalVariable* get_or_create_vm_decode_key_global(llvm::Module& module,
                                                         llvm::IntegerType* ptr_int_type,
                                                         llvm::StringRef global_name,
                                                         const llvm::APInt& key) {
  if (auto* existing = module.getNamedGlobal(global_name)) { return existing; }

  return new llvm::GlobalVariable(module,
                                  ptr_int_type,
                                  /*isConstant=*/false,
                                  llvm::GlobalValue::PrivateLinkage,
                                  llvm::ConstantInt::get(ptr_int_type, key),
                                  global_name);
}

llvm::APInt derive_vm_pointer_materialization_mask(llvm::Function& interface_function,
                                                   llvm::IntegerType* ptr_int_type,
                                                   std::uint64_t seed_base,
                                                   llvm::StringRef prefix,
                                                   std::uint64_t salt) {
  std::uint64_t mask = stable_hash_string(interface_function.getName());
  mask = mix_vm_handshake_seed(mask, seed_base ^ salt);
  mask = mix_vm_handshake_seed(mask, stable_hash_string(prefix));
  if (mask == 0) { mask = 0x6a09e667f3bcc909ULL ^ salt; }

  return llvm::APInt(ptr_int_type->getBitWidth(),
                     mask,
                     /*isSigned=*/false,
                     /*implicitTrunc=*/true);
}

llvm::Value* materialize_vm_impl_pointer_int(llvm::IRBuilder<>& builder,
                                             std::uint64_t decision_seed,
                                             protection_level level,
                                             llvm::Function& owner,
                                             llvm::Function& interface_function,
                                             llvm::Function& implementation_function,
                                             llvm::IntegerType* ptr_int_type,
                                             llvm::Value* opaque_key,
                                             const mba::builder_context& context,
                                             std::uint64_t seed_base,
                                             llvm::StringRef prefix,
                                             vm_pointer_materialization_shape shape) {
  (void)owner;
  const unsigned bit_width = ptr_int_type->getBitWidth();
  if (shape == vm_pointer_materialization_shape::split_xor_chunks && bit_width < 32) {
    if (level == protection_level::strong_vm) {
      llvm_unreachable("strong_vm passed split_xor_chunks on <32 bit width");
      shape = vm_pointer_materialization_shape::add_sub_bias;
    } else {
      shape = vm_pointer_materialization_shape::direct_ptrtoint;
    }
  }

  const llvm::APInt key = derive_vm_target_key(decision_seed, interface_function, ptr_int_type);
  const std::string shape_prefix =
      (prefix + (shape == vm_pointer_materialization_shape::split_xor_chunks ? ".ptrmat.split"
                 : shape == vm_pointer_materialization_shape::add_sub_bias   ? ".ptrmat.addsub"
                                                                             : ".ptrmat.direct"))
          .str();
  llvm::Value* target_int =
      builder.CreatePtrToInt(&implementation_function, ptr_int_type, shape_prefix + ".target");

  llvm::Value* materialized_target = target_int;
  if (shape == vm_pointer_materialization_shape::split_xor_chunks) {
    const unsigned half_width = bit_width / 2;
    const llvm::APInt low_mask = llvm::APInt::getLowBitsSet(bit_width, half_width);
    const llvm::APInt mask_a = derive_vm_pointer_materialization_mask(
        interface_function, ptr_int_type, seed_base, prefix, 0x781100ULL);
    const llvm::APInt mask_b = derive_vm_pointer_materialization_mask(
        interface_function, ptr_int_type, seed_base, prefix, 0x781200ULL);

    llvm::Value* mask_a_const = llvm::ConstantInt::get(ptr_int_type, mask_a);
    llvm::Value* mask_b_const = llvm::ConstantInt::get(ptr_int_type, mask_b);
    llvm::Value* low_mask_const = llvm::ConstantInt::get(ptr_int_type, low_mask);
    llvm::Value* half_width_const = llvm::ConstantInt::get(ptr_int_type, half_width);

    llvm::Value* low_masked =
        builder.CreateAnd(builder.CreateXor(target_int, mask_a_const, shape_prefix + ".low.xor"),
                          low_mask_const,
                          shape_prefix + ".low");
    llvm::Value* high_masked = builder.CreateXor(
        builder.CreateLShr(target_int, half_width_const, shape_prefix + ".high.shift"),
        mask_b_const,
        shape_prefix + ".high");
    llvm::Value* low_real =
        builder.CreateXor(low_masked,
                          llvm::ConstantInt::get(ptr_int_type, mask_a & low_mask),
                          shape_prefix + ".low.real");
    llvm::Value* high_real =
        builder.CreateXor(high_masked, mask_b_const, shape_prefix + ".high.real");
    materialized_target = builder.CreateOr(
        builder.CreateShl(high_real, half_width_const, shape_prefix + ".join.high"),
        low_real,
        shape_prefix + ".real");
  } else if (shape == vm_pointer_materialization_shape::add_sub_bias) {
    llvm::APInt bias = derive_vm_pointer_materialization_mask(
        interface_function, ptr_int_type, seed_base, prefix, 0x782100ULL);
    if (bias.isZero()) {
      bias = llvm::APInt(ptr_int_type->getBitWidth(),
                         0x4f1bbcddULL,
                         /*isSigned=*/false,
                         /*implicitTrunc=*/true);
    }

    llvm::Value* bias_const = llvm::ConstantInt::get(ptr_int_type, bias);
    llvm::Value* biased = builder.CreateAdd(target_int, bias_const, shape_prefix + ".biased");
    materialized_target = builder.CreateSub(biased, bias_const, shape_prefix + ".real");
  }

  llvm::Value* masked_target = mba::create_xor(builder,
                                               materialized_target,
                                               opaque_key,
                                               context,
                                               0x63f100ULL + key.getLimitedValue(),
                                               shape_prefix + ".masked");
  return mba::create_xor(builder,
                         masked_target,
                         opaque_key,
                         context,
                         0x63f200ULL + key.getLimitedValue(),
                         shape_prefix + ".real.unmasked");
}

llvm::Value* decode_virtualized_target_seed_shared(llvm::IRBuilder<>& builder,
                                                   std::uint64_t /*decision_seed*/,
                                                   llvm::Function& owner,
                                                   llvm::StringRef prefix,
                                                   llvm::GlobalVariable& target_seed_global,
                                                   llvm::Value* opaque_key,
                                                   const llvm::APInt& seed_mask,
                                                   std::uint64_t seed_base,
                                                   std::uint32_t mba_depth) {
  auto* ptr_int_type = llvm::cast<llvm::IntegerType>(target_seed_global.getValueType());
  auto* encoded_base =
      builder.CreateLoad(ptr_int_type, &target_seed_global, prefix.str() + ".target.seed.base");
  mba::builder_context decode_context{.entropy_anchor =
                                          mba::get_or_create_entropy_anchor(*owner.getParent()),
                                      .seed_base = seed_base ^ seed_mask.getLimitedValue(),
                                      .depth = mba_depth};
  llvm::Value* masked_base = mba::create_xor(builder,
                                             encoded_base,
                                             opaque_key,
                                             decode_context,
                                             0x604000ULL + seed_base,
                                             prefix.str() + ".target.base.masked");
  llvm::Value* real_base = mba::create_xor(builder,
                                           masked_base,
                                           opaque_key,
                                           decode_context,
                                           0x605000ULL + seed_base,
                                           prefix.str() + ".target.base");
  llvm::Function* resolver =
      get_or_create_vm_target_seed_resolver(*owner.getParent(), ptr_int_type);
  auto* share_value = builder.CreateCall(resolver->getFunctionType(),
                                         resolver,
                                         {opaque_key, real_base},
                                         prefix.str() + ".target.seed.value");
  llvm::Value* masked_value = mba::create_xor(builder,
                                              share_value,
                                              opaque_key,
                                              decode_context,
                                              0x606000ULL + seed_base,
                                              prefix.str() + ".target.value.masked");
  llvm::Value* real_value = mba::create_xor(builder,
                                            masked_value,
                                            opaque_key,
                                            decode_context,
                                            0x607000ULL + seed_base,
                                            prefix.str() + ".target.value");
  return builder.CreateSub(real_value, real_base, prefix.str() + ".real.int");
}

llvm::Value* decode_virtualized_target_seed_local(llvm::IRBuilder<>& builder,
                                                  std::uint64_t decision_seed,
                                                  protection_level level,
                                                  llvm::Function& owner,
                                                  llvm::Function& interface_function,
                                                  llvm::Function& implementation_function,
                                                  llvm::StringRef prefix,
                                                  llvm::GlobalVariable& target_seed_global,
                                                  llvm::Value* opaque_key,
                                                  const llvm::APInt& seed_mask,
                                                  std::uint64_t seed_base,
                                                  std::uint32_t mba_depth) {
  auto* ptr_int_type = llvm::cast<llvm::IntegerType>(target_seed_global.getValueType());
  auto* encoded_base =
      builder.CreateLoad(ptr_int_type, &target_seed_global, prefix.str() + ".target.seed.base");
  mba::builder_context decode_context{.entropy_anchor =
                                          mba::get_or_create_entropy_anchor(*owner.getParent()),
                                      .seed_base = seed_base ^ seed_mask.getLimitedValue(),
                                      .depth = mba_depth};
  llvm::Value* masked_base = mba::create_xor(builder,
                                             encoded_base,
                                             opaque_key,
                                             decode_context,
                                             0x604000ULL + seed_base,
                                             prefix.str() + ".target.base.masked");
  llvm::Value* real_base = mba::create_xor(builder,
                                           masked_base,
                                           opaque_key,
                                           decode_context,
                                           0x605000ULL + seed_base,
                                           prefix.str() + ".target.base");

  const llvm::APInt key = derive_vm_target_key(decision_seed, interface_function, ptr_int_type);
  mba_config resolve_cfg;
  resolve_cfg.depth = mba_depth;
  auto resolve_context =
      obf::support::make_mba_context(owner,
                                     (prefix + ".target.local.seed").str(),
                                     key.getLimitedValue() ^ seed_base ^ 0x63f000ULL,
                                     resolve_cfg);
  const vm_pointer_materialization_shape pointer_shape = select_vm_pointer_materialization_shape(
      level, ptr_int_type->getBitWidth(), interface_function, seed_base, prefix);
  llvm::Value* resolved_target = materialize_vm_impl_pointer_int(builder,
                                                                 decision_seed,
                                                                 level,
                                                                 owner,
                                                                 interface_function,
                                                                 implementation_function,
                                                                 ptr_int_type,
                                                                 opaque_key,
                                                                 resolve_context,
                                                                 seed_base,
                                                                 prefix.str() + ".target.seed",
                                                                 pointer_shape);
  llvm::Value* share_value = mba::create_add(builder,
                                             resolved_target,
                                             real_base,
                                             resolve_context,
                                             0x63f300ULL + key.getLimitedValue(),
                                             prefix.str() + ".target.seed.value");
  llvm::Value* masked_value = mba::create_xor(builder,
                                              share_value,
                                              opaque_key,
                                              decode_context,
                                              0x606000ULL + seed_base,
                                              prefix.str() + ".target.value.masked");
  llvm::Value* real_value = mba::create_xor(builder,
                                            masked_value,
                                            opaque_key,
                                            decode_context,
                                            0x607000ULL + seed_base,
                                            prefix.str() + ".target.value");
  return builder.CreateSub(real_value, real_base, prefix.str() + ".real.int");
}

llvm::Value* decode_virtualized_target_seed(llvm::IRBuilder<>& builder,
                                            std::uint64_t decision_seed,
                                            protection_level level,
                                            llvm::Function& owner,
                                            llvm::StringRef prefix,
                                            llvm::Function& interface_function,
                                            llvm::Function& implementation_function,
                                            llvm::GlobalVariable& target_seed_global,
                                            llvm::Value* opaque_key,
                                            const llvm::APInt& seed_mask,
                                            vm_seed_resolver_shape seed_resolver_shape,
                                            std::uint64_t seed_base,
                                            std::uint32_t mba_depth) {
  if (seed_resolver_shape == vm_seed_resolver_shape::local_inline_resolver) {
    return decode_virtualized_target_seed_local(builder,
                                                decision_seed,
                                                level,
                                                owner,
                                                interface_function,
                                                implementation_function,
                                                prefix,
                                                target_seed_global,
                                                opaque_key,
                                                seed_mask,
                                                seed_base,
                                                mba_depth);
  }

  return decode_virtualized_target_seed_shared(builder,
                                               decision_seed,
                                               owner,
                                               prefix,
                                               target_seed_global,
                                               opaque_key,
                                               seed_mask,
                                               seed_base,
                                               mba_depth);
}

llvm::Value* decode_virtualized_integer_return(llvm::IRBuilder<>& builder,
                                               llvm::Function& owner,
                                               llvm::StringRef callee_name,
                                               llvm::StringRef retkey_global_name,
                                               llvm::Value* encoded_ret,
                                               llvm::Value* hidden_token,
                                               std::uint64_t token_seed,
                                               std::uint32_t mba_depth) {
  llvm::Module* module = owner.getParent();
  if (module == nullptr || !encoded_ret->getType()->isIntegerTy()) { return encoded_ret; }

  llvm::GlobalVariable* retkey_global = module->getNamedGlobal(retkey_global_name);
  if (retkey_global == nullptr) { return encoded_ret; }

  auto* retkey_load =
      builder.CreateLoad(builder.getInt64Ty(), retkey_global, callee_name.str() + ".obf.retkey");
  llvm::Value* token_for_ret = hidden_token;
  if (token_for_ret->getType() != builder.getInt64Ty()) {
    token_for_ret = builder.CreateZExtOrTrunc(
        token_for_ret, builder.getInt64Ty(), callee_name.str() + ".obf.rettoken.cast");
  }

  llvm::Value* token_bound_retkey = mba::create_xor(
      builder,
      retkey_load,
      token_for_ret,
      mba::builder_context{.entropy_anchor = mba::get_or_create_entropy_anchor(*module),
                           .seed_base = token_seed ^ 0x731000ULL,
                           .depth = mba_depth},
      0x731000ULL + token_seed,
      (callee_name + ".obf.retkey.bound").str());
  llvm::Value* retkey_cast = token_bound_retkey;
  if (encoded_ret->getType() != builder.getInt64Ty()) {
    retkey_cast = builder.CreateZExtOrTrunc(
        token_bound_retkey, encoded_ret->getType(), callee_name.str() + ".obf.retkey.cast");
  }

  mba::builder_context decode_context = mba::get_or_create_builder_context(
      owner, (callee_name + ".obf.ret").str(), token_seed ^ 0x730000ULL);
  decode_context.depth = mba_depth;
  return mba::create_xor(builder,
                         encoded_ret,
                         retkey_cast,
                         decode_context,
                         0x730000ULL + token_seed,
                         (callee_name + ".obf.retdec").str());
}

}  // namespace obf
