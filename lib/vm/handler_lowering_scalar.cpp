#include "obf/vm/virtualize_internal.h"

#include "llvm/IR/Constants.h"

namespace obf::vm {

namespace {

bool is_binary_opcode(opcode op) {
  switch (op) {
  case opcode::add:
  case opcode::sub:
  case opcode::mul:
  case opcode::udiv:
  case opcode::sdiv:
  case opcode::urem:
  case opcode::srem:
  case opcode::shl:
  case opcode::lshr:
  case opcode::ashr:
  case opcode::and_op:
  case opcode::or_op:
  case opcode::xor_op:
  case opcode::fadd:
  case opcode::fsub:
  case opcode::fmul:
  case opcode::fdiv:
  case opcode::frem:
    return true;
  default:
    return false;
  }
}

bool is_polymorphic_integer_binary_opcode(opcode op) {
  switch (op) {
  case opcode::add:
  case opcode::sub:
  case opcode::and_op:
  case opcode::or_op:
  case opcode::xor_op:
    return true;
  default:
    return false;
  }
}

llvm::StringRef scalar_shape_marker(scalar_handler_shape shape) {
  switch (shape) {
  case scalar_handler_shape::direct:
    return "vm.handler.shape.direct";
  case scalar_handler_shape::temp_slot_roundtrip:
    return "vm.handler.shape.temp";
  case scalar_handler_shape::mba_neutralized:
    return "vm.handler.shape.neutral";
  }
  llvm_unreachable("unknown scalar handler shape");
}

llvm::AllocaInst *create_handler_temp_slot(llvm::IRBuilder<> &builder,
                                           llvm::Type *type,
                                           llvm::StringRef name) {
  llvm::BasicBlock *block = builder.GetInsertBlock();
  llvm::Function *function = block != nullptr ? block->getParent() : nullptr;
  if (function == nullptr || type == nullptr) {
    return nullptr;
  }

  llvm::BasicBlock &entry_block = function->getEntryBlock();
  llvm::IRBuilder<> entry_builder(&entry_block, entry_block.begin());
  return entry_builder.CreateAlloca(type, nullptr, name);
}

llvm::BinaryOperator *emit_plain_integer_binary(llvm::IRBuilder<> &builder,
                                                opcode op, llvm::Value *lhs,
                                                llvm::Value *rhs,
                                                llvm::StringRef name) {
  switch (op) {
  case opcode::add:
    return llvm::cast<llvm::BinaryOperator>(builder.CreateAdd(lhs, rhs, name));
  case opcode::sub:
    return llvm::cast<llvm::BinaryOperator>(builder.CreateSub(lhs, rhs, name));
  case opcode::and_op:
    return llvm::cast<llvm::BinaryOperator>(builder.CreateAnd(lhs, rhs, name));
  case opcode::or_op:
    return llvm::cast<llvm::BinaryOperator>(builder.CreateOr(lhs, rhs, name));
  case opcode::xor_op:
    return llvm::cast<llvm::BinaryOperator>(builder.CreateXor(lhs, rhs, name));
  default:
    llvm_unreachable("opcode is not a polymorphic integer binary opcode");
  }
}

llvm::Value *emit_current_integer_binary(llvm::IRBuilder<> &builder, opcode op,
                                         llvm::Value *lhs, llvm::Value *rhs,
                                         std::uint32_t flags,
                                         const mba::builder_context &mba_context,
                                         std::uint64_t salt,
                                         llvm::Instruction *&flag_target,
                                         llvm::StringRef name) {
  flag_target = nullptr;
  switch (op) {
  case opcode::add:
    if (!has_instruction_flag(flags, instruction_flag_nsw) &&
        !has_instruction_flag(flags, instruction_flag_nuw)) {
      return mba::create_add(builder, lhs, rhs, mba_context, salt + 3, name);
    }
    flag_target = emit_plain_integer_binary(builder, op, lhs, rhs, name);
    return flag_target;
  case opcode::sub:
    if (!has_instruction_flag(flags, instruction_flag_nsw) &&
        !has_instruction_flag(flags, instruction_flag_nuw)) {
      return mba::create_sub(builder, lhs, rhs, mba_context, salt + 4, name);
    }
    flag_target = emit_plain_integer_binary(builder, op, lhs, rhs, name);
    return flag_target;
  case opcode::xor_op:
    return mba::create_xor(builder, lhs, rhs, mba_context, salt + 5, name);
  case opcode::and_op:
  case opcode::or_op:
    flag_target = emit_plain_integer_binary(builder, op, lhs, rhs, name);
    return flag_target;
  default:
    llvm_unreachable("opcode is not a polymorphic integer binary opcode");
  }
}

void apply_integer_binary_flags(llvm::Instruction *instruction,
                                std::uint32_t flags) {
  if (instruction == nullptr) {
    return;
  }
  auto *binary = llvm::dyn_cast<llvm::BinaryOperator>(instruction);
  if (binary == nullptr) {
    return;
  }
  if (has_instruction_flag(flags, instruction_flag_nsw)) {
    binary->setHasNoSignedWrap();
  }
  if (has_instruction_flag(flags, instruction_flag_nuw)) {
    binary->setHasNoUnsignedWrap();
  }
}

llvm::Value *apply_scalar_handler_shape(llvm::IRBuilder<> &builder,
                                        scalar_handler_shape shape,
                                        llvm::Value *result) {
  if (result == nullptr || !result->getType()->isIntegerTy()) {
    return result;
  }

  const llvm::StringRef marker = scalar_shape_marker(shape);
  if (shape == scalar_handler_shape::direct) {
    if (result->hasName()) {
      result->setName(marker);
    }
    return result;
  }

  if (shape == scalar_handler_shape::temp_slot_roundtrip) {
    llvm::AllocaInst *temp = create_handler_temp_slot(builder, result->getType(), marker);
    if (temp == nullptr) {
      return result;
    }
    builder.CreateStore(result, temp);
    return builder.CreateLoad(result->getType(), temp, marker);
  }

  auto *integer_type = llvm::cast<llvm::IntegerType>(result->getType());
  return builder.CreateXor(result, llvm::ConstantInt::get(integer_type, 0), marker);
}

bool is_cast_opcode(opcode op) {
  switch (op) {
  case opcode::trunc:
  case opcode::zext:
  case opcode::sext:
  case opcode::fp_trunc:
  case opcode::fp_ext:
  case opcode::ui_to_fp:
  case opcode::si_to_fp:
  case opcode::fp_to_ui:
  case opcode::fp_to_si:
  case opcode::ptr_to_int:
  case opcode::int_to_ptr:
  case opcode::bitcast:
  case opcode::addrspace_cast:
    return true;
  default:
    return false;
  }
}

bool is_icmp_opcode(opcode op) {
  switch (op) {
  case opcode::icmp_eq:
  case opcode::icmp_ne:
  case opcode::icmp_ugt:
  case opcode::icmp_uge:
  case opcode::icmp_ult:
  case opcode::icmp_ule:
  case opcode::icmp_sgt:
  case opcode::icmp_sge:
  case opcode::icmp_slt:
  case opcode::icmp_sle:
    return true;
  default:
    return false;
  }
}

bool is_fcmp_opcode(opcode op) {
  switch (op) {
  case opcode::fcmp_false:
  case opcode::fcmp_oeq:
  case opcode::fcmp_ogt:
  case opcode::fcmp_oge:
  case opcode::fcmp_olt:
  case opcode::fcmp_ole:
  case opcode::fcmp_one:
  case opcode::fcmp_ord:
  case opcode::fcmp_uno:
  case opcode::fcmp_ueq:
  case opcode::fcmp_ugt:
  case opcode::fcmp_uge:
  case opcode::fcmp_ult:
  case opcode::fcmp_ule:
  case opcode::fcmp_une:
  case opcode::fcmp_true:
    return true;
  default:
    return false;
  }
}

llvm::CmpInst::Predicate icmp_predicate_for_opcode(opcode op) {
  if (!is_icmp_opcode(op)) {
    llvm_unreachable("opcode is not an icmp predicate");
  }

  switch (op) {
  case opcode::icmp_eq:
    return llvm::CmpInst::ICMP_EQ;
  case opcode::icmp_ne:
    return llvm::CmpInst::ICMP_NE;
  case opcode::icmp_ugt:
    return llvm::CmpInst::ICMP_UGT;
  case opcode::icmp_uge:
    return llvm::CmpInst::ICMP_UGE;
  case opcode::icmp_ult:
    return llvm::CmpInst::ICMP_ULT;
  case opcode::icmp_ule:
    return llvm::CmpInst::ICMP_ULE;
  case opcode::icmp_sgt:
    return llvm::CmpInst::ICMP_SGT;
  case opcode::icmp_sge:
    return llvm::CmpInst::ICMP_SGE;
  case opcode::icmp_slt:
    return llvm::CmpInst::ICMP_SLT;
  case opcode::icmp_sle:
    return llvm::CmpInst::ICMP_SLE;
  default:
    llvm_unreachable("opcode is not an icmp predicate");
  }
}

llvm::CmpInst::Predicate fcmp_predicate_for_opcode(opcode op) {
  if (!is_fcmp_opcode(op)) {
    llvm_unreachable("opcode is not an fcmp predicate");
  }

  switch (op) {
  case opcode::fcmp_false:
    return llvm::CmpInst::FCMP_FALSE;
  case opcode::fcmp_oeq:
    return llvm::CmpInst::FCMP_OEQ;
  case opcode::fcmp_ogt:
    return llvm::CmpInst::FCMP_OGT;
  case opcode::fcmp_oge:
    return llvm::CmpInst::FCMP_OGE;
  case opcode::fcmp_olt:
    return llvm::CmpInst::FCMP_OLT;
  case opcode::fcmp_ole:
    return llvm::CmpInst::FCMP_OLE;
  case opcode::fcmp_one:
    return llvm::CmpInst::FCMP_ONE;
  case opcode::fcmp_ord:
    return llvm::CmpInst::FCMP_ORD;
  case opcode::fcmp_uno:
    return llvm::CmpInst::FCMP_UNO;
  case opcode::fcmp_ueq:
    return llvm::CmpInst::FCMP_UEQ;
  case opcode::fcmp_ugt:
    return llvm::CmpInst::FCMP_UGT;
  case opcode::fcmp_uge:
    return llvm::CmpInst::FCMP_UGE;
  case opcode::fcmp_ult:
    return llvm::CmpInst::FCMP_ULT;
  case opcode::fcmp_ule:
    return llvm::CmpInst::FCMP_ULE;
  case opcode::fcmp_une:
    return llvm::CmpInst::FCMP_UNE;
  case opcode::fcmp_true:
    return llvm::CmpInst::FCMP_TRUE;
  default:
    llvm_unreachable("opcode is not an fcmp predicate");
  }
}

llvm::Value *emit_integer_nonzero_test(
    llvm::IRBuilder<> &builder, llvm::Value *value,
    const mba::builder_context &mba_context, std::uint64_t salt) {
  auto *integer_type = llvm::cast<llvm::IntegerType>(value->getType());
  llvm::Value *negated = mba::create_sub(
      builder, llvm::ConstantInt::get(integer_type, 0), value, mba_context,
      salt + 1, "obf.vm.icmp.nz.neg");
  llvm::Value *combined = builder.CreateOr(value, negated, "obf.vm.icmp.nz.or");
  llvm::Value *top_bit = builder.CreateLShr(
      combined,
      llvm::ConstantInt::get(integer_type, integer_type->getBitWidth() - 1),
      "obf.vm.icmp.nz.sh");
  return builder.CreateTrunc(top_bit, builder.getInt1Ty(), "obf.vm.icmp.nz");
}

llvm::Value *emit_integer_unsigned_lt(
    llvm::IRBuilder<> &builder, llvm::Value *lhs, llvm::Value *rhs,
    const mba::builder_context &mba_context, std::uint64_t salt) {
  auto *integer_type = llvm::cast<llvm::IntegerType>(lhs->getType());
  auto *wide_type = llvm::IntegerType::get(builder.getContext(),
                                           integer_type->getBitWidth() + 1);
  llvm::Value *lhs_ext = builder.CreateZExt(lhs, wide_type, "obf.vm.icmp.ult.lhs");
  llvm::Value *rhs_ext = builder.CreateZExt(rhs, wide_type, "obf.vm.icmp.ult.rhs");
  llvm::Value *diff = mba::create_sub(builder, lhs_ext, rhs_ext, mba_context,
                                      salt + 1, "obf.vm.icmp.ult.diff");
  llvm::Value *borrow = builder.CreateLShr(
      diff, llvm::ConstantInt::get(wide_type, integer_type->getBitWidth()),
      "obf.vm.icmp.ult.borrow");
  return builder.CreateTrunc(borrow, builder.getInt1Ty(), "obf.vm.icmp.ult");
}

llvm::Value *emit_integer_icmp(llvm::IRBuilder<> &builder, opcode predicate,
                               llvm::Value *lhs, llvm::Value *rhs,
                               const mba::builder_context &mba_context,
                               std::uint64_t salt) {
  auto *integer_type = llvm::cast<llvm::IntegerType>(lhs->getType());
  llvm::Value *result = nullptr;
  switch (predicate) {
  case opcode::icmp_eq:
  case opcode::icmp_ne: {
    llvm::Value *difference = mba::create_xor(builder, lhs, rhs, mba_context,
                                              salt + 1, "obf.vm.icmp.eq.diff");
    llvm::Value *nonzero = emit_integer_nonzero_test(builder, difference,
                                                     mba_context, salt + 2);
    result = predicate == opcode::icmp_ne
                 ? nonzero
                 : builder.CreateXor(nonzero, builder.getTrue(), "obf.vm.icmp.eq");
    break;
  }
  case opcode::icmp_ult:
    result = emit_integer_unsigned_lt(builder, lhs, rhs, mba_context, salt + 3);
    break;
  case opcode::icmp_ugt:
    result = emit_integer_unsigned_lt(builder, rhs, lhs, mba_context, salt + 4);
    break;
  case opcode::icmp_ule:
    result = builder.CreateXor(
        emit_integer_unsigned_lt(builder, rhs, lhs, mba_context, salt + 5),
        builder.getTrue(), "obf.vm.icmp.ule");
    break;
  case opcode::icmp_uge:
    result = builder.CreateXor(
        emit_integer_unsigned_lt(builder, lhs, rhs, mba_context, salt + 6),
        builder.getTrue(), "obf.vm.icmp.uge");
    break;
  case opcode::icmp_slt:
  case opcode::icmp_sgt:
  case opcode::icmp_sle:
  case opcode::icmp_sge: {
    llvm::Constant *sign_mask = llvm::ConstantInt::get(
        integer_type, llvm::APInt::getSignMask(integer_type->getBitWidth()));
    llvm::Value *lhs_biased = mba::create_xor(builder, lhs, sign_mask,
                                              mba_context, salt + 7,
                                              "obf.vm.icmp.signed.lhs");
    llvm::Value *rhs_biased = mba::create_xor(builder, rhs, sign_mask,
                                              mba_context, salt + 8,
                                              "obf.vm.icmp.signed.rhs");
    switch (predicate) {
    case opcode::icmp_slt:
      result = emit_integer_unsigned_lt(builder, lhs_biased, rhs_biased,
                                        mba_context, salt + 9);
      break;
    case opcode::icmp_sgt:
      result = emit_integer_unsigned_lt(builder, rhs_biased, lhs_biased,
                                        mba_context, salt + 10);
      break;
    case opcode::icmp_sle:
      result = builder.CreateXor(
          emit_integer_unsigned_lt(builder, rhs_biased, lhs_biased,
                                   mba_context, salt + 11),
          builder.getTrue(), "obf.vm.icmp.sle");
      break;
    case opcode::icmp_sge:
      result = builder.CreateXor(
          emit_integer_unsigned_lt(builder, lhs_biased, rhs_biased,
                                   mba_context, salt + 12),
          builder.getTrue(), "obf.vm.icmp.sge");
      break;
    default:
      llvm_unreachable("unexpected signed integer compare predicate");
    }
    break;
  }
  default:
    llvm_unreachable("opcode is not a scalar integer compare predicate");
  }

  return result;
}

llvm::Value *emit_integer_sign_recovery(llvm::IRBuilder<> &builder,
                                        llvm::Value *widened_value,
                                        unsigned source_bit_width,
                                        llvm::StringRef name_prefix) {
  auto *destination_type = llvm::cast<llvm::IntegerType>(widened_value->getType());
  if (source_bit_width >= destination_type->getBitWidth()) {
    return widened_value;
  }

  llvm::Value *shift_amount = llvm::ConstantInt::get(
      destination_type, destination_type->getBitWidth() - source_bit_width);
  llvm::Value *shifted =
      builder.CreateShl(widened_value, shift_amount, (name_prefix + ".shl").str());
  return builder.CreateAShr(shifted, shift_amount, name_prefix);
}

llvm::Value *emit_integer_zext(llvm::IRBuilder<> &builder, llvm::Value *operand,
                               llvm::IntegerType *destination_type,
                               const mba::builder_context &mba_context,
                               std::uint64_t salt) {
  auto *source_type = llvm::cast<llvm::IntegerType>(operand->getType());
  llvm::Constant *source_bias = llvm::ConstantInt::get(
      source_type,
      llvm::APInt::getOneBitSet(source_type->getBitWidth(),
                                source_type->getBitWidth() - 1));
  llvm::Value *biased = mba::create_xor(builder, operand, source_bias, mba_context,
                                        salt + 1, "obf.vm.zext.bias");
  llvm::Value *widened = builder.CreateZExt(biased, destination_type,
                                            "obf.vm.zext.wide");
  widened = mba::create_xor(builder, widened,
                            llvm::ConstantInt::get(destination_type, 0),
                            mba_context, salt + 2, "obf.vm.zext.mix");
  llvm::Value *signed_value = emit_integer_sign_recovery(
      builder, widened, source_type->getBitWidth(), "obf.vm.zext.signed");
  llvm::Constant *destination_bias = llvm::ConstantInt::get(
      destination_type,
      llvm::APInt::getOneBitSet(destination_type->getBitWidth(),
                                source_type->getBitWidth() - 1));
  return mba::create_add(builder, signed_value, destination_bias, mba_context,
                         salt + 3, "obf.vm.zext");
}

llvm::Value *emit_integer_sext(llvm::IRBuilder<> &builder, llvm::Value *operand,
                               llvm::IntegerType *destination_type,
                               const mba::builder_context &mba_context,
                               std::uint64_t salt) {
  auto *source_type = llvm::cast<llvm::IntegerType>(operand->getType());
  llvm::Value *widened = builder.CreateZExt(operand, destination_type,
                                            "obf.vm.sext.wide");
  widened = mba::create_xor(builder, widened,
                            llvm::ConstantInt::get(destination_type, 0),
                            mba_context, salt + 1, "obf.vm.sext.mix");
  return emit_integer_sign_recovery(builder, widened, source_type->getBitWidth(),
                                    "obf.vm.sext");
}

llvm::Value *emit_integer_trunc(llvm::IRBuilder<> &builder, llvm::Value *operand,
                                llvm::IntegerType *destination_type,
                                const mba::builder_context &mba_context,
                                std::uint64_t salt) {
  auto *source_type = llvm::cast<llvm::IntegerType>(operand->getType());
  llvm::Value *masked = builder.CreateAnd(
      operand,
      llvm::ConstantInt::get(
          source_type,
          llvm::APInt::getLowBitsSet(source_type->getBitWidth(),
                                     destination_type->getBitWidth())),
      "obf.vm.trunc.mask");
  if (destination_type->isIntegerTy(1)) {
    masked = mba::create_xor(builder, masked,
                             llvm::ConstantInt::get(source_type, 0), mba_context,
                             salt + 1, "obf.vm.trunc.mix");
    return emit_integer_nonzero_test(builder, masked, mba_context, salt + 2);
  }

  return builder.CreateTrunc(masked, destination_type, "obf.vm.trunc");
}

llvm::Value *emit_integer_cast(llvm::IRBuilder<> &builder, opcode cast_opcode,
                               llvm::Value *operand,
                               llvm::Type *destination_type,
                               const mba::builder_context &mba_context,
                               std::uint64_t salt) {
  auto *source_type = llvm::dyn_cast<llvm::IntegerType>(operand->getType());
  auto *destination_integer_type =
      llvm::dyn_cast<llvm::IntegerType>(destination_type);
  if (source_type == nullptr || destination_integer_type == nullptr) {
    return nullptr;
  }

  switch (cast_opcode) {
  case opcode::trunc:
    if (source_type->getBitWidth() > destination_integer_type->getBitWidth()) {
      return emit_integer_trunc(builder, operand, destination_integer_type,
                                mba_context, salt + 1);
    }
    break;
  case opcode::zext:
    if (source_type->getBitWidth() < destination_integer_type->getBitWidth()) {
      return emit_integer_zext(builder, operand, destination_integer_type,
                               mba_context, salt + 2);
    }
    break;
  case opcode::sext:
    if (source_type->getBitWidth() < destination_integer_type->getBitWidth()) {
      return emit_integer_sext(builder, operand, destination_integer_type,
                               mba_context, salt + 3);
    }
    break;
  default:
    break;
  }

  return nullptr;
}

llvm::Value *emit_binary(llvm::IRBuilder<> &builder,
                         const slot_storage &slot_allocas,
                         llvm::ArrayRef<std::uint32_t> slot_mapping,
                         const bytecode_program &program,
                         const micro_instruction &instruction,
                         llvm::AllocaInst *opaque_seed_slot,
                          std::uint64_t opaque_seed_base,
                         std::uint64_t bytecode_seed,
                         const opcode_permutation &opcode_map,
                         const mba::builder_context &mba_context,
                         std::uint64_t salt) {
  if (!is_binary_opcode(instruction.op)) {
    llvm_unreachable("opcode is not a binary opcode");
  }

  llvm::Value *const lhs =
      materialize_value(builder, slot_allocas, slot_mapping, program,
                        instruction.operands[0], opaque_seed_slot,
                        opaque_seed_base, mba_context, salt + 1);
  llvm::Value *const rhs =
      materialize_value(builder, slot_allocas, slot_mapping, program,
                        instruction.operands[1], opaque_seed_slot,
                        opaque_seed_base, mba_context, salt + 2);

  llvm::Value *result = nullptr;
  llvm::Instruction *flag_target = nullptr;
  if (is_polymorphic_integer_binary_opcode(instruction.op) &&
      lhs->getType()->isIntegerTy() && lhs->getType() == rhs->getType()) {
    const scalar_handler_shape shape = select_scalar_handler_shape(
        bytecode_seed, instruction.op, get_physical_opcode(opcode_map, instruction.op),
        salt);
    result = emit_current_integer_binary(builder, instruction.op, lhs, rhs,
                                         instruction.flags, mba_context, salt,
                                         flag_target, "obf.vm.scalar");
    apply_integer_binary_flags(flag_target, instruction.flags);
    return apply_scalar_handler_shape(builder, shape, result);
  }

  switch (instruction.op) {
  case opcode::add:
    if (!has_instruction_flag(instruction.flags, instruction_flag_nsw) &&
        !has_instruction_flag(instruction.flags, instruction_flag_nuw)) {
      result = mba::create_add(builder, lhs, rhs, mba_context, salt + 3,
                               "obf.vm.add");
    } else if (select_handler_variant(instruction.op, opaque_seed_base, salt) == 0) {
      result = builder.CreateAdd(lhs, rhs, "obf.vm.add");
    } else if (lhs->getType()->isIntegerTy()) {
      llvm::Value *sum = builder.CreateAdd(lhs, rhs, "obf.vm.add.variant");
      result = builder.CreateAdd(
          sum,
          mba::create_opaque_integer(builder,
                                     llvm::cast<llvm::IntegerType>(sum->getType()),
                                     mba_context,
                                     llvm::APInt(sum->getType()->getIntegerBitWidth(), 0),
                                     salt + 0x41, "obf.vm.add.zero"),
          "obf.vm.add");
    } else {
      result = builder.CreateAdd(lhs, rhs, "obf.vm.add");
    }
    break;
  case opcode::sub:
    if (!has_instruction_flag(instruction.flags, instruction_flag_nsw) &&
        !has_instruction_flag(instruction.flags, instruction_flag_nuw)) {
      result = mba::create_sub(builder, lhs, rhs, mba_context, salt + 4,
                               "obf.vm.sub");
    } else if (select_handler_variant(instruction.op, opaque_seed_base, salt) == 0) {
      result = builder.CreateSub(lhs, rhs, "obf.vm.sub");
    } else if (lhs->getType()->isIntegerTy()) {
      llvm::Value *diff = builder.CreateSub(lhs, rhs, "obf.vm.sub.variant");
      result = builder.CreateXor(
          diff,
          mba::create_opaque_integer(builder,
                                     llvm::cast<llvm::IntegerType>(diff->getType()),
                                     mba_context,
                                     llvm::APInt(diff->getType()->getIntegerBitWidth(), 0),
                                     salt + 0x42, "obf.vm.sub.zero"),
          "obf.vm.sub");
    } else {
      result = builder.CreateSub(lhs, rhs, "obf.vm.sub");
    }
    break;
  case opcode::mul:
    result = builder.CreateMul(lhs, rhs, "obf.vm.mul");
    break;
  case opcode::udiv:
    result = builder.CreateUDiv(lhs, rhs, "obf.vm.udiv");
    break;
  case opcode::sdiv:
    result = builder.CreateSDiv(lhs, rhs, "obf.vm.sdiv");
    break;
  case opcode::urem:
    result = builder.CreateURem(lhs, rhs, "obf.vm.urem");
    break;
  case opcode::srem:
    result = builder.CreateSRem(lhs, rhs, "obf.vm.srem");
    break;
  case opcode::shl:
    result = builder.CreateShl(lhs, rhs, "obf.vm.shl");
    break;
  case opcode::lshr:
    result = builder.CreateLShr(lhs, rhs, "obf.vm.lshr");
    break;
  case opcode::ashr:
    result = builder.CreateAShr(lhs, rhs, "obf.vm.ashr");
    break;
  case opcode::and_op:
    result = builder.CreateAnd(lhs, rhs, "obf.vm.and");
    break;
  case opcode::or_op:
    result = builder.CreateOr(lhs, rhs, "obf.vm.or");
    break;
  case opcode::xor_op:
    result = mba::create_xor(builder, lhs, rhs, mba_context, salt + 5,
                             "obf.vm.xor");
    break;
  case opcode::fadd:
    result = builder.CreateFAdd(lhs, rhs, "obf.vm.fadd");
    break;
  case opcode::fsub:
    result = builder.CreateFSub(lhs, rhs, "obf.vm.fsub");
    break;
  case opcode::fmul:
    result = builder.CreateFMul(lhs, rhs, "obf.vm.fmul");
    break;
  case opcode::fdiv:
    result = builder.CreateFDiv(lhs, rhs, "obf.vm.fdiv");
    break;
  case opcode::frem:
    result = builder.CreateFRem(lhs, rhs, "obf.vm.frem");
    break;
  default:
    llvm_unreachable("opcode is not a binary opcode");
  }

  auto *binary = llvm::cast<llvm::BinaryOperator>(result);
  if (has_instruction_flag(instruction.flags, instruction_flag_nsw)) {
    binary->setHasNoSignedWrap();
  }
  if (has_instruction_flag(instruction.flags, instruction_flag_nuw)) {
    binary->setHasNoUnsignedWrap();
  }
  if (has_instruction_flag(instruction.flags, instruction_flag_exact)) {
    switch (instruction.op) {
    case opcode::udiv:
    case opcode::sdiv:
    case opcode::lshr:
    case opcode::ashr:
      binary->setIsExact();
      break;
    default:
      break;
    }
  }
  apply_fast_math_flags(binary, instruction.flags);
  return result;
}

llvm::Value *emit_cast(llvm::IRBuilder<> &builder,
                       const slot_storage &slot_allocas,
                       llvm::ArrayRef<std::uint32_t> slot_mapping,
                       const bytecode_program &program,
                       const micro_instruction &instruction,
                       llvm::AllocaInst *opaque_seed_slot,
                       std::uint64_t opaque_seed_base,
                       const mba::builder_context &mba_context,
                       std::uint64_t salt) {
  if (!is_cast_opcode(instruction.op)) {
    llvm_unreachable("opcode is not a cast opcode");
  }

  llvm::Type *const destination_type =
      const_cast<llvm::Type *>(program.slots[instruction.result_slot].type);
  const llvm::Type *const source_type =
      value_ref_type(program, instruction.operands[0]);

  llvm::Value *operand = nullptr;
  const auto materialize_operand = [&]() -> llvm::Value * {
    if (operand == nullptr) {
      operand = materialize_value(builder, slot_allocas, slot_mapping, program,
                                  instruction.operands[0], opaque_seed_slot,
                                  opaque_seed_base, mba_context, salt + 1);
    }

    return operand;
  };

  if (instruction.op == opcode::ptr_to_int && source_type->isPointerTy() &&
      destination_type->isIntegerTy()) {
    if (llvm::Value *carrier = materialize_pointer_carrier_from_value_ref(
            builder, slot_allocas, slot_mapping, program,
            instruction.operands[0], opaque_seed_slot, opaque_seed_base,
            mba_context, salt + 2)) {
      return emit_unsigned_integer_width_cast(
          builder, carrier, llvm::cast<llvm::IntegerType>(destination_type),
          mba_context, salt + 3);
    }
  }

  if (instruction.op == opcode::int_to_ptr && destination_type->isPointerTy()) {
    llvm::Value *source_integer = materialize_operand();
    if (auto *carrier_type = get_pointer_carrier_type(builder, destination_type)) {
      if (llvm::Value *carrier = emit_unsigned_integer_width_cast(
              builder, source_integer, carrier_type, mba_context, salt + 4)) {
        carrier = mba::entangle_value(builder, carrier, mba_context,
                                      salt ^ 0x5606ULL,
                                      "obf.vm.inttoptr.carrier");
        return builder.CreateIntToPtr(carrier, destination_type,
                                      "obf.vm.inttoptr");
      }
    }
  }

  if (instruction.op == opcode::bitcast && source_type->isPointerTy() &&
      destination_type->isPointerTy()) {
    if (llvm::Value *carrier = materialize_pointer_carrier_from_value_ref(
            builder, slot_allocas, slot_mapping, program,
            instruction.operands[0], opaque_seed_slot, opaque_seed_base,
            mba_context, salt + 5)) {
      if (auto *carrier_type = get_pointer_carrier_type(builder, destination_type)) {
        if (llvm::Value *normalized = emit_unsigned_integer_width_cast(
                builder, carrier, carrier_type, mba_context, salt + 6)) {
          return builder.CreateIntToPtr(normalized, destination_type,
                                        "obf.vm.bitcast");
        }
      }
    }
  }

  llvm::Value *const materialized_operand = materialize_operand();

  if (llvm::Value *integer_cast = emit_integer_cast(
          builder, instruction.op, materialized_operand, destination_type,
          mba_context, salt + 2)) {
    return integer_cast;
  }

  switch (instruction.op) {
  case opcode::trunc:
    return builder.CreateTrunc(materialized_operand, destination_type,
                               "obf.vm.trunc");
  case opcode::zext:
    return builder.CreateZExt(materialized_operand, destination_type,
                              "obf.vm.zext");
  case opcode::sext:
    return builder.CreateSExt(materialized_operand, destination_type,
                              "obf.vm.sext");
  case opcode::fp_trunc:
    return builder.CreateFPTrunc(materialized_operand, destination_type,
                                 "obf.vm.fptrunc");
  case opcode::fp_ext:
    return builder.CreateFPExt(materialized_operand, destination_type,
                               "obf.vm.fpext");
  case opcode::ui_to_fp:
    return builder.CreateUIToFP(materialized_operand, destination_type,
                                "obf.vm.uitofp");
  case opcode::si_to_fp:
    return builder.CreateSIToFP(materialized_operand, destination_type,
                                "obf.vm.sitofp");
  case opcode::fp_to_ui:
    return builder.CreateFPToUI(materialized_operand, destination_type,
                                "obf.vm.fptoui");
  case opcode::fp_to_si:
    return builder.CreateFPToSI(materialized_operand, destination_type,
                                "obf.vm.fptosi");
  case opcode::ptr_to_int:
    return builder.CreatePtrToInt(materialized_operand, destination_type,
                                  "obf.vm.ptrtoint");
  case opcode::int_to_ptr:
    return builder.CreateIntToPtr(materialized_operand, destination_type,
                                  "obf.vm.inttoptr");
  case opcode::bitcast:
    return builder.CreateBitCast(materialized_operand, destination_type,
                                 "obf.vm.bitcast");
  case opcode::addrspace_cast:
    return builder.CreateAddrSpaceCast(materialized_operand, destination_type,
                                       "obf.vm.addrspacecast");
  default:
    llvm_unreachable("opcode is not a cast opcode");
  }
}

} // namespace

llvm::FastMathFlags decode_fast_math_flags(std::uint32_t flags) {
  llvm::FastMathFlags fast_math;
  fast_math.setAllowReassoc(
      has_instruction_flag(flags, instruction_flag_fast_reassoc));
  fast_math.setNoNaNs(has_instruction_flag(flags, instruction_flag_fast_nnan));
  fast_math.setNoInfs(has_instruction_flag(flags, instruction_flag_fast_ninf));
  fast_math.setNoSignedZeros(
      has_instruction_flag(flags, instruction_flag_fast_nsz));
  fast_math.setAllowReciprocal(
      has_instruction_flag(flags, instruction_flag_fast_arcp));
  fast_math.setAllowContract(
      has_instruction_flag(flags, instruction_flag_fast_contract));
  fast_math.setApproxFunc(has_instruction_flag(flags, instruction_flag_fast_afn));
  if (has_instruction_flag(flags, instruction_flag_fast_fast)) {
    fast_math.setFast();
  }
  return fast_math;
}

void apply_fast_math_flags(llvm::Instruction *instruction, std::uint32_t flags) {
  if (instruction == nullptr) {
    return;
  }

  instruction->setFastMathFlags(decode_fast_math_flags(flags));
}

std::uint32_t select_handler_variant(opcode op, std::uint64_t seed_base,
                                     std::uint64_t salt,
                                     std::uint32_t variant_count) {
  if (variant_count <= 1) {
    return 0;
  }

  return static_cast<std::uint32_t>(
      mix_seed(seed_base,
               salt ^ ((static_cast<std::uint64_t>(opcode_to_index(op)) + 1) *
                       0x9e3779b97f4a7c15ULL)) %
      variant_count);
}

scalar_handler_shape select_scalar_handler_shape(std::uint64_t seed_base,
                                                 opcode op,
                                                 std::uint8_t physical_opcode,
                                                 std::uint64_t salt) {
  std::uint64_t mixed = mix_seed(seed_base, salt ^ 0x51a9d15ca1a3ULL);
  mixed = mix_seed(mixed,
                   (static_cast<std::uint64_t>(opcode_to_index(op)) + 1) *
                       0x9e3779b97f4a7c15ULL);
  mixed = mix_seed(mixed,
                   (static_cast<std::uint64_t>(physical_opcode) + 1) *
                       0xbf58476d1ce4e5b9ULL);
  return static_cast<scalar_handler_shape>(mixed % 3);
}

llvm::Value *emit_unsigned_integer_width_cast(
    llvm::IRBuilder<> &builder, llvm::Value *operand,
    llvm::IntegerType *destination_type,
    const mba::builder_context &mba_context, std::uint64_t salt) {
  auto *source_type = llvm::dyn_cast<llvm::IntegerType>(operand->getType());
  if (source_type == nullptr || destination_type == nullptr) {
    return nullptr;
  }

  if (source_type == destination_type) {
    return operand;
  }

  if (source_type->getBitWidth() < destination_type->getBitWidth()) {
    return emit_integer_zext(builder, operand, destination_type, mba_context,
                             salt + 1);
  }

  if (source_type->getBitWidth() > destination_type->getBitWidth()) {
    return emit_integer_trunc(builder, operand, destination_type, mba_context,
                              salt + 2);
  }

  return operand;
}

bool lower_scalar_instruction(llvm::IRBuilder<> &builder,
                              const instruction_rewrite_context &context) {
  rewrite_function_context &function_context = context.function_context;
  const micro_instruction &instruction = context.instruction;
  const std::uint64_t instruction_index = context.instruction_index;

  switch (instruction.op) {
  case opcode::add:
  case opcode::sub:
  case opcode::mul:
  case opcode::udiv:
  case opcode::sdiv:
  case opcode::urem:
  case opcode::srem:
  case opcode::shl:
  case opcode::lshr:
  case opcode::ashr:
  case opcode::and_op:
  case opcode::or_op:
  case opcode::xor_op:
  case opcode::fadd:
  case opcode::fsub:
  case opcode::fmul:
  case opcode::fdiv:
  case opcode::frem:
    finish_value(builder, context,
                  emit_binary(builder, function_context.slot_allocas,
                              context.current_slot_mapping, function_context.program,
                              instruction, function_context.opaque_seed_slot,
                              function_context.opaque_seed_base,
                              function_context.bytecode_seed,
                              function_context.opcode_map,
                              function_context.mba_context,
                              0xb000 + instruction_index));
    return true;

  case opcode::trunc:
  case opcode::zext:
  case opcode::sext:
  case opcode::fp_trunc:
  case opcode::fp_ext:
  case opcode::ui_to_fp:
  case opcode::si_to_fp:
  case opcode::fp_to_ui:
  case opcode::fp_to_si:
  case opcode::ptr_to_int:
  case opcode::int_to_ptr:
  case opcode::bitcast:
  case opcode::addrspace_cast:
    if (select_handler_variant(instruction.op, function_context.opaque_seed_base,
                               0xc800 + instruction_index) == 0) {
      finish_value(builder, context,
                   emit_cast(builder, function_context.slot_allocas,
                             context.current_slot_mapping, function_context.program,
                             instruction, function_context.opaque_seed_slot,
                             function_context.opaque_seed_base,
                             function_context.mba_context,
                             0xc000 + instruction_index));
    } else {
      emit_in_helper_block(
          builder, context, "vm.cast.exec.", [&](llvm::IRBuilder<> &helper_builder) {
            finish_value_in_builder(
                helper_builder, context,
                emit_cast(helper_builder, function_context.slot_allocas,
                          context.current_slot_mapping, function_context.program,
                          instruction, function_context.opaque_seed_slot,
                          function_context.opaque_seed_base,
                          function_context.mba_context,
                          0xc000 + instruction_index));
          });
    }
    return true;

  case opcode::freeze:
    finish_value(builder, context,
                 builder.CreateFreeze(
                     materialize_value(builder, function_context.slot_allocas,
                                       context.current_slot_mapping,
                                       function_context.program,
                                       instruction.operands[0],
                                       function_context.opaque_seed_slot,
                                       function_context.opaque_seed_base,
                                       function_context.mba_context,
                                       0xd000 + instruction_index),
                     "obf.vm.freeze"));
    return true;

  case opcode::fneg: {
    auto *neg = llvm::cast<llvm::Instruction>(builder.CreateFNeg(
        materialize_value(builder, function_context.slot_allocas,
                          context.current_slot_mapping, function_context.program,
                          instruction.operands[0],
                          function_context.opaque_seed_slot,
                          function_context.opaque_seed_base,
                          function_context.mba_context,
                          0xd080 + instruction_index),
        "obf.vm.fneg"));
    apply_fast_math_flags(neg, instruction.flags);
    finish_value(builder, context, neg);
    return true;
  }

  case opcode::icmp_eq:
  case opcode::icmp_ne:
  case opcode::icmp_ugt:
  case opcode::icmp_uge:
  case opcode::icmp_ult:
  case opcode::icmp_ule:
  case opcode::icmp_sgt:
  case opcode::icmp_sge:
  case opcode::icmp_slt:
  case opcode::icmp_sle: {
    const auto emit_compare = [&](llvm::IRBuilder<> &compare_builder) {
      llvm::Value *lhs = materialize_value(
          compare_builder, function_context.slot_allocas,
          context.current_slot_mapping, function_context.program,
          instruction.operands[0], function_context.opaque_seed_slot,
          function_context.opaque_seed_base, function_context.mba_context,
          0xe000 + instruction_index);
      llvm::Value *rhs = materialize_value(
          compare_builder, function_context.slot_allocas,
          context.current_slot_mapping, function_context.program,
          instruction.operands[1], function_context.opaque_seed_slot,
          function_context.opaque_seed_base, function_context.mba_context,
          0xe100 + instruction_index);
      if (lhs->getType()->isIntegerTy() && lhs->getType() == rhs->getType()) {
        return emit_integer_icmp(compare_builder, instruction.op, lhs, rhs,
                                 function_context.mba_context,
                                 0xe200 + instruction_index * 16);
      }
      return compare_builder.CreateICmp(
          icmp_predicate_for_opcode(instruction.op), lhs, rhs, "obf.vm.icmp");
    };

    if (value_ref_type(function_context.program, instruction.operands[0])->isIntegerTy() &&
        value_ref_type(function_context.program, instruction.operands[0]) ==
            value_ref_type(function_context.program, instruction.operands[1])) {
      finish_value(builder, context, emit_compare(builder));
    } else if (select_handler_variant(instruction.op,
                                      function_context.opaque_seed_base,
                                      0xe800 + instruction_index) == 0) {
      finish_value(builder, context, emit_compare(builder));
    } else {
      emit_in_helper_block(builder, context, "vm.icmp.exec.",
                           [&](llvm::IRBuilder<> &helper_builder) {
                             finish_value_in_builder(helper_builder, context,
                                                     emit_compare(helper_builder));
                           });
    }
    return true;
  }

  case opcode::fcmp_false:
  case opcode::fcmp_oeq:
  case opcode::fcmp_ogt:
  case opcode::fcmp_oge:
  case opcode::fcmp_olt:
  case opcode::fcmp_ole:
  case opcode::fcmp_one:
  case opcode::fcmp_ord:
  case opcode::fcmp_uno:
  case opcode::fcmp_ueq:
  case opcode::fcmp_ugt:
  case opcode::fcmp_uge:
  case opcode::fcmp_ult:
  case opcode::fcmp_ule:
  case opcode::fcmp_une:
  case opcode::fcmp_true:
    if (select_handler_variant(instruction.op, function_context.opaque_seed_base,
                               0xf800 + instruction_index) == 0) {
      auto *compare = llvm::cast<llvm::Instruction>(builder.CreateFCmp(
          fcmp_predicate_for_opcode(instruction.op),
          materialize_value(builder, function_context.slot_allocas,
                            context.current_slot_mapping,
                            function_context.program, instruction.operands[0],
                            function_context.opaque_seed_slot,
                            function_context.opaque_seed_base,
                            function_context.mba_context,
                            0xf000 + instruction_index),
          materialize_value(builder, function_context.slot_allocas,
                            context.current_slot_mapping,
                            function_context.program, instruction.operands[1],
                            function_context.opaque_seed_slot,
                            function_context.opaque_seed_base,
                            function_context.mba_context,
                            0xf100 + instruction_index),
          "obf.vm.fcmp"));
      apply_fast_math_flags(compare, instruction.flags);
      finish_value(builder, context, compare);
    } else {
      emit_in_helper_block(
          builder, context, "vm.fcmp.exec.",
          [&](llvm::IRBuilder<> &helper_builder) {
            auto *compare = llvm::cast<llvm::Instruction>(helper_builder.CreateFCmp(
                fcmp_predicate_for_opcode(instruction.op),
                materialize_value(helper_builder, function_context.slot_allocas,
                                  context.current_slot_mapping,
                                  function_context.program, instruction.operands[0],
                                  function_context.opaque_seed_slot,
                                  function_context.opaque_seed_base,
                                  function_context.mba_context,
                                  0xf000 + instruction_index),
                materialize_value(helper_builder, function_context.slot_allocas,
                                  context.current_slot_mapping,
                                  function_context.program, instruction.operands[1],
                                  function_context.opaque_seed_slot,
                                  function_context.opaque_seed_base,
                                  function_context.mba_context,
                                  0xf100 + instruction_index),
                "obf.vm.fcmp"));
            apply_fast_math_flags(compare, instruction.flags);
            finish_value_in_builder(helper_builder, context, compare);
          });
    }
    return true;

  case opcode::select:
    if (instruction.result_slot != invalid_slot &&
        (function_context.program.slots[instruction.result_slot].type->isIntegerTy() ||
         function_context.program.slots[instruction.result_slot].type->isPointerTy()) &&
        value_ref_type(function_context.program, instruction.operands[0])
            ->isIntegerTy(1)) {
      auto *true_block = llvm::BasicBlock::Create(
          function_context.function.getContext(),
          "vm.select.store.true." + std::to_string(instruction_index),
          &function_context.function);
      auto *false_block = llvm::BasicBlock::Create(
          function_context.function.getContext(),
          "vm.select.store.false." + std::to_string(instruction_index),
          &function_context.function);
      auto *merge_block = llvm::BasicBlock::Create(
          function_context.function.getContext(),
          "vm.select.store.merge." + std::to_string(instruction_index),
          &function_context.function);
      llvm::Value *condition = materialize_value(
          builder, function_context.slot_allocas, context.current_slot_mapping,
          function_context.program, instruction.operands[0],
          function_context.opaque_seed_slot, function_context.opaque_seed_base,
          function_context.mba_context, 0x10000 + instruction_index);
      builder.CreateCondBr(condition, true_block, false_block);

      llvm::IRBuilder<> true_builder(true_block);
      llvm::Value *true_value = materialize_value(
          true_builder, function_context.slot_allocas,
          context.current_slot_mapping, function_context.program,
          instruction.operands[1], function_context.opaque_seed_slot,
          function_context.opaque_seed_base, function_context.mba_context,
          0x10100 + instruction_index);
      store_slot(true_builder, function_context.slot_allocas,
                 context.current_slot_mapping, function_context.program,
                 instruction.result_slot, true_value,
                 function_context.opaque_seed_slot,
                 function_context.opaque_seed_base, function_context.mba_context,
                 0x10300 + instruction_index);
      true_builder.CreateBr(merge_block);

      llvm::IRBuilder<> false_builder(false_block);
      llvm::Value *false_value = materialize_value(
          false_builder, function_context.slot_allocas,
          context.current_slot_mapping, function_context.program,
          instruction.operands[2], function_context.opaque_seed_slot,
          function_context.opaque_seed_base, function_context.mba_context,
          0x10200 + instruction_index);
      store_slot(false_builder, function_context.slot_allocas,
                 context.current_slot_mapping, function_context.program,
                 instruction.result_slot, false_value,
                 function_context.opaque_seed_slot,
                 function_context.opaque_seed_base, function_context.mba_context,
                 0x10400 + instruction_index);
      false_builder.CreateBr(merge_block);

      llvm::IRBuilder<> merge_builder(merge_block);
      if (instruction_index + 1 < function_context.slot_mappings.size()) {
        rotate_to_mapping(merge_builder, context,
                          static_cast<std::uint32_t>(instruction_index + 1));
      }
      llvm::Value *next_target = decode_target_dispatch(
          merge_builder, function_context, context.layout.fallthrough_target_offset,
          0x10300 + instruction_index);
      emit_dispatch(merge_builder, function_context, next_target,
                    0x10400 + instruction_index,
                    static_cast<std::uint32_t>(instruction_index + 1));
    } else if (select_handler_variant(instruction.op,
                                      function_context.opaque_seed_base,
                                      0x10000 + instruction_index) == 0) {
      finish_value(builder, context,
                   builder.CreateSelect(
                       materialize_value(builder, function_context.slot_allocas,
                                         context.current_slot_mapping,
                                         function_context.program,
                                         instruction.operands[0],
                                         function_context.opaque_seed_slot,
                                         function_context.opaque_seed_base,
                                         function_context.mba_context,
                                         0x10000 + instruction_index),
                       materialize_value(builder, function_context.slot_allocas,
                                         context.current_slot_mapping,
                                         function_context.program,
                                         instruction.operands[1],
                                         function_context.opaque_seed_slot,
                                         function_context.opaque_seed_base,
                                         function_context.mba_context,
                                         0x10100 + instruction_index),
                       materialize_value(builder, function_context.slot_allocas,
                                         context.current_slot_mapping,
                                         function_context.program,
                                         instruction.operands[2],
                                         function_context.opaque_seed_slot,
                                         function_context.opaque_seed_base,
                                         function_context.mba_context,
                                         0x10200 + instruction_index),
                       "obf.vm.select"));
    } else {
      auto *true_block = llvm::BasicBlock::Create(
          function_context.function.getContext(),
          "vm.select.true." + std::to_string(instruction_index),
          &function_context.function);
      auto *false_block = llvm::BasicBlock::Create(
          function_context.function.getContext(),
          "vm.select.false." + std::to_string(instruction_index),
          &function_context.function);
      auto *merge_block = llvm::BasicBlock::Create(
          function_context.function.getContext(),
          "vm.select.merge." + std::to_string(instruction_index),
          &function_context.function);
      llvm::Value *condition = materialize_value(
          builder, function_context.slot_allocas, context.current_slot_mapping,
          function_context.program, instruction.operands[0],
          function_context.opaque_seed_slot, function_context.opaque_seed_base,
          function_context.mba_context, 0x10000 + instruction_index);
      builder.CreateCondBr(condition, true_block, false_block);

      llvm::IRBuilder<> true_builder(true_block);
      llvm::Value *true_value = materialize_value(
          true_builder, function_context.slot_allocas,
          context.current_slot_mapping, function_context.program,
          instruction.operands[1], function_context.opaque_seed_slot,
          function_context.opaque_seed_base, function_context.mba_context,
          0x10100 + instruction_index);
      true_builder.CreateBr(merge_block);

      llvm::IRBuilder<> false_builder(false_block);
      llvm::Value *false_value = materialize_value(
          false_builder, function_context.slot_allocas,
          context.current_slot_mapping, function_context.program,
          instruction.operands[2], function_context.opaque_seed_slot,
          function_context.opaque_seed_base, function_context.mba_context,
          0x10200 + instruction_index);
      false_builder.CreateBr(merge_block);

      llvm::IRBuilder<> merge_builder(merge_block);
      auto *phi =
          merge_builder.CreatePHI(true_value->getType(), 2, "obf.vm.select.phi");
      phi->addIncoming(true_value, true_block);
      phi->addIncoming(false_value, false_block);
      finish_value_in_builder(merge_builder, context, phi);
    }
    return true;

  default:
    return false;
  }
}

} // namespace obf::vm
