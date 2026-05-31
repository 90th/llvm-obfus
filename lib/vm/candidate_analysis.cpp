#include "obf/vm/candidate_analysis.h"

#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/DenseSet.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/InstrTypes.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Operator.h"
#include "llvm/IR/Type.h"

#include <optional>
#include <string>

namespace obf::vm {

namespace {

candidate_result reject(llvm::StringRef detail) {
  return {.eligible = false, .detail = detail.str()};
}

bool has_unsupported_varargs_usage(const llvm::Function& function) {
  for (const llvm::BasicBlock& block : function) {
    for (const llvm::Instruction& instruction : block) {
      if (llvm::isa<llvm::VAArgInst>(instruction)) { return true; }

      const auto* intrinsic = llvm::dyn_cast<llvm::IntrinsicInst>(&instruction);
      if (intrinsic == nullptr) { continue; }
      switch (intrinsic->getIntrinsicID()) {
        case llvm::Intrinsic::vastart:
        case llvm::Intrinsic::vaend:
        case llvm::Intrinsic::vacopy:
          return true;
        default:
          break;
      }
    }
  }

  return false;
}

bool is_supported_scalar_type(const llvm::Type* type) {
  return type->isIntegerTy() || type->isFloatingPointTy() || type->isPointerTy();
}

bool is_supported_type(const llvm::Type* type) {
  if (type->isVoidTy()) { return true; }

  if (is_supported_scalar_type(type)) { return true; }

  if (const auto* vector_type = llvm::dyn_cast<llvm::FixedVectorType>(type)) {
    return is_supported_scalar_type(vector_type->getElementType());
  }

  if (const auto* array_type = llvm::dyn_cast<llvm::ArrayType>(type)) {
    return is_supported_type(array_type->getElementType());
  }

  if (const auto* struct_type = llvm::dyn_cast<llvm::StructType>(type)) {
    for (llvm::Type* element_type : struct_type->elements()) {
      if (!is_supported_type(element_type)) { return false; }
    }
    return true;
  }

  return false;
}

bool is_supported_gep_source_type(const llvm::Type* type) {
  if (is_supported_type(type)) { return true; }

  if (const auto* array_type = llvm::dyn_cast<llvm::ArrayType>(type)) {
    return is_supported_gep_source_type(array_type->getElementType());
  }

  if (const auto* struct_type = llvm::dyn_cast<llvm::StructType>(type)) {
    for (llvm::Type* element_type : struct_type->elements()) {
      if (!is_supported_gep_source_type(element_type)) { return false; }
    }
    return true;
  }

  return false;
}

slot_kind classify_slot_kind(const llvm::Type* type) {
  if (type->isIntegerTy()) { return slot_kind::integer; }

  if (type->isFloatingPointTy()) { return slot_kind::floating; }

  if (type->isPointerTy()) { return slot_kind::pointer; }

  if (llvm::isa<llvm::FixedVectorType>(type)) { return slot_kind::vector; }

  return slot_kind::aggregate;
}

std::optional<opcode> map_binary_opcode(const llvm::BinaryOperator& instruction) {
  switch (instruction.getOpcode()) {
    case llvm::Instruction::Add:
      return opcode::add;
    case llvm::Instruction::Sub:
      return opcode::sub;
    case llvm::Instruction::Mul:
      return opcode::mul;
    case llvm::Instruction::UDiv:
      return opcode::udiv;
    case llvm::Instruction::SDiv:
      return opcode::sdiv;
    case llvm::Instruction::URem:
      return opcode::urem;
    case llvm::Instruction::SRem:
      return opcode::srem;
    case llvm::Instruction::Shl:
      return opcode::shl;
    case llvm::Instruction::LShr:
      return opcode::lshr;
    case llvm::Instruction::AShr:
      return opcode::ashr;
    case llvm::Instruction::And:
      return opcode::and_op;
    case llvm::Instruction::Or:
      return opcode::or_op;
    case llvm::Instruction::Xor:
      return opcode::xor_op;
    case llvm::Instruction::FAdd:
      return opcode::fadd;
    case llvm::Instruction::FSub:
      return opcode::fsub;
    case llvm::Instruction::FMul:
      return opcode::fmul;
    case llvm::Instruction::FDiv:
      return opcode::fdiv;
    case llvm::Instruction::FRem:
      return opcode::frem;
    default:
      return std::nullopt;
  }
}

std::optional<opcode> map_cast_opcode(const llvm::CastInst& instruction) {
  switch (instruction.getOpcode()) {
    case llvm::Instruction::Trunc:
      return opcode::trunc;
    case llvm::Instruction::ZExt:
      return opcode::zext;
    case llvm::Instruction::SExt:
      return opcode::sext;
    case llvm::Instruction::FPTrunc:
      return opcode::fp_trunc;
    case llvm::Instruction::FPExt:
      return opcode::fp_ext;
    case llvm::Instruction::UIToFP:
      return opcode::ui_to_fp;
    case llvm::Instruction::SIToFP:
      return opcode::si_to_fp;
    case llvm::Instruction::FPToUI:
      return opcode::fp_to_ui;
    case llvm::Instruction::FPToSI:
      return opcode::fp_to_si;
    case llvm::Instruction::PtrToInt:
      return opcode::ptr_to_int;
    case llvm::Instruction::IntToPtr:
      return opcode::int_to_ptr;
    case llvm::Instruction::BitCast:
      return opcode::bitcast;
    case llvm::Instruction::AddrSpaceCast:
      return opcode::addrspace_cast;
    default:
      return std::nullopt;
  }
}

std::optional<opcode> map_intrinsic_opcode(const llvm::IntrinsicInst& instruction) {
  switch (instruction.getIntrinsicID()) {
    case llvm::Intrinsic::memcpy:
      return opcode::memcpy_fixed;
    case llvm::Intrinsic::memmove:
      return opcode::memmove_fixed;
    case llvm::Intrinsic::memset:
      return opcode::memset_fixed;
    default:
      return std::nullopt;
  }
}

bool is_integer_min_intrinsic(const llvm::IntrinsicInst& instruction) {
  switch (instruction.getIntrinsicID()) {
    case llvm::Intrinsic::umin:
    case llvm::Intrinsic::smin:
      return instruction.getType()->isIntegerTy() && instruction.arg_size() == 2;
    default:
      return false;
  }
}

opcode min_compare_opcode(const llvm::IntrinsicInst& instruction) {
  switch (instruction.getIntrinsicID()) {
    case llvm::Intrinsic::umin:
      return opcode::icmp_ult;
    case llvm::Intrinsic::smin:
      return opcode::icmp_slt;
    default:
      llvm_unreachable("unexpected integer min intrinsic");
  }
}

std::optional<opcode> map_icmp_opcode(const llvm::ICmpInst& instruction) {
  switch (instruction.getPredicate()) {
    case llvm::CmpInst::ICMP_EQ:
      return opcode::icmp_eq;
    case llvm::CmpInst::ICMP_NE:
      return opcode::icmp_ne;
    case llvm::CmpInst::ICMP_UGT:
      return opcode::icmp_ugt;
    case llvm::CmpInst::ICMP_UGE:
      return opcode::icmp_uge;
    case llvm::CmpInst::ICMP_ULT:
      return opcode::icmp_ult;
    case llvm::CmpInst::ICMP_ULE:
      return opcode::icmp_ule;
    case llvm::CmpInst::ICMP_SGT:
      return opcode::icmp_sgt;
    case llvm::CmpInst::ICMP_SGE:
      return opcode::icmp_sge;
    case llvm::CmpInst::ICMP_SLT:
      return opcode::icmp_slt;
    case llvm::CmpInst::ICMP_SLE:
      return opcode::icmp_sle;
    default:
      return std::nullopt;
  }
}

std::optional<opcode> map_fcmp_opcode(const llvm::FCmpInst& instruction) {
  switch (instruction.getPredicate()) {
    case llvm::CmpInst::FCMP_FALSE:
      return opcode::fcmp_false;
    case llvm::CmpInst::FCMP_OEQ:
      return opcode::fcmp_oeq;
    case llvm::CmpInst::FCMP_OGT:
      return opcode::fcmp_ogt;
    case llvm::CmpInst::FCMP_OGE:
      return opcode::fcmp_oge;
    case llvm::CmpInst::FCMP_OLT:
      return opcode::fcmp_olt;
    case llvm::CmpInst::FCMP_OLE:
      return opcode::fcmp_ole;
    case llvm::CmpInst::FCMP_ONE:
      return opcode::fcmp_one;
    case llvm::CmpInst::FCMP_ORD:
      return opcode::fcmp_ord;
    case llvm::CmpInst::FCMP_UNO:
      return opcode::fcmp_uno;
    case llvm::CmpInst::FCMP_UEQ:
      return opcode::fcmp_ueq;
    case llvm::CmpInst::FCMP_UGT:
      return opcode::fcmp_ugt;
    case llvm::CmpInst::FCMP_UGE:
      return opcode::fcmp_uge;
    case llvm::CmpInst::FCMP_ULT:
      return opcode::fcmp_ult;
    case llvm::CmpInst::FCMP_ULE:
      return opcode::fcmp_ule;
    case llvm::CmpInst::FCMP_UNE:
      return opcode::fcmp_une;
    case llvm::CmpInst::FCMP_TRUE:
      return opcode::fcmp_true;
    default:
      return std::nullopt;
  }
}

opcode classify_load_opcode(const llvm::Type* type) {
  switch (classify_slot_kind(type)) {
    case slot_kind::integer:
      return opcode::load_int;
    case slot_kind::floating:
      return opcode::load_float;
    case slot_kind::pointer:
      return opcode::load_ptr;
    case slot_kind::vector:
    case slot_kind::aggregate:
      return opcode::load_vector;
  }

  llvm_unreachable("unsupported load slot kind");
}

opcode classify_store_opcode(const llvm::Type* type) {
  switch (classify_slot_kind(type)) {
    case slot_kind::integer:
      return opcode::store_int;
    case slot_kind::floating:
      return opcode::store_float;
    case slot_kind::pointer:
      return opcode::store_ptr;
    case slot_kind::vector:
    case slot_kind::aggregate:
      return opcode::store_vector;
  }

  llvm_unreachable("unsupported store slot kind");
}

std::uint32_t encode_fast_math_flags(const llvm::Instruction& instruction) {
  const auto* fp_op = llvm::dyn_cast<llvm::FPMathOperator>(&instruction);
  if (fp_op == nullptr) { return 0; }

  const llvm::FastMathFlags fast_math = fp_op->getFastMathFlags();
  std::uint32_t flags = 0;
  if (fast_math.allowReassoc()) { flags |= instruction_flag_fast_reassoc; }
  if (fast_math.noNaNs()) { flags |= instruction_flag_fast_nnan; }
  if (fast_math.noInfs()) { flags |= instruction_flag_fast_ninf; }
  if (fast_math.noSignedZeros()) { flags |= instruction_flag_fast_nsz; }
  if (fast_math.allowReciprocal()) { flags |= instruction_flag_fast_arcp; }
  if (fast_math.allowContract()) { flags |= instruction_flag_fast_contract; }
  if (fast_math.approxFunc()) { flags |= instruction_flag_fast_afn; }
  if (fast_math.isFast()) { flags |= instruction_flag_fast_fast; }
  return flags;
}

std::uint32_t encode_instruction_flags(const llvm::Instruction& instruction) {
  std::uint32_t flags = encode_fast_math_flags(instruction);

  if (const auto* binary = llvm::dyn_cast<llvm::BinaryOperator>(&instruction)) {
    if (binary->hasNoSignedWrap()) { flags |= instruction_flag_nsw; }
    if (binary->hasNoUnsignedWrap()) { flags |= instruction_flag_nuw; }
    if (binary->isExact()) { flags |= instruction_flag_exact; }
  }

  return flags;
}

std::uint32_t add_slot(bytecode_program& program, const llvm::Type* type) {
  program.slots.push_back({.type = type, .kind = classify_slot_kind(type)});
  return static_cast<std::uint32_t>(program.slots.size() - 1);
}

candidate_result build_program(const llvm::Function& function, bytecode_program* program_output) {
  if (function.isDeclaration()) { return reject("declaration"); }

  if (function.isVarArg() && has_unsupported_varargs_usage(function)) {
    return reject("varargs unsupported");
  }

  if (!is_supported_type(function.getReturnType())) { return reject("unsupported return type"); }

  bytecode_program program;
  program.argument_slots.reserve(function.arg_size());
  program.blocks.resize(function.size());

  llvm::DenseMap<const llvm::Value*, std::uint32_t> slots;
  for (const llvm::Argument& argument : function.args()) {
    if (!is_supported_type(argument.getType())) { return reject("unsupported argument type"); }

    program.argument_slots.push_back(add_slot(program, argument.getType()));
    slots[&argument] = program.argument_slots.back();
  }

  for (const llvm::BasicBlock& block : function) {
    if (block.isEHPad()) { return reject("eh pad unsupported"); }

    for (const llvm::Instruction& instruction : block) {
      if (llvm::isa<llvm::DbgInfoIntrinsic>(&instruction)) { continue; }

      if (const auto* intrinsic = llvm::dyn_cast<llvm::IntrinsicInst>(&instruction)) {
        switch (intrinsic->getIntrinsicID()) {
          case llvm::Intrinsic::lifetime_start:
          case llvm::Intrinsic::lifetime_end:
            continue;
          default:
            break;
        }
      }

      if (!is_supported_type(instruction.getType())) {
        return reject("unsupported instruction type");
      }

      if (!instruction.getType()->isVoidTy()) {
        slots[&instruction] = add_slot(program, instruction.getType());
      }
    }
  }

  llvm::DenseMap<const llvm::BasicBlock*, std::uint32_t> block_ids;
  std::uint32_t next_block_id = 0;
  for (const llvm::BasicBlock& block : function) { block_ids[&block] = next_block_id++; }

  const auto lower_value = [&](const llvm::Value& value,
                               std::string& detail) -> std::optional<value_ref> {
    if (const auto iterator = slots.find(&value); iterator != slots.end()) {
      return value_ref{.kind = value_ref_kind::slot, .slot = iterator->second};
    }

    const auto* constant = llvm::dyn_cast<llvm::Constant>(&value);
    if (constant == nullptr || !is_supported_type(constant->getType())) {
      detail = "unsupported SSA operand";
      return std::nullopt;
    }

    return value_ref{.kind = value_ref_kind::constant, .constant = constant};
  };

  const auto lower_edge_value = [&](this auto&& self,
                                    const llvm::Value& value,
                                    const llvm::BasicBlock& source,
                                    const llvm::BasicBlock& target,
                                    llvm::DenseSet<const llvm::PHINode*>& resolving,
                                    std::string& detail) -> std::optional<value_ref> {
    const auto* phi = llvm::dyn_cast<llvm::PHINode>(&value);
    if (phi == nullptr || phi->getParent() != &target) { return lower_value(value, detail); }

    if (!resolving.insert(phi).second) {
      const auto iterator = slots.find(phi);
      if (iterator == slots.end()) {
        detail = "missing phi slot";
        return std::nullopt;
      }

      return value_ref{.kind = value_ref_kind::slot, .slot = iterator->second};
    }

    const llvm::Value* incoming = phi->getIncomingValueForBlock(&source);
    if (incoming == nullptr) {
      detail = "malformed phi";
      resolving.erase(phi);
      return std::nullopt;
    }

    const std::optional<value_ref> resolved = self(*incoming, source, target, resolving, detail);
    resolving.erase(phi);
    return resolved;
  };

  const auto lower_edge = [&](const llvm::BasicBlock& source,
                              const llvm::BasicBlock& target,
                              std::string& detail) -> std::optional<control_edge> {
    control_edge edge;
    edge.target_block = block_ids.lookup(&target);
    llvm::DenseSet<const llvm::PHINode*> resolving;

    for (const llvm::Instruction& instruction : target) {
      const auto* phi = llvm::dyn_cast<llvm::PHINode>(&instruction);
      if (phi == nullptr) { break; }

      const llvm::Value* incoming = phi->getIncomingValueForBlock(&source);
      if (incoming == nullptr) {
        detail = "malformed phi";
        return std::nullopt;
      }

      const auto slot_iterator = slots.find(phi);
      if (slot_iterator == slots.end()) {
        detail = "missing phi slot";
        return std::nullopt;
      }

      const std::optional<value_ref> incoming_value =
          lower_edge_value(*incoming, source, target, resolving, detail);
      if (!incoming_value) { return std::nullopt; }

      edge.assignments.push_back({.slot = slot_iterator->second, .value = *incoming_value});
    }

    return edge;
  };

  std::string detail;
  for (const llvm::BasicBlock& block : function) {
    program.blocks[block_ids.lookup(&block)].first_instruction =
        static_cast<std::uint32_t>(program.instructions.size());

    for (const llvm::Instruction& instruction : block) {
      if (llvm::isa<llvm::DbgInfoIntrinsic>(&instruction) ||
          llvm::isa<llvm::PHINode>(&instruction)) {
        continue;
      }

      if (const auto* intrinsic = llvm::dyn_cast<llvm::IntrinsicInst>(&instruction)) {
        switch (intrinsic->getIntrinsicID()) {
          case llvm::Intrinsic::lifetime_start:
          case llvm::Intrinsic::lifetime_end:
            continue;
          default:
            break;
        }
      }

      if (&instruction == block.getTerminator()) { break; }

      micro_instruction vm_instruction;
      vm_instruction.result_slot =
          instruction.getType()->isVoidTy() ? invalid_slot : slots.lookup(&instruction);
      vm_instruction.flags = encode_instruction_flags(instruction);

      if (const auto* intrinsic = llvm::dyn_cast<llvm::IntrinsicInst>(&instruction);
          intrinsic != nullptr && is_integer_min_intrinsic(*intrinsic)) {
        const std::optional<value_ref> lhs = lower_value(*intrinsic->getArgOperand(0), detail);
        const std::optional<value_ref> rhs = lower_value(*intrinsic->getArgOperand(1), detail);
        if (!lhs || !rhs) { return reject(detail); }

        const std::uint32_t compare_slot =
            add_slot(program, llvm::Type::getInt1Ty(function.getContext()));

        micro_instruction compare_instruction;
        compare_instruction.result_slot = compare_slot;
        compare_instruction.op = min_compare_opcode(*intrinsic);
        compare_instruction.operands.push_back(*lhs);
        compare_instruction.operands.push_back(*rhs);
        program.instructions.push_back(std::move(compare_instruction));

        vm_instruction.op = opcode::select;
        vm_instruction.operands.push_back(
            value_ref{.kind = value_ref_kind::slot, .slot = compare_slot});
        vm_instruction.operands.push_back(*lhs);
        vm_instruction.operands.push_back(*rhs);
        program.instructions.push_back(std::move(vm_instruction));
        continue;
      }

      if (const auto* binary = llvm::dyn_cast<llvm::BinaryOperator>(&instruction)) {
        const std::optional<opcode> lowered_opcode = map_binary_opcode(*binary);
        if (!lowered_opcode) {
          return reject("unsupported binary opcode: " + std::string(binary->getOpcodeName()));
        }

        vm_instruction.op = *lowered_opcode;
        const std::optional<value_ref> lhs = lower_value(*binary->getOperand(0), detail);
        const std::optional<value_ref> rhs = lower_value(*binary->getOperand(1), detail);
        if (!lhs || !rhs) { return reject(detail); }
        vm_instruction.operands.push_back(*lhs);
        vm_instruction.operands.push_back(*rhs);
      } else if (const auto* fneg = llvm::dyn_cast<llvm::UnaryOperator>(&instruction)) {
        if (fneg->getOpcode() != llvm::Instruction::FNeg) {
          return reject("unsupported unary opcode: " + std::string(fneg->getOpcodeName()));
        }

        vm_instruction.op = opcode::fneg;
        const std::optional<value_ref> operand = lower_value(*fneg->getOperand(0), detail);
        if (!operand) { return reject(detail); }
        vm_instruction.operands.push_back(*operand);
      } else if (const auto* cast = llvm::dyn_cast<llvm::CastInst>(&instruction)) {
        const std::optional<opcode> lowered_opcode = map_cast_opcode(*cast);
        if (!lowered_opcode) {
          return reject("unsupported cast opcode: " + std::string(cast->getOpcodeName()));
        }

        vm_instruction.op = *lowered_opcode;
        const std::optional<value_ref> operand = lower_value(*cast->getOperand(0), detail);
        if (!operand) { return reject(detail); }
        vm_instruction.operands.push_back(*operand);
      } else if (const auto* freeze = llvm::dyn_cast<llvm::FreezeInst>(&instruction)) {
        vm_instruction.op = opcode::freeze;
        const std::optional<value_ref> operand = lower_value(*freeze->getOperand(0), detail);
        if (!operand) { return reject(detail); }
        vm_instruction.operands.push_back(*operand);
      } else if (const auto* icmp = llvm::dyn_cast<llvm::ICmpInst>(&instruction)) {
        const std::optional<opcode> lowered_opcode = map_icmp_opcode(*icmp);
        if (!lowered_opcode) { return reject("unsupported icmp predicate"); }

        vm_instruction.op = *lowered_opcode;
        const std::optional<value_ref> lhs = lower_value(*icmp->getOperand(0), detail);
        const std::optional<value_ref> rhs = lower_value(*icmp->getOperand(1), detail);
        if (!lhs || !rhs) { return reject(detail); }
        vm_instruction.operands.push_back(*lhs);
        vm_instruction.operands.push_back(*rhs);
      } else if (const auto* fcmp = llvm::dyn_cast<llvm::FCmpInst>(&instruction)) {
        const std::optional<opcode> lowered_opcode = map_fcmp_opcode(*fcmp);
        if (!lowered_opcode) { return reject("unsupported fcmp predicate"); }

        vm_instruction.op = *lowered_opcode;
        const std::optional<value_ref> lhs = lower_value(*fcmp->getOperand(0), detail);
        const std::optional<value_ref> rhs = lower_value(*fcmp->getOperand(1), detail);
        if (!lhs || !rhs) { return reject(detail); }
        vm_instruction.operands.push_back(*lhs);
        vm_instruction.operands.push_back(*rhs);
      } else if (const auto* select = llvm::dyn_cast<llvm::SelectInst>(&instruction)) {
        vm_instruction.op = opcode::select;
        const std::optional<value_ref> condition = lower_value(*select->getCondition(), detail);
        const std::optional<value_ref> true_value = lower_value(*select->getTrueValue(), detail);
        const std::optional<value_ref> false_value = lower_value(*select->getFalseValue(), detail);
        if (!condition || !true_value || !false_value) { return reject(detail); }
        vm_instruction.operands.push_back(*condition);
        vm_instruction.operands.push_back(*true_value);
        vm_instruction.operands.push_back(*false_value);
      } else if (const auto* extract_element =
                     llvm::dyn_cast<llvm::ExtractElementInst>(&instruction)) {
        vm_instruction.op = opcode::extract_element;
        const std::optional<value_ref> vector =
            lower_value(*extract_element->getVectorOperand(), detail);
        const std::optional<value_ref> index =
            lower_value(*extract_element->getIndexOperand(), detail);
        if (!vector || !index) { return reject(detail); }
        vm_instruction.operands.push_back(*vector);
        vm_instruction.operands.push_back(*index);
      } else if (const auto* insert_element =
                     llvm::dyn_cast<llvm::InsertElementInst>(&instruction)) {
        vm_instruction.op = opcode::insert_element;
        const std::optional<value_ref> vector = lower_value(*insert_element->getOperand(0), detail);
        const std::optional<value_ref> element =
            lower_value(*insert_element->getOperand(1), detail);
        const std::optional<value_ref> index = lower_value(*insert_element->getOperand(2), detail);
        if (!vector || !element || !index) { return reject(detail); }
        vm_instruction.operands.push_back(*vector);
        vm_instruction.operands.push_back(*element);
        vm_instruction.operands.push_back(*index);
      } else if (const auto* shuffle_vector =
                     llvm::dyn_cast<llvm::ShuffleVectorInst>(&instruction)) {
        vm_instruction.op = opcode::shuffle_vector;
        const std::optional<value_ref> lhs = lower_value(*shuffle_vector->getOperand(0), detail);
        const std::optional<value_ref> rhs = lower_value(*shuffle_vector->getOperand(1), detail);
        if (!lhs || !rhs) { return reject(detail); }
        vm_instruction.operands.push_back(*lhs);
        vm_instruction.operands.push_back(*rhs);
        for (int mask_index : shuffle_vector->getShuffleMask()) {
          vm_instruction.case_values.push_back(
              llvm::ConstantInt::get(llvm::Type::getInt32Ty(function.getContext()), mask_index));
        }
      } else if (const auto* extract_value = llvm::dyn_cast<llvm::ExtractValueInst>(&instruction)) {
        vm_instruction.op = opcode::extract_value;
        vm_instruction.type = extract_value->getAggregateOperand()->getType();
        const std::optional<value_ref> aggregate =
            lower_value(*extract_value->getAggregateOperand(), detail);
        if (!aggregate) { return reject(detail); }
        vm_instruction.operands.push_back(*aggregate);
        for (unsigned index : extract_value->getIndices()) {
          vm_instruction.case_values.push_back(
              llvm::ConstantInt::get(llvm::Type::getInt32Ty(function.getContext()), index));
        }
      } else if (const auto* insert_value = llvm::dyn_cast<llvm::InsertValueInst>(&instruction)) {
        vm_instruction.op = opcode::insert_value;
        vm_instruction.type = insert_value->getAggregateOperand()->getType();
        const std::optional<value_ref> aggregate =
            lower_value(*insert_value->getAggregateOperand(), detail);
        const std::optional<value_ref> element =
            lower_value(*insert_value->getInsertedValueOperand(), detail);
        if (!aggregate || !element) { return reject(detail); }
        vm_instruction.operands.push_back(*aggregate);
        vm_instruction.operands.push_back(*element);
        for (unsigned index : insert_value->getIndices()) {
          vm_instruction.case_values.push_back(
              llvm::ConstantInt::get(llvm::Type::getInt32Ty(function.getContext()), index));
        }
      } else if (const auto* load = llvm::dyn_cast<llvm::LoadInst>(&instruction)) {
        if (load->isVolatile() || load->isAtomic()) {
          return reject("volatile and atomic loads unsupported");
        }

        vm_instruction.op = classify_load_opcode(load->getType());
        vm_instruction.type = load->getType();
        vm_instruction.immediate = load->getAlign().value();
        const std::optional<value_ref> pointer = lower_value(*load->getPointerOperand(), detail);
        if (!pointer) { return reject(detail); }
        vm_instruction.operands.push_back(*pointer);
      } else if (const auto* store = llvm::dyn_cast<llvm::StoreInst>(&instruction)) {
        if (store->isVolatile() || store->isAtomic()) {
          return reject("volatile and atomic stores unsupported");
        }

        vm_instruction.op = classify_store_opcode(store->getValueOperand()->getType());
        vm_instruction.type = store->getValueOperand()->getType();
        vm_instruction.immediate = store->getAlign().value();
        const std::optional<value_ref> value = lower_value(*store->getValueOperand(), detail);
        const std::optional<value_ref> pointer = lower_value(*store->getPointerOperand(), detail);
        if (!value || !pointer) { return reject(detail); }
        vm_instruction.operands.push_back(*value);
        vm_instruction.operands.push_back(*pointer);
      } else if (const auto* gep = llvm::dyn_cast<llvm::GetElementPtrInst>(&instruction)) {
        if (!is_supported_gep_source_type(gep->getSourceElementType())) {
          return reject("unsupported gep source type");
        }

        vm_instruction.op = gep->isInBounds() ? opcode::gep_inbounds : opcode::gep;
        vm_instruction.type = gep->getSourceElementType();
        const std::optional<value_ref> pointer = lower_value(*gep->getPointerOperand(), detail);
        if (!pointer) { return reject(detail); }
        vm_instruction.operands.push_back(*pointer);

        for (llvm::Value* index : gep->indices()) {
          const std::optional<value_ref> lowered_index = lower_value(*index, detail);
          if (!lowered_index) { return reject(detail); }
          vm_instruction.operands.push_back(*lowered_index);
        }
      } else if (const auto* intrinsic = llvm::dyn_cast<llvm::IntrinsicInst>(&instruction)) {
        const std::optional<opcode> lowered_opcode = map_intrinsic_opcode(*intrinsic);
        if (!lowered_opcode) {
          return reject("unsupported intrinsic: " +
                        std::string(intrinsic->getCalledFunction()->getName()));
        }

        if (intrinsic->isVolatile()) { return reject("volatile memory intrinsic unsupported"); }

        vm_instruction.op = *lowered_opcode;
        if (auto* mem_intrinsic = llvm::dyn_cast<llvm::MemIntrinsic>(intrinsic)) {
          if (!llvm::isa<llvm::ConstantInt>(mem_intrinsic->getLength())) {
            return reject("dynamic memory intrinsic length unsupported");
          }
          vm_instruction.immediate = static_cast<std::uint32_t>(
              llvm::cast<llvm::ConstantInt>(mem_intrinsic->getLength())->getZExtValue());
        }

        for (const llvm::Use& argument : intrinsic->args()) {
          const std::optional<value_ref> lowered_argument = lower_value(*argument.get(), detail);
          if (!lowered_argument) { return reject(detail); }
          vm_instruction.operands.push_back(*lowered_argument);
        }
      } else if (const auto* call = llvm::dyn_cast<llvm::CallBase>(&instruction)) {
        if (call->isInlineAsm()) { return reject("inline asm unsupported"); }
        if (call->getNumOperandBundles() != 0) { return reject("operand bundles unsupported"); }
        if (call->isMustTailCall()) { return reject("musttail unsupported"); }

        vm_instruction.op = opcode::call;
        vm_instruction.type = call->getFunctionType();
        vm_instruction.subtype = static_cast<std::uint32_t>(call->getCallingConv());
        vm_instruction.attributes = call->getAttributes();
        const std::optional<value_ref> callee = lower_value(*call->getCalledOperand(), detail);
        if (!callee) { return reject(detail); }
        vm_instruction.operands.push_back(*callee);

        for (const llvm::Use& argument : call->args()) {
          const std::optional<value_ref> lowered_argument = lower_value(*argument.get(), detail);
          if (!lowered_argument) { return reject(detail); }
          vm_instruction.operands.push_back(*lowered_argument);
        }
      } else {
        return reject("unsupported instruction: " + std::string(instruction.getOpcodeName()));
      }

      program.instructions.push_back(std::move(vm_instruction));
    }

    const llvm::Instruction* terminator = block.getTerminator();
    micro_instruction vm_terminator;
    if (const auto* branch = llvm::dyn_cast<llvm::BranchInst>(terminator)) {
      if (branch->isUnconditional()) {
        vm_terminator.op = opcode::jump;
        const std::optional<control_edge> edge =
            lower_edge(block, *branch->getSuccessor(0), detail);
        if (!edge) { return reject(detail); }
        vm_terminator.edges.push_back(*edge);
      } else {
        vm_terminator.op = opcode::branch;
        const std::optional<value_ref> condition = lower_value(*branch->getCondition(), detail);
        const std::optional<control_edge> true_edge =
            lower_edge(block, *branch->getSuccessor(0), detail);
        const std::optional<control_edge> false_edge =
            lower_edge(block, *branch->getSuccessor(1), detail);
        if (!condition || !true_edge || !false_edge) { return reject(detail); }
        vm_terminator.operands.push_back(*condition);
        vm_terminator.edges.push_back(*true_edge);
        vm_terminator.edges.push_back(*false_edge);
      }
    } else if (const auto* switch_inst = llvm::dyn_cast<llvm::SwitchInst>(terminator)) {
      vm_terminator.op = opcode::switch_op;
      const std::optional<value_ref> condition = lower_value(*switch_inst->getCondition(), detail);
      if (!condition) { return reject(detail); }

      vm_terminator.operands.push_back(*condition);
      const std::optional<control_edge> default_edge =
          lower_edge(block, *switch_inst->getDefaultDest(), detail);
      if (!default_edge) { return reject(detail); }

      vm_terminator.edges.push_back(*default_edge);
      for (const auto& switch_case : switch_inst->cases()) {
        const std::optional<control_edge> case_edge =
            lower_edge(block, *switch_case.getCaseSuccessor(), detail);
        if (!case_edge) { return reject(detail); }

        vm_terminator.case_values.push_back(switch_case.getCaseValue());
        vm_terminator.edges.push_back(*case_edge);
      }
    } else if (llvm::isa<llvm::UnreachableInst>(terminator)) {
      vm_terminator.op = opcode::unreachable_op;
    } else if (const auto* ret = llvm::dyn_cast<llvm::ReturnInst>(terminator)) {
      vm_terminator.op = opcode::ret;
      if (llvm::Value* return_value = ret->getReturnValue()) {
        const std::optional<value_ref> lowered_return = lower_value(*return_value, detail);
        if (!lowered_return) { return reject(detail); }
        vm_terminator.operands.push_back(*lowered_return);
      }
    } else {
      return reject("unsupported terminator: " + std::string(terminator->getOpcodeName()));
    }

    program.instructions.push_back(std::move(vm_terminator));
  }

  if (program.instructions.empty()) { return reject("missing virtual instructions"); }

  if (program.instructions.size() > 512) { return reject("too many virtual instructions"); }

  if (program_output != nullptr) { *program_output = program; }

  return {.eligible = true,
          .instruction_count = program.instructions.size(),
          .detail = "eligible: " + std::to_string(program.instructions.size()) +
                    " virtual instruction(s) across " + std::to_string(program.blocks.size()) +
                    " block(s)"};
}

}  // namespace

candidate_result analyze_candidate(const llvm::Function& function, bytecode_program* program) {
  return build_program(function, program);
}

}  // namespace obf::vm
