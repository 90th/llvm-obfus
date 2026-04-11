#include "obf/vm/virtualize.h"

#include "obf/vm/candidate_analysis.h"

#include "llvm/ADT/SmallVector.h"
#include "llvm/IR/Attributes.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/CallingConv.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Intrinsics.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Operator.h"
#include "llvm/IR/Type.h"

#include <algorithm>
#include <string>

namespace obf::vm {

namespace {

bool should_preserve_function_attribute(llvm::Attribute attribute) {
  if (attribute.isStringAttribute()) {
    return true;
  }

  if (!attribute.hasKindAsEnum()) {
    return false;
  }

  if (llvm::Attribute::intersectMustPreserve(attribute.getKindAsEnum())) {
    return true;
  }

  switch (attribute.getKindAsEnum()) {
  case llvm::Attribute::AlwaysInline:
  case llvm::Attribute::Cold:
  case llvm::Attribute::Convergent:
  case llvm::Attribute::DisableSanitizerInstrumentation:
  case llvm::Attribute::Hot:
  case llvm::Attribute::InlineHint:
  case llvm::Attribute::JumpTable:
  case llvm::Attribute::MinSize:
  case llvm::Attribute::MustProgress:
  case llvm::Attribute::NoFree:
  case llvm::Attribute::NoInline:
  case llvm::Attribute::NoRedZone:
  case llvm::Attribute::NoSync:
  case llvm::Attribute::NoUnwind:
  case llvm::Attribute::NullPointerIsValid:
  case llvm::Attribute::OptimizeForDebugging:
  case llvm::Attribute::OptimizeForSize:
  case llvm::Attribute::OptimizeNone:
  case llvm::Attribute::SafeStack:
  case llvm::Attribute::SanitizeAddress:
  case llvm::Attribute::SanitizeHWAddress:
  case llvm::Attribute::SanitizeMemTag:
  case llvm::Attribute::SanitizeMemory:
  case llvm::Attribute::SanitizeNumericalStability:
  case llvm::Attribute::SanitizeRealtime:
  case llvm::Attribute::SanitizeRealtimeBlocking:
  case llvm::Attribute::SanitizeThread:
  case llvm::Attribute::SanitizeType:
  case llvm::Attribute::ShadowCallStack:
  case llvm::Attribute::SpeculativeLoadHardening:
  case llvm::Attribute::StackProtect:
  case llvm::Attribute::StackProtectReq:
  case llvm::Attribute::StackProtectStrong:
  case llvm::Attribute::StrictFP:
  case llvm::Attribute::UWTable:
  case llvm::Attribute::WillReturn:
    return true;
  default:
    return false;
  }
}

llvm::AttributeList build_preserved_function_attributes(llvm::Function &function) {
  llvm::LLVMContext &context = function.getContext();
  const llvm::AttributeList original = function.getAttributes();
  llvm::AttributeList preserved;

  for (llvm::Attribute attribute : original.getRetAttrs()) {
    preserved = preserved.addRetAttribute(context, attribute);
  }

  for (llvm::Argument &argument : function.args()) {
    const unsigned argument_index = argument.getArgNo();
    for (llvm::Attribute attribute : original.getParamAttrs(argument_index)) {
      preserved = preserved.addAttributeAtIndex(
          context, llvm::AttributeList::FirstArgIndex + argument_index, attribute);
    }
  }

  for (llvm::Attribute attribute : original.getFnAttrs()) {
    if (should_preserve_function_attribute(attribute)) {
      if (attribute.isStringAttribute()) {
        preserved = preserved.addFnAttribute(context, attribute.getKindAsString(),
                                             attribute.getValueAsString());
        continue;
      }

      preserved = preserved.addFnAttribute(context, attribute);
    }
  }

  return preserved;
}

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

llvm::Value *load_slot(llvm::IRBuilder<> &builder,
                       const llvm::SmallVectorImpl<llvm::AllocaInst *> &slot_allocas,
                       const bytecode_program &program, std::uint32_t slot) {
  const slot_desc &slot_info = program.slots[slot];
  return builder.CreateLoad(const_cast<llvm::Type *>(slot_info.type),
                            slot_allocas[slot], "obf.vm.slot");
}

void store_slot(llvm::IRBuilder<> &builder,
                const llvm::SmallVectorImpl<llvm::AllocaInst *> &slot_allocas,
                std::uint32_t slot, llvm::Value *value) {
  builder.CreateStore(value, slot_allocas[slot]);
}

llvm::Value *materialize_value(llvm::IRBuilder<> &builder,
                               const llvm::SmallVectorImpl<llvm::AllocaInst *> &slot_allocas,
                               const bytecode_program &program,
                               const value_ref &value) {
  if (value.kind == value_ref_kind::slot) {
    return load_slot(builder, slot_allocas, program, value.slot);
  }

  return const_cast<llvm::Constant *>(value.constant);
}

llvm::Value *emit_binary(llvm::IRBuilder<> &builder,
                         const llvm::SmallVectorImpl<llvm::AllocaInst *> &slot_allocas,
                         const bytecode_program &program,
                         const micro_instruction &instruction) {
  llvm::Value *const lhs =
      materialize_value(builder, slot_allocas, program, instruction.operands[0]);
  llvm::Value *const rhs =
      materialize_value(builder, slot_allocas, program, instruction.operands[1]);

  llvm::Value *result = nullptr;
  const auto subopcode = static_cast<binary_opcode>(instruction.subtype);
  switch (subopcode) {
  case binary_opcode::add:
    result = builder.CreateAdd(lhs, rhs, "obf.vm.add");
    break;
  case binary_opcode::sub:
    result = builder.CreateSub(lhs, rhs, "obf.vm.sub");
    break;
  case binary_opcode::mul:
    result = builder.CreateMul(lhs, rhs, "obf.vm.mul");
    break;
  case binary_opcode::udiv:
    result = builder.CreateUDiv(lhs, rhs, "obf.vm.udiv");
    break;
  case binary_opcode::sdiv:
    result = builder.CreateSDiv(lhs, rhs, "obf.vm.sdiv");
    break;
  case binary_opcode::urem:
    result = builder.CreateURem(lhs, rhs, "obf.vm.urem");
    break;
  case binary_opcode::srem:
    result = builder.CreateSRem(lhs, rhs, "obf.vm.srem");
    break;
  case binary_opcode::shl:
    result = builder.CreateShl(lhs, rhs, "obf.vm.shl");
    break;
  case binary_opcode::lshr:
    result = builder.CreateLShr(lhs, rhs, "obf.vm.lshr");
    break;
  case binary_opcode::ashr:
    result = builder.CreateAShr(lhs, rhs, "obf.vm.ashr");
    break;
  case binary_opcode::and_op:
    result = builder.CreateAnd(lhs, rhs, "obf.vm.and");
    break;
  case binary_opcode::or_op:
    result = builder.CreateOr(lhs, rhs, "obf.vm.or");
    break;
  case binary_opcode::xor_op:
    result = builder.CreateXor(lhs, rhs, "obf.vm.xor");
    break;
  case binary_opcode::fadd:
    result = builder.CreateFAdd(lhs, rhs, "obf.vm.fadd");
    break;
  case binary_opcode::fsub:
    result = builder.CreateFSub(lhs, rhs, "obf.vm.fsub");
    break;
  case binary_opcode::fmul:
    result = builder.CreateFMul(lhs, rhs, "obf.vm.fmul");
    break;
  case binary_opcode::fdiv:
    result = builder.CreateFDiv(lhs, rhs, "obf.vm.fdiv");
    break;
  case binary_opcode::frem:
    result = builder.CreateFRem(lhs, rhs, "obf.vm.frem");
    break;
  }

  auto *binary = llvm::cast<llvm::BinaryOperator>(result);
  if (has_instruction_flag(instruction.flags, instruction_flag_nsw)) {
    binary->setHasNoSignedWrap();
  }
  if (has_instruction_flag(instruction.flags, instruction_flag_nuw)) {
    binary->setHasNoUnsignedWrap();
  }
  if (has_instruction_flag(instruction.flags, instruction_flag_exact)) {
    switch (subopcode) {
    case binary_opcode::udiv:
    case binary_opcode::sdiv:
    case binary_opcode::lshr:
    case binary_opcode::ashr:
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
                       const llvm::SmallVectorImpl<llvm::AllocaInst *> &slot_allocas,
                       const bytecode_program &program,
                       const micro_instruction &instruction) {
  llvm::Value *const operand =
      materialize_value(builder, slot_allocas, program, instruction.operands[0]);
  llvm::Type *const destination_type =
      const_cast<llvm::Type *>(program.slots[instruction.result_slot].type);

  switch (static_cast<cast_opcode>(instruction.subtype)) {
  case cast_opcode::trunc:
    return builder.CreateTrunc(operand, destination_type, "obf.vm.trunc");
  case cast_opcode::zext:
    return builder.CreateZExt(operand, destination_type, "obf.vm.zext");
  case cast_opcode::sext:
    return builder.CreateSExt(operand, destination_type, "obf.vm.sext");
  case cast_opcode::fp_trunc:
    return builder.CreateFPTrunc(operand, destination_type, "obf.vm.fptrunc");
  case cast_opcode::fp_ext:
    return builder.CreateFPExt(operand, destination_type, "obf.vm.fpext");
  case cast_opcode::ui_to_fp:
    return builder.CreateUIToFP(operand, destination_type, "obf.vm.uitofp");
  case cast_opcode::si_to_fp:
    return builder.CreateSIToFP(operand, destination_type, "obf.vm.sitofp");
  case cast_opcode::fp_to_ui:
    return builder.CreateFPToUI(operand, destination_type, "obf.vm.fptoui");
  case cast_opcode::fp_to_si:
    return builder.CreateFPToSI(operand, destination_type, "obf.vm.fptosi");
  case cast_opcode::ptr_to_int:
    return builder.CreatePtrToInt(operand, destination_type, "obf.vm.ptrtoint");
  case cast_opcode::int_to_ptr:
    return builder.CreateIntToPtr(operand, destination_type, "obf.vm.inttoptr");
  case cast_opcode::bitcast:
    return builder.CreateBitCast(operand, destination_type, "obf.vm.bitcast");
  case cast_opcode::addrspace_cast:
    return builder.CreateAddrSpaceCast(operand, destination_type,
                                       "obf.vm.addrspacecast");
  }

  return nullptr;
}

void apply_edge_assignments(
    llvm::IRBuilder<> &builder,
    const llvm::SmallVectorImpl<llvm::AllocaInst *> &slot_allocas,
    const bytecode_program &program, const control_edge &edge) {
  llvm::SmallVector<llvm::Value *, 8> incoming_values;
  incoming_values.reserve(edge.assignments.size());
  for (const edge_assignment &assignment : edge.assignments) {
    incoming_values.push_back(
        materialize_value(builder, slot_allocas, program, assignment.value));
  }

  for (std::size_t assignment_index = 0;
       assignment_index < edge.assignments.size(); ++assignment_index) {
    store_slot(builder, slot_allocas, edge.assignments[assignment_index].slot,
               incoming_values[assignment_index]);
  }
}

void rewrite_function_body(llvm::Function &function,
                           const bytecode_program &program) {
  llvm::LLVMContext &context = function.getContext();
  const llvm::AttributeList preserved_attributes =
      build_preserved_function_attributes(function);

  function.setAttributes(preserved_attributes);

  llvm::SmallVector<llvm::BasicBlock *, 8> old_blocks;
  old_blocks.reserve(function.size());
  for (llvm::BasicBlock &block : function) {
    old_blocks.push_back(&block);
  }

  for (llvm::BasicBlock *block : old_blocks) {
    block->dropAllReferences();
  }
  for (llvm::BasicBlock *block : old_blocks) {
    block->eraseFromParent();
  }

  auto *entry_block = llvm::BasicBlock::Create(context, "entry.obf.vm", &function);
  auto *dispatch_block =
      llvm::BasicBlock::Create(context, "dispatch.obf.vm", &function);
  auto *trap_block = llvm::BasicBlock::Create(context, "trap.obf.vm", &function);

  llvm::SmallVector<llvm::BasicBlock *, 32> instruction_blocks;
  instruction_blocks.reserve(program.instructions.size());
  for (std::size_t instruction_index = 0;
       instruction_index < program.instructions.size(); ++instruction_index) {
    instruction_blocks.push_back(llvm::BasicBlock::Create(
        context, "vm." + std::to_string(instruction_index), &function));
  }

  llvm::IRBuilder<> entry_builder(entry_block);
  llvm::SmallVector<llvm::AllocaInst *, 16> slot_allocas;
  slot_allocas.reserve(program.slots.size());
  for (std::size_t slot_index = 0; slot_index < program.slots.size(); ++slot_index) {
    slot_allocas.push_back(entry_builder.CreateAlloca(
        const_cast<llvm::Type *>(program.slots[slot_index].type), nullptr,
        "obf.vm.slot." + std::to_string(slot_index)));
  }

  auto *pc = entry_builder.CreateAlloca(entry_builder.getInt32Ty(), nullptr,
                                        "obf.vm.pc");

  std::size_t argument_index = 0;
  for (llvm::Argument &argument : function.args()) {
    store_slot(entry_builder, slot_allocas,
               program.argument_slots[argument_index++], &argument);
  }

  const std::uint32_t entry_pc = program.blocks.empty()
                                     ? 0
                                     : program.blocks.front().first_instruction;
  entry_builder.CreateStore(entry_builder.getInt32(static_cast<int>(entry_pc)), pc);
  entry_builder.CreateBr(dispatch_block);

  llvm::IRBuilder<> dispatch_builder(dispatch_block);
  llvm::Value *const current_pc =
      dispatch_builder.CreateLoad(dispatch_builder.getInt32Ty(), pc,
                                  "obf.vm.pc.load");
  auto *dispatch_switch = dispatch_builder.CreateSwitch(current_pc, trap_block,
                                                        instruction_blocks.size());
  for (std::size_t instruction_index = 0;
       instruction_index < instruction_blocks.size(); ++instruction_index) {
    dispatch_switch->addCase(dispatch_builder.getInt32(instruction_index),
                             instruction_blocks[instruction_index]);
  }

  const auto branch_to_dispatch = [&](llvm::IRBuilder<> &builder,
                                      std::uint32_t next_pc) {
    builder.CreateStore(builder.getInt32(static_cast<int>(next_pc)), pc);
    builder.CreateBr(dispatch_block);
  };

  const auto target_pc = [&](const control_edge &edge) {
    return program.blocks[edge.target_block].first_instruction;
  };

  for (std::size_t instruction_index = 0;
       instruction_index < program.instructions.size(); ++instruction_index) {
    const micro_instruction &instruction = program.instructions[instruction_index];
    llvm::IRBuilder<> builder(instruction_blocks[instruction_index]);

    const auto finish_value = [&](llvm::Value *result) {
      if (instruction.result_slot != invalid_slot) {
        store_slot(builder, slot_allocas, instruction.result_slot, result);
      }
      branch_to_dispatch(builder,
                         static_cast<std::uint32_t>(instruction_index + 1));
    };

    switch (instruction.op) {
    case opcode::binary:
      finish_value(emit_binary(builder, slot_allocas, program, instruction));
      break;
    case opcode::cast:
      finish_value(emit_cast(builder, slot_allocas, program, instruction));
      break;
    case opcode::freeze:
      finish_value(builder.CreateFreeze(
          materialize_value(builder, slot_allocas, program, instruction.operands[0]),
          "obf.vm.freeze"));
      break;
    case opcode::icmp:
      finish_value(builder.CreateICmp(
          static_cast<llvm::CmpInst::Predicate>(instruction.subtype),
          materialize_value(builder, slot_allocas, program, instruction.operands[0]),
          materialize_value(builder, slot_allocas, program, instruction.operands[1]),
          "obf.vm.icmp"));
      break;
    case opcode::fcmp: {
      auto *compare = llvm::cast<llvm::Instruction>(builder.CreateFCmp(
          static_cast<llvm::CmpInst::Predicate>(instruction.subtype),
          materialize_value(builder, slot_allocas, program, instruction.operands[0]),
          materialize_value(builder, slot_allocas, program, instruction.operands[1]),
          "obf.vm.fcmp"));
      apply_fast_math_flags(compare, instruction.flags);
      finish_value(compare);
      break;
    }
    case opcode::select:
      finish_value(builder.CreateSelect(
          materialize_value(builder, slot_allocas, program, instruction.operands[0]),
          materialize_value(builder, slot_allocas, program, instruction.operands[1]),
          materialize_value(builder, slot_allocas, program, instruction.operands[2]),
          "obf.vm.select"));
      break;
    case opcode::load: {
      auto *load = builder.CreateLoad(
          const_cast<llvm::Type *>(instruction.type),
          materialize_value(builder, slot_allocas, program, instruction.operands[0]),
          "obf.vm.load");
      if (instruction.immediate != 0) {
        load->setAlignment(llvm::Align(instruction.immediate));
      }
      finish_value(load);
      break;
    }
    case opcode::store: {
      auto *store = builder.CreateStore(
          materialize_value(builder, slot_allocas, program, instruction.operands[0]),
          materialize_value(builder, slot_allocas, program, instruction.operands[1]));
      if (instruction.immediate != 0) {
        store->setAlignment(llvm::Align(instruction.immediate));
      }
      branch_to_dispatch(builder,
                         static_cast<std::uint32_t>(instruction_index + 1));
      break;
    }
    case opcode::gep: {
      llvm::SmallVector<llvm::Value *, 4> indices;
      indices.reserve(instruction.operands.size() - 1);
      for (std::size_t operand_index = 1; operand_index < instruction.operands.size();
           ++operand_index) {
        indices.push_back(materialize_value(builder, slot_allocas, program,
                                            instruction.operands[operand_index]));
      }

      llvm::Value *gep = nullptr;
      llvm::Value *const pointer =
          materialize_value(builder, slot_allocas, program, instruction.operands[0]);
      if (has_instruction_flag(instruction.flags, instruction_flag_inbounds)) {
        gep = builder.CreateInBoundsGEP(const_cast<llvm::Type *>(instruction.type),
                                        pointer, indices, "obf.vm.gep");
      } else {
        gep = builder.CreateGEP(const_cast<llvm::Type *>(instruction.type), pointer,
                                indices, "obf.vm.gep");
      }
      finish_value(gep);
      break;
    }
    case opcode::call: {
      llvm::SmallVector<llvm::Value *, 8> arguments;
      arguments.reserve(instruction.operands.size() - 1);
      for (std::size_t operand_index = 1; operand_index < instruction.operands.size();
           ++operand_index) {
        arguments.push_back(materialize_value(builder, slot_allocas, program,
                                              instruction.operands[operand_index]));
      }

      auto *call = builder.CreateCall(
          llvm::cast<llvm::FunctionType>(const_cast<llvm::Type *>(instruction.type)),
          materialize_value(builder, slot_allocas, program, instruction.operands[0]),
          arguments,
          instruction.result_slot == invalid_slot ? "" : "obf.vm.call");
      call->setCallingConv(
          static_cast<llvm::CallingConv::ID>(instruction.subtype));
      call->setAttributes(instruction.attributes);
      apply_fast_math_flags(call, instruction.flags);
      if (instruction.result_slot != invalid_slot) {
        store_slot(builder, slot_allocas, instruction.result_slot, call);
      }
      branch_to_dispatch(builder,
                         static_cast<std::uint32_t>(instruction_index + 1));
      break;
    }
    case opcode::jump:
      apply_edge_assignments(builder, slot_allocas, program, instruction.edges[0]);
      branch_to_dispatch(builder, target_pc(instruction.edges[0]));
      break;
    case opcode::branch: {
      auto *true_block = llvm::BasicBlock::Create(
          context, "vm.edge.true." + std::to_string(instruction_index), &function);
      auto *false_block = llvm::BasicBlock::Create(
          context, "vm.edge.false." + std::to_string(instruction_index), &function);
      builder.CreateCondBr(
          materialize_value(builder, slot_allocas, program, instruction.operands[0]),
          true_block, false_block);

      llvm::IRBuilder<> true_builder(true_block);
      apply_edge_assignments(true_builder, slot_allocas, program, instruction.edges[0]);
      branch_to_dispatch(true_builder, target_pc(instruction.edges[0]));

      llvm::IRBuilder<> false_builder(false_block);
      apply_edge_assignments(false_builder, slot_allocas, program, instruction.edges[1]);
      branch_to_dispatch(false_builder, target_pc(instruction.edges[1]));
      break;
    }
    case opcode::switch_op: {
      auto *default_block = llvm::BasicBlock::Create(
          context, "vm.switch.default." + std::to_string(instruction_index), &function);
      auto *switch_inst = builder.CreateSwitch(
          materialize_value(builder, slot_allocas, program, instruction.operands[0]),
          default_block, instruction.case_values.size());

      llvm::SmallVector<llvm::BasicBlock *, 8> case_blocks;
      case_blocks.reserve(instruction.case_values.size());
      for (std::size_t case_index = 0; case_index < instruction.case_values.size();
           ++case_index) {
        auto *case_block = llvm::BasicBlock::Create(
            context,
            "vm.switch.case." + std::to_string(instruction_index) + "." +
                std::to_string(case_index),
            &function);
        switch_inst->addCase(const_cast<llvm::ConstantInt *>(instruction.case_values[case_index]),
                             case_block);
        case_blocks.push_back(case_block);
      }

      llvm::IRBuilder<> default_builder(default_block);
      apply_edge_assignments(default_builder, slot_allocas, program, instruction.edges[0]);
      branch_to_dispatch(default_builder, target_pc(instruction.edges[0]));

      for (std::size_t case_index = 0; case_index < case_blocks.size(); ++case_index) {
        llvm::IRBuilder<> case_builder(case_blocks[case_index]);
        apply_edge_assignments(case_builder, slot_allocas, program,
                               instruction.edges[case_index + 1]);
        branch_to_dispatch(case_builder, target_pc(instruction.edges[case_index + 1]));
      }
      break;
    }
    case opcode::unreachable_op:
      builder.CreateBr(trap_block);
      break;
    case opcode::ret:
      if (instruction.operands.empty()) {
        builder.CreateRetVoid();
      } else {
        builder.CreateRet(
            materialize_value(builder, slot_allocas, program, instruction.operands[0]));
      }
      break;
    }
  }

  llvm::IRBuilder<> trap_builder(trap_block);
  llvm::FunctionCallee trap = llvm::Intrinsic::getOrInsertDeclaration(
      function.getParent(), llvm::Intrinsic::trap);
  trap_builder.CreateCall(trap);
  trap_builder.CreateUnreachable();
}

} // namespace

virtualization_result run_virtualization(llvm::Function &function) {
  bytecode_program program;
  const candidate_result analysis = analyze_candidate(function, &program);
  if (!analysis.eligible) {
    return {.virtualized = false, .detail = analysis.detail};
  }

  rewrite_function_body(function, program);
  return {.virtualized = true,
          .instruction_count = analysis.instruction_count,
          .detail = std::to_string(analysis.instruction_count) +
                    " virtual instruction(s) emitted"};
}

} // namespace obf::vm
