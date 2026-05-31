#include "obf/vm/virtualize_internal.h"

#include "obf/support/stable_hash.h"

#include "llvm/IR/Constants.h"
#include "llvm/Support/raw_ostream.h"

#include <algorithm>
#include <bit>
#include <string>

namespace obf::vm {

namespace {

struct decoded_metadata_span_result {
  llvm::Value* assembled_word = nullptr;
  bool consumed = false;

  [[nodiscard]] bool valid() const { return consumed; }
};

struct bytecode_anchor_selection {
  llvm::GlobalVariable* anchor = nullptr;
  llvm::Value* base = nullptr;
  llvm::ArrayType* array_type = nullptr;

  [[nodiscard]] bool valid() const {
    return anchor != nullptr && base != nullptr && array_type != nullptr;
  }
};

std::uint32_t value_descriptor(const value_ref& value) {
  if (value.kind == value_ref_kind::slot) { return value.slot; }

  std::string printed;
  llvm::raw_string_ostream stream(printed);
  value.constant->printAsOperand(stream, /*PrintType=*/true);
  stream.flush();
  return static_cast<std::uint32_t>(stable_hash_string(printed));
}

std::uint8_t
derive_bytecode_key(std::uint64_t state, std::uint32_t offset, std::uint64_t seed_base) {
  const std::uint64_t mixed = state ^ std::rotr(state, 13) ^ mix_seed(seed_base, offset + 1);
  return static_cast<std::uint8_t>(mixed & 0xffU);
}

std::uint64_t advance_bytecode_state(std::uint64_t state, std::uint8_t decoded) {
  return (state << 8) | static_cast<std::uint64_t>(decoded);
}

std::uint64_t integrity_fold_state(std::uint64_t state, std::uint8_t ciphertext_byte) {
  const std::uint64_t rotated = std::rotr(state, 7);
  const std::uint64_t scaled = static_cast<std::uint64_t>(ciphertext_byte) * 0x517cc1b727220a95ULL;
  return state ^ (rotated + scaled);
}

void append_encoded_u8(std::vector<std::uint8_t>& bytes,
                       std::uint8_t decoded,
                       std::uint64_t& state,
                       std::uint64_t seed_base) {
  const std::uint32_t offset = static_cast<std::uint32_t>(bytes.size());
  bytes.push_back(decoded ^ derive_bytecode_key(state, offset, seed_base));
  state = advance_bytecode_state(state, decoded);
}

void append_encoded_u32(std::vector<std::uint8_t>& bytes,
                        std::uint32_t decoded,
                        std::uint64_t& state,
                        std::uint64_t seed_base) {
  for (unsigned byte_index = 0; byte_index < 4; ++byte_index) {
    append_encoded_u8(
        bytes, static_cast<std::uint8_t>(decoded >> (byte_index * 8)), state, seed_base);
  }
}

void append_rekey_state(std::vector<std::uint8_t>& bytes,
                        std::uint64_t target_state,
                        std::uint64_t& state,
                        std::uint64_t seed_base) {
  for (int shift = 56; shift >= 0; shift -= 8) {
    append_encoded_u8(bytes, static_cast<std::uint8_t>(target_state >> shift), state, seed_base);
  }
}

llvm::Value* load_byte_through_window(llvm::IRBuilder<>& builder,
                                      llvm::Value* array_base,
                                      llvm::ArrayType* array_type,
                                      std::uint32_t byte_offset,
                                      llvm::AllocaInst* opaque_seed_slot,
                                      std::uint64_t opaque_seed_base,
                                      const mba::builder_context& mba_context,
                                      std::uint64_t salt,
                                      llvm::StringRef name_prefix = "obf.vm.byte") {
  if (array_base == nullptr || array_type == nullptr || !array_base->getType()->isPointerTy() ||
      array_type->getElementType() != builder.getInt8Ty()) {
    return nullptr;
  }

  const llvm::DataLayout* data_layout = get_builder_data_layout(builder);
  if (data_layout == nullptr) { return nullptr; }

  const std::uint64_t byte_count = array_type->getNumElements();
  if (byte_offset >= byte_count) { return nullptr; }

  std::uint32_t window_bytes = 0;
  if (byte_count >= 4) {
    window_bytes = 4;
  } else if (byte_count >= 2) {
    window_bytes = 2;
  } else {
    return nullptr;
  }

  const std::uint64_t max_base = byte_count - window_bytes;
  std::uint64_t base_index = byte_offset >= window_bytes - 1 ? byte_offset - (window_bytes - 1) : 0;
  if (base_index > max_base) { base_index = max_base; }

  const std::uint64_t byte_index = byte_offset - base_index;
  const std::string base_name = name_prefix.empty() ? "obf.vm.byte" : name_prefix.str();
  auto* window_type = builder.getIntNTy(window_bytes * 8);

  auto* base_index_constant = llvm::ConstantInt::get(builder.getInt32Ty(), base_index);
  llvm::Value* base_index_value = materialize_integer_constant(builder,
                                                               *base_index_constant,
                                                               opaque_seed_slot,
                                                               opaque_seed_base,
                                                               mba_context,
                                                               salt ^ 0x5c0cULL);
  llvm::Value* window_ptr = builder.CreateInBoundsGEP(
      array_type, array_base, {builder.getInt32(0), base_index_value}, base_name + ".ptr");
  auto* window_load = builder.CreateLoad(window_type, window_ptr, base_name + ".window");
  window_load->setAlignment(llvm::Align(1));

  const std::uint64_t shift_bits =
      data_layout->isLittleEndian() ? byte_index * 8 : (window_bytes - 1 - byte_index) * 8;
  llvm::Value* window_value = window_load;
  if (shift_bits != 0) {
    auto* shift_constant = llvm::ConstantInt::get(window_type, shift_bits);
    llvm::Value* shift_value = materialize_integer_constant(builder,
                                                            *shift_constant,
                                                            opaque_seed_slot,
                                                            opaque_seed_base,
                                                            mba_context,
                                                            salt ^ 0x5d0dULL);
    window_value = builder.CreateLShr(window_value, shift_value, base_name + ".shr");
  }

  return builder.CreateTrunc(window_value, builder.getInt8Ty(), base_name);
}

llvm::Value* materialize_decode_round_constant(llvm::IRBuilder<>& builder,
                                               const rewrite_function_context& context,
                                               llvm::IntegerType* type,
                                               std::uint64_t value,
                                               std::uint64_t salt) {
  auto* constant = llvm::ConstantInt::get(type, value);
  llvm::Value* materialized = materialize_integer_constant(builder,
                                                           *constant,
                                                           context.opaque_seed_slot,
                                                           context.opaque_seed_base,
                                                           context.mba_context,
                                                           salt);
  return materialized != nullptr ? materialized : constant;
}

bytecode_anchor_selection select_bytecode_anchor(llvm::IRBuilder<>& builder,
                                                 const rewrite_function_context& context,
                                                 std::uint32_t offset,
                                                 std::uint64_t salt) {
  bytecode_anchor_selection selection;
  if (context.bytecode_global == nullptr) { return selection; }

  llvm::GlobalVariable* anchor = context.bytecode_global;
  // use all anchors (real + decoy) as candidates — decoys have identical content
  // so any selection is semantically correct; spreading reads across both pools
  // reduces xref concentration on any single anchor global.
  const std::uint32_t candidate_count =
      static_cast<std::uint32_t>(context.bytecode_anchor_globals.size());
  if (candidate_count > 0) {
    // double-mix for better per-site entropy: first fold offset and salt
    // together with a different multiplier, then mix with the function seed.
    // this reduces the modulo-clustering that a single mix_seed exhibits for
    // small candidate_count values (2-6) over a large range of offset values.
    const std::uint64_t site_key =
        mix_seed(static_cast<std::uint64_t>(offset) * 0xc4ceb9fe1a85ec53ULL ^ salt,
                 context.opaque_seed_base ^ (static_cast<std::uint64_t>(offset) + 1));
    const std::uint64_t selector = mix_seed(context.bytecode_seed, site_key);
    llvm::GlobalVariable* candidate =
        context.bytecode_anchor_globals[selector % static_cast<std::uint64_t>(candidate_count)];
    if (candidate != nullptr) { anchor = candidate; }
  }

  auto* array_type = llvm::dyn_cast<llvm::ArrayType>(anchor->getValueType());
  if (array_type == nullptr) { return selection; }

  llvm::Value* base = materialize_pointer_value(builder,
                                                anchor,
                                                context.opaque_seed_slot,
                                                context.opaque_seed_base,
                                                context.mba_context,
                                                salt ^ 0x5707ULL);
  if (base == nullptr) { base = anchor; }

  selection.anchor = anchor;
  selection.base = base;
  selection.array_type = array_type;
  return selection;
}

llvm::Value* decode_byte_and_advance_state(llvm::IRBuilder<>& builder,
                                           const rewrite_function_context& context,
                                           llvm::Value* encoded,
                                           llvm::Value*& state,
                                           std::uint32_t offset,
                                           llvm::Value* rotate_right,
                                           llvm::Value* rotate_left,
                                           llvm::Value* state_shift,
                                           std::uint64_t salt,
                                           llvm::StringRef name_prefix = "obf.vm.bc") {
  const std::string base_name = name_prefix.empty() ? "obf.vm.bc" : name_prefix.str();
  auto* state_type = builder.getInt64Ty();
  llvm::Value* rotated =
      builder.CreateOr(builder.CreateLShr(state, rotate_right, base_name + ".shr"),
                       builder.CreateShl(state, rotate_left, base_name + ".shl"),
                       base_name + ".rot");
  llvm::Value* key_mix = mba::create_xor(
      builder, state, rotated, context.mba_context, salt + 1, base_name + ".key.mix");
  llvm::Value* key_seed = materialize_decode_round_constant(
      builder,
      context,
      state_type,
      mix_seed(context.bytecode_seed, static_cast<std::uint64_t>(offset) + 1),
      salt ^ 0x6b6bULL);
  llvm::Value* key_word = mba::create_xor(
      builder, key_mix, key_seed, context.mba_context, salt + 2, base_name + ".key.word");
  llvm::Value* key = builder.CreateTrunc(key_word, builder.getInt8Ty(), base_name + ".key");
  llvm::Value* decoded =
      mba::create_xor(builder, encoded, key, context.mba_context, salt + 3, base_name + ".byte");
  llvm::Value* shifted_state = builder.CreateShl(state, state_shift, base_name + ".state.shift");
  llvm::Value* decoded_byte = builder.CreateZExt(decoded, state_type, base_name + ".state.byte");
  state = mba::create_add(builder,
                          shifted_state,
                          decoded_byte,
                          context.mba_context,
                          salt + 4,
                          base_name + ".state.next");
  return decoded;
}

llvm::Value* fetch_byte(llvm::IRBuilder<>& builder,
                        const rewrite_function_context& context,
                        std::uint32_t offset,
                        std::uint64_t salt) {
  bytecode_anchor_selection selection = select_bytecode_anchor(builder, context, offset, salt);
  if (!selection.valid()) { return builder.getInt8(0); }

  const std::uint64_t fetch_count = selection.array_type->getNumElements();
  if (offset >= fetch_count) { return builder.getInt8(0); }

  llvm::Value* slot = builder.CreateInBoundsGEP(selection.anchor->getValueType(),
                                                selection.base,
                                                {builder.getInt32(0), builder.getInt32(offset)},
                                                "obf.vm.bc.slot");
  llvm::Value* encoded =
      load_byte_through_window(builder,
                               selection.base,
                               selection.array_type,
                               offset,
                               context.opaque_seed_slot,
                               context.opaque_seed_base,
                               context.mba_context,
                               salt ^ 0x5e0eULL,
                               "obf.vm.bc.enc");
  if (encoded == nullptr) {
    encoded = builder.CreateLoad(builder.getInt8Ty(), slot, "obf.vm.bc.enc");
  }
  auto* state_type = builder.getInt64Ty();
  llvm::Value* rotate_right =
      materialize_decode_round_constant(builder, context, state_type, 13, salt ^ 0x6113ULL);
  llvm::Value* rotate_left =
      materialize_decode_round_constant(builder, context, state_type, 51, salt ^ 0x6151ULL);
  llvm::Value* state_shift =
      materialize_decode_round_constant(builder, context, state_type, 8, salt ^ 0x6108ULL);
  llvm::Value* state_value =
      builder.CreateLoad(builder.getInt64Ty(), context.state_slot, "obf.vm.bc.state.load");
  llvm::Value* decoded = decode_byte_and_advance_state(builder,
                                                       context,
                                                       encoded,
                                                       state_value,
                                                       offset,
                                                       rotate_right,
                                                       rotate_left,
                                                       state_shift,
                                                       salt ^ 0x6200ULL,
                                                       "obf.vm.bc");
  (void)builder.CreateStore(state_value, context.state_slot);
  return decoded;
}

decoded_metadata_span_result decode_metadata_span(llvm::IRBuilder<>& builder,
                                                  const rewrite_function_context& context,
                                                  std::uint32_t offset,
                                                  std::uint32_t length,
                                                  bool assemble_first_word,
                                                  std::uint64_t salt) {
  decoded_metadata_span_result result;
  if (context.bytecode_global == nullptr) { return result; }
  auto* array_type = llvm::dyn_cast<llvm::ArrayType>(context.bytecode_global->getValueType());
  const llvm::DataLayout* data_layout = get_builder_data_layout(builder);
  if (array_type == nullptr || data_layout == nullptr || !data_layout->isLittleEndian() ||
      length <= 1) {
    return result;
  }

  const std::uint64_t byte_count = array_type->getNumElements();
  if (static_cast<std::uint64_t>(offset) + length > byte_count) { return result; }

  llvm::Value* state =
      builder.CreateLoad(builder.getInt64Ty(), context.state_slot, "obf.vm.bc.state.span.load");
  llvm::Value* assembled_word = assemble_first_word ? builder.getInt32(0) : nullptr;
  auto* state_type = builder.getInt64Ty();
  llvm::Value* rotate_right =
      materialize_decode_round_constant(builder, context, state_type, 13, salt ^ 0x6213ULL);
  llvm::Value* rotate_left =
      materialize_decode_round_constant(builder, context, state_type, 51, salt ^ 0x6251ULL);
  llvm::Value* state_shift =
      materialize_decode_round_constant(builder, context, state_type, 8, salt ^ 0x6208ULL);
  for (std::uint32_t processed = 0; processed < length; ++processed) {
    const std::uint64_t byte_salt = salt + static_cast<std::uint64_t>(processed) * 8;
    const std::uint32_t byte_offset = offset + processed;
    bytecode_anchor_selection selection =
      select_bytecode_anchor(builder, context, byte_offset, byte_salt ^ 0x5f0fULL);
    if (!selection.valid()) { return result; }

    const std::uint64_t span_count = selection.array_type->getNumElements();
    if (byte_offset >= span_count) { return result; }

    llvm::Value* slot =
      builder.CreateInBoundsGEP(selection.array_type,
                    selection.base,
                                  {builder.getInt32(0), builder.getInt32(byte_offset)},
                                  "obf.vm.bc.span.ptr");
    llvm::Value* encoded = load_byte_through_window(builder,
                            selection.base,
                            selection.array_type,
                                                    byte_offset,
                                                    context.opaque_seed_slot,
                                                    context.opaque_seed_base,
                                                    context.mba_context,
                                                    byte_salt ^ 0x6000ULL,
                                                    "obf.vm.bc.span.enc");
    if (encoded == nullptr) {
      encoded = builder.CreateLoad(builder.getInt8Ty(), slot, "obf.vm.bc.span.enc");
    }
    llvm::Value* decoded = decode_byte_and_advance_state(builder,
                                                         context,
                                                         encoded,
                                                         state,
                                                         byte_offset,
                                                         rotate_right,
                                                         rotate_left,
                                                         state_shift,
                                                         byte_salt ^ 0x6300ULL,
                                                         "obf.vm.bc.span");

    if (assembled_word != nullptr && processed < 4) {
      llvm::Value* piece = builder.CreateZExt(decoded, builder.getInt32Ty(), "obf.vm.bc.word.byte");
      if (processed != 0) {
        piece = builder.CreateShl(piece,
                                  materialize_integer_constant(
                                      builder,
                                      *llvm::ConstantInt::get(builder.getInt32Ty(), processed * 8),
                                      context.opaque_seed_slot,
                                      context.opaque_seed_base,
                                      context.mba_context,
                                      byte_salt + 4),
                                  "obf.vm.bc.word.shl");
      }
      assembled_word = builder.CreateAdd(assembled_word, piece, "obf.vm.bc.word");
    }
  }

  (void)builder.CreateStore(state, context.state_slot);
  result.assembled_word = assembled_word;
  result.consumed = true;
  return result;
}

llvm::Value* fetch_u32(llvm::IRBuilder<>& builder,
                       const rewrite_function_context& context,
                       std::uint32_t offset,
                       std::uint64_t salt) {
  if (decoded_metadata_span_result span = decode_metadata_span(builder,
                                                               context,
                                                               offset,
                                                               4,
                                                               /*assemble_first_word=*/true,
                                                               salt ^ 0x6100ULL);
      span.valid()) {
    return span.assembled_word;
  }

  llvm::Value* word = builder.CreateZExt(
      fetch_byte(builder, context, offset, salt), builder.getInt32Ty(), "obf.vm.bc.word.0");
  for (unsigned byte_index = 1; byte_index < 4; ++byte_index) {
    llvm::Value* piece = builder.CreateShl(
        builder.CreateZExt(fetch_byte(builder, context, offset + byte_index, salt + byte_index),
                           builder.getInt32Ty(),
                           "obf.vm.bc.word.byte"),
        builder.getInt32(byte_index * 8),
        "obf.vm.bc.word.shl");
    word = builder.CreateOr(word, piece, "obf.vm.bc.word");
  }
  return word;
}

}  // namespace

serialized_bytecode_program
serialize_bytecode_program(const bytecode_program& program,
                           llvm::ArrayRef<std::uint32_t> dispatch_index_for_instruction,
                           llvm::ArrayRef<std::uint64_t> entry_states,
                           std::uint64_t seed_base,
                           const opcode_permutation& opcode_map) {
  serialized_bytecode_program serialized;
  serialized.layouts.resize(program.instructions.size());

  for (std::size_t instruction_index = 0; instruction_index < program.instructions.size();
       ++instruction_index) {
    const micro_instruction& instruction = program.instructions[instruction_index];
    bytecode_layout& layout = serialized.layouts[instruction_index];
    layout.header_offset = static_cast<std::uint32_t>(serialized.bytes.size());

    std::uint64_t header_state = entry_states[instruction_index];
    std::vector<pending_bytecode_header_chunk> header_chunks;
    header_chunks.reserve(10 + instruction.operands.size() * 2);

    std::uint64_t chunk_ordinal = 0;
    const auto next_header_order_key = [&](std::uint64_t salt) {
      return mix_seed(
          seed_base,
          salt ^ (static_cast<std::uint64_t>(instruction_index + 1) * 0x9e3779b97f4a7c15ULL) ^
              (++chunk_ordinal * 0x517cc1b727220a95ULL));
    };
    const auto append_header_u8 =
        [&](std::uint8_t decoded, std::uint64_t salt, bool carries_opcode = false) {
          pending_bytecode_header_chunk chunk;
          chunk.decoded_bytes[0] = decoded;
          chunk.order_key = next_header_order_key(salt ^ decoded);
          chunk.size = 1;
          chunk.carries_opcode = carries_opcode;
          header_chunks.push_back(chunk);
        };
    const auto append_header_u32 = [&](std::uint32_t decoded, std::uint64_t salt) {
      pending_bytecode_header_chunk chunk;
      for (unsigned byte_index = 0; byte_index < 4; ++byte_index) {
        chunk.decoded_bytes[byte_index] = static_cast<std::uint8_t>(decoded >> (byte_index * 8));
      }
      chunk.order_key = next_header_order_key(salt ^ decoded);
      chunk.size = 4;
      header_chunks.push_back(chunk);
    };

    append_header_u8(get_physical_opcode(opcode_map, instruction.op),
                     0x4100,
                     /*carries_opcode=*/true);
    append_header_u32(instruction.subtype, 0x4200);
    append_header_u32(instruction.flags, 0x4300);
    append_header_u32(instruction.immediate, 0x4400);
    append_header_u32(instruction.result_slot, 0x4500);
    append_header_u8(static_cast<std::uint8_t>(instruction.operands.size()), 0x4600);
    for (const value_ref& operand : instruction.operands) {
      const std::uint64_t operand_salt =
          0x4700 + static_cast<std::uint64_t>(&operand - instruction.operands.data()) * 2;
      append_header_u8(static_cast<std::uint8_t>(operand.kind), operand_salt);
      append_header_u32(value_descriptor(operand), operand_salt + 1);
    }
    append_header_u8(static_cast<std::uint8_t>(instruction.edges.size()), 0x4800);

    const std::uint32_t junk_chunk_count =
        1U + static_cast<std::uint32_t>(mix_seed(seed_base, 0x4d4554410000ULL + instruction_index) %
                                        3ULL);
    for (std::uint32_t junk_index = 0; junk_index < junk_chunk_count; ++junk_index) {
      pending_bytecode_header_chunk chunk;
      chunk.size = static_cast<std::uint8_t>(
          1U + mix_seed(seed_base,
                        0x4d4554411000ULL + static_cast<std::uint64_t>(instruction_index) * 8 +
                            junk_index) %
                   4ULL);
      chunk.order_key = next_header_order_key(0x4d4554412000ULL + junk_index);
      for (std::uint8_t byte_index = 0; byte_index < chunk.size; ++byte_index) {
        chunk.decoded_bytes[byte_index] = static_cast<std::uint8_t>(
            mix_seed(seed_base,
                     0x4d4554413000ULL + static_cast<std::uint64_t>(instruction_index) * 16 +
                         static_cast<std::uint64_t>(junk_index) * 4 + byte_index) &
            0xffU);
      }
      header_chunks.push_back(chunk);
    }

    std::stable_sort(
        header_chunks.begin(),
        header_chunks.end(),
        [](const pending_bytecode_header_chunk& lhs, const pending_bytecode_header_chunk& rhs) {
          return lhs.order_key < rhs.order_key;
        });
    layout.header_chunks.reserve(header_chunks.size());
    for (const pending_bytecode_header_chunk& chunk : header_chunks) {
      layout.header_chunks.push_back({.offset = static_cast<std::uint32_t>(serialized.bytes.size()),
                                      .size = chunk.size,
                                      .carries_opcode = chunk.carries_opcode});
      for (unsigned byte_index = 0; byte_index < chunk.size; ++byte_index) {
        append_encoded_u8(
            serialized.bytes, chunk.decoded_bytes[byte_index], header_state, seed_base);
      }
    }

    layout.integrity_probe_range = static_cast<std::uint32_t>(serialized.bytes.size());
    if (layout.integrity_probe_range > 0) {
      const std::uint32_t num_probes =
          2U +
          static_cast<std::uint32_t>(mix_seed(seed_base, 0xfade0000ULL + instruction_index) % 3);
      for (std::uint32_t probe = 0; probe < num_probes; ++probe) {
        const std::uint32_t probe_offset = static_cast<std::uint32_t>(
            mix_seed(seed_base,
                     static_cast<std::uint64_t>(instruction_index) * 0x1337ULL + probe + 1) %
            layout.integrity_probe_range);
        header_state = integrity_fold_state(header_state, serialized.bytes[probe_offset]);
      }
    }

    layout.expected_post_header_state = header_state;

    const auto append_target_segment = [&](std::uint32_t target_instruction) {
      std::uint64_t segment_state = header_state;
      const std::uint32_t offset = static_cast<std::uint32_t>(serialized.bytes.size());
      append_encoded_u32(serialized.bytes,
                         dispatch_index_for_instruction[target_instruction],
                         segment_state,
                         seed_base);
      append_rekey_state(
          serialized.bytes, entry_states[target_instruction], segment_state, seed_base);
      return offset;
    };

    switch (instruction.op) {
      case opcode::jump:
      case opcode::branch:
      case opcode::switch_op:
        for (const control_edge& edge : instruction.edges) {
          layout.edge_target_offsets.push_back(
              append_target_segment(program.blocks[edge.target_block].first_instruction));
        }
        break;
      case opcode::ret:
      case opcode::unreachable_op:
        break;
      default:
        layout.fallthrough_target_offset =
            append_target_segment(static_cast<std::uint32_t>(instruction_index + 1));
        break;
    }
  }

  return serialized;
}

llvm::Value* consume_metadata(llvm::IRBuilder<>& builder,
                              const rewrite_function_context& context,
                              const bytecode_layout& layout,
                              std::uint64_t salt) {
  std::uint64_t local_salt = salt;
  llvm::Value* decoded_opcode = nullptr;
  for (const bytecode_header_chunk& chunk : layout.header_chunks) {
    if (chunk.carries_opcode) {
      decoded_opcode = fetch_byte(builder, context, chunk.offset, local_salt++);
      continue;
    }
    if (chunk.size == 4) {
      (void)fetch_u32(builder, context, chunk.offset, local_salt);
      local_salt += 4;
      continue;
    }
    if (chunk.size > 1) {
      if (decode_metadata_span(builder,
                               context,
                               chunk.offset,
                               chunk.size,
                               /*assemble_first_word=*/false,
                               local_salt ^ 0x6200ULL)
              .valid()) {
        local_salt += chunk.size;
        continue;
      }
    }
    for (std::uint32_t byte_index = 0; byte_index < chunk.size; ++byte_index) {
      (void)fetch_byte(builder, context, chunk.offset + byte_index, local_salt++);
    }
  }
  if (decoded_opcode != nullptr) { return decoded_opcode; }
  llvm_unreachable("serialized vm header missing opcode");
}

llvm::Value* decode_target_dispatch(llvm::IRBuilder<>& builder,
                                    const rewrite_function_context& context,
                                    std::uint32_t offset,
                                    std::uint64_t salt) {
  if (decoded_metadata_span_result span = decode_metadata_span(builder,
                                                               context,
                                                               offset,
                                                               12,
                                                               /*assemble_first_word=*/true,
                                                               salt ^ 0x6300ULL);
      span.valid()) {
    return span.assembled_word;
  }

  llvm::Value* target = fetch_u32(builder, context, offset, salt);
  for (unsigned byte_index = 0; byte_index < 8; ++byte_index) {
    (void)fetch_byte(builder, context, offset + 4 + byte_index, salt + 4 + byte_index);
  }
  return target;
}

void emit_instruction_integrity_probes(llvm::IRBuilder<>& builder,
                                       const instruction_rewrite_context& context) {
  const bytecode_layout& layout = context.layout;
  if (layout.integrity_probe_range == 0 || context.function_context.bytecode_global == nullptr) {
    return;
  }

  const std::uint32_t num_probes =
      2U + static_cast<std::uint32_t>(mix_seed(context.function_context.bytecode_seed,
                                               0xfade0000ULL + context.instruction_index) %
                                      3);
  for (std::uint32_t probe = 0; probe < num_probes; ++probe) {
    const std::uint32_t probe_offset = static_cast<std::uint32_t>(
        mix_seed(context.function_context.bytecode_seed,
                 static_cast<std::uint64_t>(context.instruction_index) * 0x1337ULL + probe + 1) %
        layout.integrity_probe_range);
    const std::uint64_t probe_salt =
      0x5800 + static_cast<std::uint64_t>(context.instruction_index) * 4 + probe;
    bytecode_anchor_selection selection =
      select_bytecode_anchor(builder, context.function_context, probe_offset, probe_salt);
    if (!selection.valid()) { continue; }

    const std::uint64_t probe_count = selection.array_type->getNumElements();
    if (probe_offset >= probe_count) { continue; }

    llvm::Value* byte_ptr =
      builder.CreateInBoundsGEP(selection.anchor->getValueType(),
                    selection.base,
                                  {builder.getInt32(0), builder.getInt32(probe_offset)},
                                  "obf.vm.integrity.ptr");
    llvm::Value* cipher_byte = load_byte_through_window(
        builder,
      selection.base,
      selection.array_type,
        probe_offset,
        context.function_context.opaque_seed_slot,
        context.function_context.opaque_seed_base,
        context.function_context.mba_context,
        0x5900 + static_cast<std::uint64_t>(context.instruction_index) * 4 + probe,
        "obf.vm.integrity.byte");
    if (cipher_byte == nullptr) {
      cipher_byte = builder.CreateLoad(builder.getInt8Ty(), byte_ptr, "obf.vm.integrity.byte");
    }
    auto* integrity_state = builder.CreateLoad(
        builder.getInt64Ty(), context.function_context.state_slot, "obf.vm.integrity.state");
    llvm::Value* rotated = builder.CreateOr(
        builder.CreateLShr(integrity_state, builder.getInt64(7), "obf.vm.integrity.shr"),
        builder.CreateShl(integrity_state, builder.getInt64(57), "obf.vm.integrity.shl"),
        "obf.vm.integrity.rot");
    llvm::Value* extended =
        builder.CreateZExt(cipher_byte, builder.getInt64Ty(), "obf.vm.integrity.ext");
    llvm::Value* scaled = builder.CreateMul(
        extended, builder.getInt64(0x517cc1b727220a95ULL), "obf.vm.integrity.scale");
    llvm::Value* folded =
        builder.CreateXor(integrity_state,
                          builder.CreateAdd(rotated, scaled, "obf.vm.integrity.sum"),
                          "obf.vm.integrity.fold");
    (void)builder.CreateStore(folded, context.function_context.state_slot);
  }
}

}  // namespace obf::vm
