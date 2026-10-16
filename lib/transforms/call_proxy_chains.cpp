#include "obf/transforms/call_proxy_chains.h"

#include "obf/report/coverage_report.h"
#include "obf/support/runtime_abi_generated.h"
#include "obf/support/stable_hash.h"
#include "obf/transforms/mba.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/DenseSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/Analysis/ValueTracking.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Dominators.h"
#include "llvm/IR/GlobalAlias.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Metadata.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/TargetParser/Triple.h"

#include <algorithm>
#include <array>
#include <limits>
#include <optional>
#include <map>
#include <set>
#include <sstream>
#include <tuple>

namespace obf {
namespace {
using namespace llvm;
constexpr StringLiteral entry_md = "obf.lto.proxy.entry";
constexpr StringLiteral operation_md = "obf.lto.proxy.operation";
constexpr StringLiteral fingerprint_attr = "obf.lto.proxy.fingerprint";
bool is_exact_finalization_guard(const Instruction&);

enum context_field : unsigned {
  schema,
  phase,
  owner_id,
  site_id,
  route_id,
  descriptor_index,
  step,
  expected_node,
  entropy_snapshot,
  observed_continuation,
  root,
  token,
  admitted_target,
  encoded_target,
  context_field_count
};

[[noreturn]] void fail(Module& module, StringRef reason) {
  record_coverage_event(module, "finalization", "call_proxy", "", "", "failed", reason);
  write_coverage_report(module);
  report_fatal_error(Twine("call proxy: ") + reason);
}

std::uint64_t hash(StringRef text) { return stable_hash_string(text); }
std::uint64_t combine(std::uint64_t a, std::uint64_t b) { return mix_seed(a, b); }
std::uint64_t nonzero(std::uint64_t value) { return value ? value : 1; }
std::string number(std::uint64_t n) { return std::to_string(n); }
std::uint64_t hash_route_identity(std::uint64_t decision_seed,
                                  const source_site_identity& identity) {
  // Fixed-width little-endian fields keep the tuple ordered and unambiguous.
  std::array<char, 16> bytes;
  for (unsigned i = 0; i < 8; ++i) {
    bytes[i] = static_cast<char>(identity.site_id >> (i * 8));
    bytes[i + 8] = static_cast<char>(identity.instance_id >> (i * 8));
  }
  return stable_hash_string(StringRef(bytes.data(), bytes.size()), decision_seed);
}
std::uint64_t checked_add(Module& m, std::uint64_t a, std::uint64_t b) {
  if (b > std::numeric_limits<std::uint64_t>::max() - a) fail(m, "resource count overflow");
  return a + b;
}
std::uint64_t checked_mul(Module& m, std::uint64_t a, std::uint64_t b) {
  if (a && b > std::numeric_limits<std::uint64_t>::max() / a) fail(m, "resource product overflow");
  return a * b;
}
std::uint64_t integer(StringRef text, Module& m) {
  std::uint64_t result = 0;
  if (text.getAsInteger(10, result)) fail(m, "invalid retained integer");
  return result;
}

StructType* context_type(LLVMContext& c) {
  auto* i32 = Type::getInt32Ty(c);
  auto* i64 = Type::getInt64Ty(c);
  return StructType::get(
      c, {i32, i32, i64, i64, i64, i32, i32, i64, i64, i64, i64, i64, PointerType::get(c, 0), i64});
}
std::uint64_t context_size(Module& m) {
  auto* type = context_type(m.getContext());
  const auto size = m.getDataLayout().getTypeAllocSize(type);
  if (size.isScalable()) fail(m, "scalable context allocation");
  const auto align = m.getDataLayout().getABITypeAlign(type).value();
  return checked_add(m, size.getFixedValue(), align - 1) / align * align;
}

void mark(Instruction& i, std::uint64_t route, StringRef role) {
  auto& c = i.getContext();
  i.setMetadata(operation_md,
                MDNode::get(c, {MDString::get(c, number(route)), MDString::get(c, role)}));
}
void mark_value(Value* v, std::uint64_t route, StringRef role) {
  if (auto* i = dyn_cast<Instruction>(v)) mark(*i, route, role);
}

Value* field(IRBuilder<>& b, Value* ctx, unsigned index) {
  return b.CreateStructGEP(context_type(b.getContext()), ctx, index);
}
Value* load(IRBuilder<>& b, Value* ctx, unsigned index) {
  return b.CreateLoad(context_type(b.getContext())->getElementType(index), field(b, ctx, index));
}
StoreInst* store(IRBuilder<>& b, Value* ctx, unsigned index, Value* value) {
  return b.CreateStore(value, field(b, ctx, index));
}
Value* rotate(IRBuilder<>& b, Value* x, unsigned amount, bool right = false) {
  if (right) amount = 64 - amount;
  return b.CreateOr(b.CreateShl(x, amount), b.CreateLShr(x, 64 - amount));
}
Value* mix(IRBuilder<>& b, Value* x) {
  x = b.CreateXor(x, b.CreateLShr(x, 30));
  x = b.CreateMul(x, b.getInt64(0xbf58476d1ce4e5b9ULL));
  x = b.CreateXor(x, b.CreateLShr(x, 27));
  x = b.CreateMul(x, b.getInt64(0x94d049bb133111ebULL));
  return b.CreateXor(x, b.CreateLShr(x, 31));
}
Value* transition(IRBuilder<>& b, Value* p, const proxy_node_descriptor& n) {
  return b.CreateAdd(b.CreateMul(rotate(b, b.CreateXor(p, b.getInt64(n.constant)), n.rotation),
                                 b.getInt64(n.multiplier)),
                     b.getInt64(n.addend));
}
Value* prefix(IRBuilder<>& b, Value* r, const proxy_route_descriptor& route, unsigned count) {
  Value* p = mix(b, b.CreateXor(r, b.getInt64(route.route_id)));
  for (unsigned i = 0; i < count; ++i) p = transition(b, p, route.nodes[i]);
  return p;
}
Value* recompute_root(IRBuilder<>& b, Value* ctx, const proxy_route_descriptor& route) {
  auto* x = b.CreateXor(load(b, ctx, entropy_snapshot), load(b, ctx, observed_continuation));
  x = b.CreateXor(x, b.getInt64(route.source.site.identity.site_id));
  return mix(b, b.CreateXor(x, b.getInt64(route.route_seed)));
}

bool abi_attribute(Attribute a) {
  if (a.isStringAttribute()) return false;
  switch (a.getKindAsEnum()) {
    case Attribute::SExt:
    case Attribute::ZExt:
    case Attribute::InReg:
    case Attribute::ByVal:
    case Attribute::StructRet:
    case Attribute::Alignment:
      return true;
    default:
      return false;
  }
}
AttributeList fresh_attributes(LLVMContext& c, AttributeList source, unsigned parameters) {
  SmallVector<std::pair<unsigned, Attribute>, 16> attrs;
  for (Attribute a : source.getRetAttrs())
    if (abi_attribute(a)) attrs.emplace_back(AttributeList::ReturnIndex, a);
  for (unsigned i = 0; i < parameters; ++i)
    for (Attribute a : source.getParamAttrs(i))
      if (abi_attribute(a)) attrs.emplace_back(i + 1, a);
  return AttributeList::get(c, attrs);
}
std::string printed_type(Type* type) {
  std::string text;
  raw_string_ostream out(text);
  const auto emit = [&](Type* t, auto&& self) -> void {
    out << unsigned(t->getTypeID()) << '[';
    if (auto* integer = dyn_cast<IntegerType>(t)) out << integer->getBitWidth();
    else if (auto* pointer = dyn_cast<PointerType>(t))
      out << pointer->getAddressSpace();
    else if (auto* array = dyn_cast<ArrayType>(t)) {
      out << array->getNumElements() << ':';
      self(array->getElementType(), self);
    } else if (auto* vector = dyn_cast<VectorType>(t)) {
      out << vector->getElementCount().getKnownMinValue() << ':'
          << vector->getElementCount().isScalable();
      self(vector->getElementType(), self);
    } else if (auto* structure = dyn_cast<StructType>(t)) {
      out << structure->isPacked() << ':' << structure->isOpaque();
      if (!structure->isOpaque())
        for (Type* element : structure->elements()) self(element, self);
    } else if (auto* function = dyn_cast<FunctionType>(t)) {
      out << function->isVarArg() << ':';
      self(function->getReturnType(), self);
      for (Type* parameter : function->params()) self(parameter, self);
    }
    out << ']';
  };
  emit(type, emit);
  return text;
}

void print_abi(raw_ostream& out, AttributeList attrs, unsigned parameters) {
  for (unsigned i = 0; i <= parameters; ++i) {
    out << i << '{';
    for (Attribute a : i ? attrs.getParamAttrs(i - 1) : attrs.getRetAttrs()) {
      if (!abi_attribute(a)) continue;
      out << unsigned(a.getKindAsEnum()) << ':';
      if (a.isTypeAttribute()) out << printed_type(a.getValueAsType());
      else if (a.isIntAttribute())
        out << a.getValueAsInt();
      out << ',';
    }
    out << '}';
  }
}
std::string abi_key(const CallBase& call) {
  std::string text;
  raw_string_ostream out(text);
  out << printed_type(call.getFunctionType()) << ':' << call.getCallingConv() << ':';
  print_abi(out, call.getAttributes(), call.arg_size());
  for (StringRef name :
       {"target-cpu", "target-features", "tune-cpu", "frame-pointer", "no-red-zone"})
    out << ':' << name << '=' << call.getFunction()->getFnAttribute(name).getValueAsString();
  return number(hash(out.str()));
}

std::string dependency_abi_key(const Function& function) {
  std::string text;
  raw_string_ostream out(text);
  out << printed_type(function.getFunctionType()) << ':' << function.getCallingConv() << ':';
  print_abi(out, function.getAttributes(), function.arg_size());
  for (StringRef name :
       {"target-cpu", "target-features", "tune-cpu", "frame-pointer", "no-red-zone"})
    out << ':' << name << '=' << function.getFnAttribute(name).getValueAsString();
  return number(hash(out.str()));
}

bool special(const Function& f) {
  for (auto a : {Attribute::ReturnsTwice,
                 Attribute::Convergent,
                 Attribute::Naked,
                 Attribute::NoDuplicate,
                 Attribute::NoMerge,
                 Attribute::PresplitCoroutine})
    if (f.hasFnAttribute(a)) return true;
  return f.hasFnAttribute("coroutine.presplit") || f.hasFnAttribute("thunk");
}

bool forbidden_abi(Attribute a) {
  if (a.isStringAttribute()) return true;
  switch (a.getKindAsEnum()) {
    case Attribute::InAlloca:
    case Attribute::Preallocated:
    case Attribute::ByRef:
    case Attribute::Nest:
    case Attribute::SwiftSelf:
    case Attribute::SwiftError:
    case Attribute::SwiftAsync:
    case Attribute::ElementType:
      return true;
    default:
      return false;
  }
}

bool compatible_subtarget(const Function& a, const Function& b) {
  for (StringRef key :
       {"target-cpu", "target-features", "tune-cpu", "frame-pointer", "no-red-zone"}) {
    const auto av = a.getFnAttribute(key);
    const auto bv = b.getFnAttribute(key);
    if (bv.isValid() && av != bv) return false;
  }
  return true;
}

Function* exact_target(Value* value) {
  SmallPtrSet<Value*, 8> seen;
  while (value && seen.insert(value).second) {
    if (auto* function = dyn_cast<Function>(value)) return function;
    if (auto* alias = dyn_cast<GlobalAlias>(value)) {
      if (!alias->isDSOLocal() || alias->isInterposable() || alias->hasExternalWeakLinkage())
        return nullptr;
      value = alias->getAliasee();
      continue;
    }
    if (auto* cast = dyn_cast<ConstantExpr>(value)) {
      if (cast->getOpcode() != Instruction::BitCast) return nullptr;
      value = cast->getOperand(0);
      continue;
    }
    return nullptr;
  }
  return nullptr;
}

void copy_codegen(const Function& source, Function& target) {
  for (StringRef key :
       {"target-cpu", "target-features", "tune-cpu", "frame-pointer", "no-red-zone"}) {
    auto a = source.getFnAttribute(key);
    if (a.isValid()) target.addFnAttr(a);
  }
  for (auto a : {Attribute::SanitizeAddress,
                 Attribute::SanitizeThread,
                 Attribute::SanitizeMemory,
                 Attribute::SanitizeHWAddress,
                 Attribute::ShadowCallStack,
                 Attribute::SafeStack,
                 Attribute::StackProtect,
                 Attribute::StackProtectReq,
                 Attribute::StackProtectStrong})
    if (source.hasFnAttribute(a)) target.addFnAttr(a);
  target.setUWTableKind(UWTableKind::Async);
}

FunctionType* private_type(const proxy_route_descriptor& r) {
  auto* call = cast<CallBase>(static_cast<Value*>(r.source.site.replacement_call));
  if (r.source.admission.mode == proxy_route_mode::abi_only) return call->getFunctionType();
  SmallVector<Type*, 16> args(call->getFunctionType()->params());
  args.push_back(PointerType::get(call->getContext(), 0));
  return FunctionType::get(call->getType(), args, false);
}

void trap(IRBuilder<>& b, Module& m) {
  b.CreateCall(Intrinsic::getOrInsertDeclaration(&m, Intrinsic::trap));
  b.CreateUnreachable();
}
void check(
    IRBuilder<>& b, Value* condition, BasicBlock* failure, StringRef role, std::uint64_t route) {
  auto* ok = BasicBlock::Create(b.getContext(), "proxy.valid", b.GetInsertBlock()->getParent());
  auto* branch = b.CreateCondBr(condition, ok, failure);
  mark(*branch, route, role);
  b.SetInsertPoint(ok);
}
void equal(IRBuilder<>& b,
           Value* a,
           Value* expected,
           BasicBlock* failure,
           StringRef role,
           std::uint64_t route) {
  check(b, b.CreateICmpEQ(a, expected), failure, role, route);
}

Value* entropy(IRBuilder<>& b, Module& m) {
  mba::get_or_create_entropy_anchor(m);
  auto* pair = StructType::get(b.getContext(), {b.getInt64Ty(), b.getInt64Ty()});
  auto* type = FunctionType::get(pair, false);
  auto callee = m.getOrInsertFunction(OBF_RT_LOAD_ENTROPY_PAIR_STR, type);
  auto* function = dyn_cast<Function>(callee.getCallee());
  if (!function || function->getFunctionType() != type)
    fail(m, "entropy accessor has an incompatible ABI");
  function->setDoesNotThrow();
  if (Triple(m.getTargetTriple()).isOSWindows()) function->setCallingConv(CallingConv::X86_64_SysV);
  auto* call = b.CreateCall(type, function, {}, "proxy.entropy.pair");
  call->setCallingConv(function->getCallingConv());
  return b.CreateXor(b.CreateExtractValue(call, 0), b.CreateExtractValue(call, 1), "proxy.entropy");
}

void decoys(IRBuilder<>& b,
            Value* input,
            BasicBlock* failure,
            const call_proxy_options& options,
            std::uint64_t route) {
  mba::builder_context context;
  context.depth = 0;
  context.max_ir_instructions_override = 0;
  for (unsigned i = 0; i < options.decoy_budget; ++i) {
    auto* product = mba::create_mul(b, input, input, context, route + i, "proxy.decoy.square");
    auto* even = b.CreateAnd(b.CreateAdd(product, input), b.getInt64(1));
    equal(b, even, b.getInt64(0), failure, "inert.decoy", route);
  }
}

SmallVector<Value*, 16> arguments(Function& f, bool strip_context = false) {
  SmallVector<Value*, 16> args;
  for (Argument& a : f.args()) args.push_back(&a);
  if (strip_context) args.pop_back();
  return args;
}
void return_call(IRBuilder<>& b, CallInst& call) {
  if (call.getType()->isVoidTy()) b.CreateRetVoid();
  else
    b.CreateRet(&call);
}

void clear_effects(Function& f) {
  for (auto a : {Attribute::Memory,
                 Attribute::Speculatable,
                 Attribute::WillReturn,
                 Attribute::MustProgress,
                 Attribute::NoSync,
                 Attribute::NoFree})
    f.removeFnAttr(a);
}
void clear_effects(CallBase& call) {
  for (auto a : {Attribute::Memory,
                 Attribute::Speculatable,
                 Attribute::WillReturn,
                 Attribute::MustProgress,
                 Attribute::NoSync,
                 Attribute::NoFree})
    call.removeFnAttr(a);
}
void invalidate_effects(Module& m, ArrayRef<Function*> changed) {
  SmallPtrSet<Function*, 32> affected;
  for (Function* f : changed) affected.insert(f);
  bool again = true;
  while (again) {
    again = false;
    for (Function& f : m) {
      bool touches = affected.contains(&f);
      for (Instruction& i : instructions(f)) {
        auto* call = dyn_cast<CallBase>(&i);
        if (!call) continue;
        bool incoming = false;
        if (auto* target = exact_target(call->getCalledOperand()))
          incoming = affected.contains(target);
        else if (auto* callees = call->getMetadata(LLVMContext::MD_callees)) {
          for (const MDOperand& operand : callees->operands())
            if (auto* value = dyn_cast_or_null<ValueAsMetadata>(operand.get()))
              if (auto* target = dyn_cast<Function>(value->getValue()))
                incoming |= affected.contains(target);
        } else {
          for (Function* target : affected)
            if (target->hasAddressTaken() && target->getFunctionType() == call->getFunctionType()) {
              incoming = true;
              break;
            }
        }
        if (incoming) {
          clear_effects(*call);
          touches = true;
        }
      }
      if (touches && affected.insert(&f).second) again = true;
    }
  }
  for (Function* f : affected) clear_effects(*f);
}

void collect_vm_proxy_dependencies(const live_proxy_site& site, proxy_admission& admission) {
  if (!site.is_vm || site.preserved_musttail) return;
  Value* boundary = static_cast<Value*>(site.replacement_call);
  SmallVector<Value*, 32> work;
  for (Value* root : {static_cast<Value*>(site.decoded_target),
                      static_cast<Value*>(site.hidden_token_operand),
                      static_cast<Value*>(site.return_decode_root)})
    if (root) work.push_back(root);
  SmallPtrSet<Value*, 32> seen;
  SmallPtrSet<Function*, 16> functions;
  while (!work.empty()) {
    Value* value = work.pop_back_val();
    if (value == boundary || !seen.insert(value).second || isa<GlobalValue>(value)) continue;
    if (auto* load = dyn_cast<LoadInst>(value))
      if (!load->isAtomic() && isa<GlobalVariable>(getUnderlyingObject(load->getPointerOperand())))
        admission.preserved_global_loads.emplace_back(load);
    if (auto* call = dyn_cast<CallBase>(value))
      if (auto* function = call->getCalledFunction();
          function && function->hasLocalLinkage() && !function->isDeclaration() &&
          !function->isIntrinsic() && functions.insert(function).second) {
        proxy_dependency_descriptor dependency;
        dependency.identity = nonzero(combine(site.identity.module_id, hash(function->getName())));
        if (function->hasFnAttribute("obf.lto.proxy.dependency"))
          dependency.identity =
              integer(function->getFnAttribute("obf.lto.proxy.dependency").getValueAsString(),
                      *function->getParent());
        dependency.function = function;
        dependency.abi_identity = dependency_abi_key(*function);
        admission.dependencies.push_back(std::move(dependency));
      }
    if (auto* user = dyn_cast<User>(value))
      for (const Use& operand : user->operands()) work.push_back(operand.get());
  }
  std::sort(admission.dependencies.begin(),
            admission.dependencies.end(),
            [](const auto& a, const auto& b) { return a.identity < b.identity; });
}

}  // namespace

proxy_platform_contract proxy_platform_contract_for(const Module& module) {
  proxy_platform_contract p;
  Triple triple(module.getTargetTriple());
  const auto& dl = module.getDataLayout();
  p.windows = triple.isOSWindows();
  p.byval = !p.windows;
  p.vector = !p.windows;
  p.supported = triple.getArch() == Triple::x86_64 &&
                ((triple.isOSLinux() && triple.isOSBinFormatELF()) ||
                 (triple.isOSWindows() && triple.isOSBinFormatCOFF())) &&
                dl.getPointerSizeInBits(0) == 64 && dl.getAllocaAddrSpace() == 0 &&
                !dl.isNonIntegralAddressSpace(0);
  p.identity =
      proxy_qualification_identity.str() + (p.windows ? ":pe32plus-no-byval-no-vector" : ":elf");
  if (!p.supported)
    p.rejection =
        "requires Linux ELF or native Windows PE32+ x86-64 integral address-space-zero pointers";
  for (StringRef flag : {"CFI Canonical Jump Tables", "Cross-DSO CFI", "kcfi"})
    if (module.getModuleFlag(flag)) p.terminal_hardening = false;
  for (const Function& function : module)
    for (const Instruction& i : instructions(function))
      if (const auto* intrinsic = dyn_cast<IntrinsicInst>(&i))
        if (intrinsic->getIntrinsicID() == Intrinsic::type_test ||
            intrinsic->getIntrinsicID() == Intrinsic::type_checked_load)
          p.terminal_hardening = false;
  return p;
}

std::string call_proxy_configuration_identity(const call_proxy_options& o) {
  std::ostringstream s;
  s << call_proxy_schema << ':' << proxy_qualification_identity.str() << ':' << o.enabled << ':'
    << o.min_hops << ':' << o.max_hops << ':' << static_cast<unsigned>(o.mode_policy) << ':'
    << static_cast<unsigned>(o.coverage_policy) << ':' << o.share_nodes << ':' << o.decoy_budget
    << ':' << o.max_sites_per_owner << ':' << o.max_nodes_per_module << ':'
    << o.max_context_bytes_per_owner << ':' << o.max_routes_per_shared_node << ':'
    << o.max_added_ir_instructions;
  return s.str();
}

bool is_call_proxy_helper(const Function& f) {
  auto role = f.getFnAttribute("obf.lto.proxy.role").getValueAsString();
  return role == "hop" || role == "bridge" || role == "check" ||
         f.hasFnAttribute("obf.call.proxy.hop") || f.hasFnAttribute("obf.call.proxy.bridge") ||
         f.hasFnAttribute("obf.lto.proxy.dependency");
}
bool is_call_proxy_entry(const CallBase& call) { return call.getMetadata(entry_md) != nullptr; }

proxy_admission analyze_proxy_site(const live_proxy_site& site,
                                   const proxy_platform_contract& p,
                                   const call_proxy_options& options) {
  proxy_admission result;
  const auto reject = [&](StringRef code, StringRef diagnostic) {
    result.code = code.str();
    result.diagnostic = diagnostic.str();
    return result;
  };
  if (site.preserved_unsupported)
    return reject(site.preservation_reason.empty() ? "preserved_vm_boundary"
                                                   : site.preservation_reason,
                  "preserved VM incoming boundary is unsupported: " + site.preservation_reason);
  if (!p.supported) return reject("unsupported_platform", p.rejection);
  auto* call = dyn_cast_or_null<CallInst>(static_cast<Value*>(site.replacement_call));
  if (!call) return reject("unsupported_call_kind", "requires a live fixed-arity call instruction");
  auto* owner = dyn_cast_or_null<Function>(static_cast<Value*>(site.owner_function));
  if (!owner || call->getFunction() != owner)
    return reject("owner_mismatch", "live call does not belong to its recorded owner");
  if (is_call_proxy_entry(*call))
    return reject("already_protected", "entry already has a retained proxy contract");
  if (call->isInlineAsm())
    return reject("inline_assembly", "inline assembly is not a proved function target");
  if (call->getFunctionType()->isVarArg())
    return reject("variadic", "variadic signatures are not supported");
  if (call->hasOperandBundles())
    return reject("operand_bundle", "operand bundles require a qualified forwarding contract");
  if (owner->hasPersonalityFn()) {
    auto* personality = exact_target(owner->getPersonalityFn());
    if (!personality || (personality->getName() != "__gxx_personality_v0" &&
                         personality->getName() != "rust_eh_personality"))
      return reject("unsupported_unwind",
                    "personality or funclet unwind contract is not supported");
  }
  for (Instruction& i : instructions(*owner)) {
    if (i.isEHPad()) return reject("eh_pad", "callers with EH pads or funclets are not supported");
    if (auto* intrinsic = dyn_cast<IntrinsicInst>(&i))
      if (intrinsic->getCalledFunction()->getName().starts_with("llvm.coro.") ||
          intrinsic->getCalledFunction()->getName().starts_with("llvm.stacksave") ||
          intrinsic->getCalledFunction()->getName().starts_with("llvm.stackrestore"))
        return reject("stack_switching",
                      "coroutine and stack-switching boundaries are not supported");
  }
  if (special(*owner) || call->hasFnAttr(Attribute::ReturnsTwice) ||
      call->hasFnAttr(Attribute::Convergent) || call->hasFnAttr(Attribute::NoDuplicate))
    return reject("special_semantics", "special call semantics are not supported");
  auto* target = exact_target(static_cast<Value*>(site.expected_target));
  if (!target && !site.is_vm) target = exact_target(call->getCalledOperand());
  if (!target) return reject("unproved_target", "site has no exact symbolic target provenance");
  if (target->isIntrinsic()) return reject("intrinsic", "intrinsics do not use proxy forwarding");
  const bool structured_vm_thunk =
      site.is_vm && !site.preserved_musttail && !site.preserved_unsupported &&
      site.binding.module_id && site.binding.owner_id && site.binding.binding_id &&
      static_cast<Value*>(site.expected_target) == target &&
      target->hasFnAttribute("obf.vm.entry.thunk") && target->hasLocalLinkage() &&
      target->isDSOLocal() &&
      static_cast<Value*>(site.decoded_target) == call->getCalledOperand() && !call->arg_empty() &&
      call->getArgOperand(call->arg_size() - 1) == static_cast<Value*>(site.hidden_token_operand);
  if (is_call_proxy_infrastructure(*owner) ||
      (is_call_proxy_infrastructure(*target) && !structured_vm_thunk))
    return reject("infrastructure", "runtime and authentication paths must keep their exact shape");
  if (special(*target))
    return reject("special_semantics", "target has unsupported special semantics");
  if (target->hasExternalWeakLinkage() || target->hasWeakLinkage() || target->hasLinkOnceLinkage())
    return reject("weak_resolution", "weak or nullable target resolution is not qualified");
  if (target->getFunctionType() != call->getFunctionType() ||
      target->getCallingConv() != call->getCallingConv() || target->getAddressSpace() != 0 ||
      call->getCalledOperand()->getType()->getPointerAddressSpace() != 0)
    return reject(
        "abi_mismatch",
        "target type, address space, or calling convention differs from the effective call ABI");
  if (call->getCallingConv() != CallingConv::C && call->getCallingConv() != CallingConv::Fast)
    return reject("calling_convention", "only qualified C and Fast conventions are supported");
  if (!compatible_subtarget(*owner, *target))
    return reject("subtarget_mismatch", "caller and target code-generation attributes differ");
  if (fresh_attributes(call->getContext(), call->getAttributes(), call->arg_size()) !=
      fresh_attributes(call->getContext(), target->getAttributes(), call->arg_size()))
    return reject("abi_payload_mismatch", "qualified return or parameter ABI attributes differ");
  for (unsigned i = 0; i <= call->arg_size(); ++i) {
    auto attributes =
        i ? call->getAttributes().getParamAttrs(i - 1) : call->getAttributes().getRetAttrs();
    for (Attribute a : attributes) {
      if (p.windows && a.hasAttribute(Attribute::ByVal))
        return reject("unsupported_win64_byval",
                      "Windows byval forwarding is not qualified because LLVM 22 miscompiles "
                      "register-byval musttail edges");
      if (forbidden_abi(a))
        return reject("unsupported_abi_attribute",
                      "an ABI attribute has no qualified forwarding builder");
      if ((a.hasAttribute(Attribute::ByVal) && !p.byval) ||
          (a.hasAttribute(Attribute::StructRet) && !p.sret) ||
          (a.hasAttribute(Attribute::InReg) && !p.inreg))
        return reject("signature_class", "ABI payload has no backend qualification");
      if (a.isTypeAttribute() &&
          (!a.getValueAsType()->isSized() ||
           owner->getParent()->getDataLayout().getTypeAllocSize(a.getValueAsType()).isScalable()))
        return reject("signature_class", "unsized or scalable ABI payload is not supported");
    }
  }
  auto* module = owner->getParent();
  if (!p.terminal_hardening)
    return reject("unsupported_hardening", "CFI or KCFI terminal instrumentation is not qualified");
  if (owner->hasFnAttribute(Attribute::SanitizeMemory) ||
      target->hasFnAttribute(Attribute::SanitizeMemory))
    return reject("unsupported_hardening",
                  "MSan ABI forwarding requires a qualified noundef builder");
  if (call->getMetadata(LLVMContext::MD_kcfi_type) || call->getMetadata("ptrauth"))
    return reject("unsupported_hardening",
                  "terminal call type hardening requires a qualified builder");
  if (p.windows) {
    bool vector_signature = call->getType()->isVectorTy();
    for (Type* type : call->getFunctionType()->params()) vector_signature |= type->isVectorTy();
    if (vector_signature)
      return reject("unsupported_win64_vector",
                    "Windows vector forwarding is not qualified because LLVM 22 fails native C and "
                    "Fast runtime equivalence");
  }
  const auto supported_type = [&](Type* t) {
    if (!t->isVoidTy() &&
        (!t->isSized() || module->getDataLayout().getTypeAllocSize(t).isScalable()))
      return false;
    if (t->isVoidTy() || t->isPointerTy() || t->isIntegerTy()) return p.scalar;
    if (t->isFloatTy() || t->isDoubleTy()) return p.floating;
    if (auto* v = dyn_cast<FixedVectorType>(t)) {
      const auto bytes = module->getDataLayout().getTypeAllocSize(v).getFixedValue();
      return p.vector && bytes <= 32 &&
             (bytes <= 16 ||
              owner->getFnAttribute("target-features").getValueAsString().contains("+avx"));
    }
    return t->isAggregateType() && t->isSized() && p.aggregate;
  };
  if (!supported_type(call->getType()))
    return reject("signature_class", "return type has no backend qualification");
  for (Type* t : call->getFunctionType()->params())
    if (!supported_type(t))
      return reject("signature_class", "argument type has no backend qualification");
  if (call->isMustTailCall()) {
    const auto* next = call->getNextNode();
    const auto* returned = dyn_cast_or_null<ReturnInst>(next);
    if (!returned || (!call->getType()->isVoidTy() && returned->getReturnValue() != call))
      return reject("invalid_musttail_input",
                    "musttail input lost its immediate exact return before proxy emission: owner=" +
                        owner->getName().str() +
                        " next=" + (next ? std::string(next->getOpcodeName()) : "missing"));
    if (options.mode_policy == proxy_mode_policy::stateful_only)
      return reject("stateful_requires_live_caller",
                    "original musttail sites cannot carry caller-owned state");
    if (owner->getFunctionType() != call->getFunctionType() ||
        owner->getCallingConv() != call->getCallingConv())
      return reject("musttail_abi",
                    "original musttail caller must have the exact effective signature");
    result.mode = proxy_route_mode::abi_only;
  } else if (!p.return_continuation)
    return reject("return_continuation", "first-hop continuation observation is not qualified");
  result.admitted = true;
  result.target = target;
  result.abi_identity = abi_key(*call);
  std::string security = p.identity + ':' + result.abi_identity;
  for (auto a : {Attribute::SanitizeAddress,
                 Attribute::SanitizeThread,
                 Attribute::SanitizeHWAddress,
                 Attribute::ShadowCallStack,
                 Attribute::SafeStack})
    security += owner->hasFnAttribute(a) ? ":1" : ":0";
  result.security_domain = number(combine(site.binding.binding_id, hash(security)));
  result.code = result.mode == proxy_route_mode::stateful ? "stateful" : "abi_only";
  collect_vm_proxy_dependencies(site, result);
  return result;
}

static proxy_plan
plan_call_proxy_chains_impl(Module& m,
                            ArrayRef<admitted_proxy_site> sites,
                            const call_proxy_options& options,
                            const proxy_resource_counts& retained,
                            bool reserve_lto_guards = false,
                            const SmallPtrSetImpl<Function*>* retained_dependencies = nullptr) {
  if (options.min_hops < 2 || options.max_hops > 8 || options.min_hops > options.max_hops ||
      options.decoy_budget > 2 || !options.max_sites_per_owner || !options.max_nodes_per_module ||
      !options.max_context_bytes_per_owner || !options.max_routes_per_shared_node ||
      !options.max_added_ir_instructions)
    fail(m, "invalid finite resource policy");
  if (retained.nodes > options.max_nodes_per_module ||
      checked_add(m, retained.added_instructions, retained.pending_lto_guard_instructions) >
          options.max_added_ir_instructions)
    fail(m, "retained proxy resources exceed the configured module caps");
  proxy_plan plan;
  std::vector<admitted_proxy_site> ordered(sites.begin(), sites.end());
  const auto identity_tuple = [](const admitted_proxy_site& s) {
    const auto& i = s.site.identity;
    return std::tie(i.module_id, i.owner_id, i.site_id, i.instance_id);
  };
  std::sort(ordered.begin(), ordered.end(), [&](const auto& a, const auto& b) {
    return identity_tuple(a) < identity_tuple(b);
  });
  std::set<std::tuple<std::uint64_t, std::uint64_t, std::uint64_t, std::uint64_t>> identities;
  std::set<std::uint64_t> route_ids;
  std::map<Function*, std::uint64_t> owner_sites, owner_bytes;
  for (Function& owner : m)
    for (Instruction& i : instructions(owner))
      if (i.getMetadata(entry_md)) {
        ++owner_sites[&owner];
        auto* call = dyn_cast<CallInst>(&i);
        if (call && call->arg_size() && isa<AllocaInst>(call->getArgOperand(call->arg_size() - 1)))
          owner_bytes[&owner] = checked_add(m, owner_bytes[&owner], context_size(m));
      }
  std::map<std::string, std::uint64_t> memberships;
  std::set<std::uint64_t> nodes;
  std::map<std::uint64_t, std::string> node_keys;
  std::set<Function*> dependencies;
  std::set<Function*> reserved_guard_functions;
  for (Function& function : m)
    if (function.hasFnAttribute("obf.lto.proxy.guard.pending"))
      reserved_guard_functions.insert(&function);
  for (const auto& source : ordered) {
    if (!identities.insert(identity_tuple(source)).second)
      fail(m, "selected live instance identity collision");
    proxy_route_descriptor r;
    r.source = source;
    const auto& id = source.site.identity;
    r.route_seed = hash_route_identity(source.site.decision_seed, id);
    r.route_id = nonzero(combine(combine(id.module_id, id.owner_id), r.route_seed));
    if (!route_ids.insert(r.route_id).second) fail(m, "deterministic route identity collision");
    r.terminal_id = nonzero(combine(r.route_id, 0x7465726d696e616cULL));
    r.target_salt = combine(r.route_seed, 0x746172676574ULL);
    r.descriptor_index = static_cast<std::uint32_t>(plan.routes.size());
    const unsigned count =
        options.min_hops + r.route_seed % (options.max_hops - options.min_hops + 1);
    auto* owner = cast<Function>(static_cast<Value*>(source.site.owner_function));
    auto* target = cast<Function>(static_cast<Value*>(source.admission.target));
    const bool stateful = source.admission.mode == proxy_route_mode::stateful;
    r.context_bytes = stateful ? context_size(m) : 0;
    std::string group = number(id.module_id) + ':' + source.admission.abi_identity + ':' +
                        source.admission.security_domain + ':' +
                        number(combine(ordered.front().site.identity.site_id,
                                       ordered.front().site.identity.instance_id));
    group += stateful ? ":stateful" : ":abi:" + number(hash(target->getName()));
    auto local_memberships = memberships;
    auto local_nodes = nodes;
    r.nodes.resize(count);
    for (unsigned ordinal = 0; ordinal < count; ++ordinal) {
      const unsigned i = stateful ? ordinal : count - ordinal - 1;
      std::string key = group + ':' + number(count - i);
      if (!stateful && i + 1 < count) key += ":next:" + number(r.nodes[i + 1].identity);
      if (!options.share_nodes || (stateful && i == 0)) key += ":entry:" + number(r.route_id);
      const auto membership = local_memberships[key]++;
      key += ":split:" + number(membership / options.max_routes_per_shared_node);
      proxy_node_descriptor n;
      n.identity = nonzero(hash(key));
      if (auto found = node_keys.find(n.identity); found != node_keys.end() && found->second != key)
        fail(m, "deterministic node identity collision");
      node_keys[n.identity] = key;
      n.constant = combine(n.identity, 0x636f6e7374616e74ULL);
      n.multiplier = combine(n.identity, 0x6d756c7469706c79ULL) | 1;
      n.addend = combine(n.identity, 0x616464656e64ULL);
      n.rotation = 1 + combine(n.identity, 0x726f74617465ULL) % 63;
      r.nodes[i] = n;
      local_nodes.insert(n.identity);
    }
    if (stateful) {
      if (local_nodes.contains(r.terminal_id))
        fail(m, "terminal identity collides with a protected node");
      local_nodes.insert(r.terminal_id);
      r.checker_id = nonzero(combine(r.route_id, 0x746172676574636bULL));
      if (local_nodes.contains(r.checker_id))
        fail(m, "target checker identity collides with a protected node");
      local_nodes.insert(r.checker_id);
    } else
      r.terminal_id = r.nodes.back().identity;
    auto local_dependencies = dependencies;
    auto local_guards = reserved_guard_functions;
    std::uint64_t dependency_guards = 0;
    for (const auto& dependency : source.admission.dependencies) {
      auto* function = cast<Function>(static_cast<Value*>(dependency.function));
      if ((retained_dependencies && retained_dependencies->contains(function)) ||
          !local_dependencies.insert(function).second)
        continue;
      if (reserve_lto_guards && local_guards.insert(function).second) ++dependency_guards;
    }
    // This bound includes every route case, caller initialization, trap, and decoy.
    // Shared-node instructions are charged per membership before exact accounting.
    r.reserved_instructions = checked_add(m, 256, checked_mul(m, count, 256));
    r.reserved_instructions =
        checked_add(m,
                    r.reserved_instructions,
                    checked_mul(m, source.site.effective_abi.argument_types.size(), 2));
    const auto new_nodes = local_nodes.size() - nodes.size();
    if (reserve_lto_guards)
      r.reserved_instructions = checked_add(m, r.reserved_instructions, new_nodes);
    const bool owner_guard = reserve_lto_guards && local_guards.insert(owner).second;
    if (owner_guard) r.reserved_instructions = checked_add(m, r.reserved_instructions, 1);
    if (reserve_lto_guards)
      r.reserved_instructions = checked_add(m, r.reserved_instructions, dependency_guards);
    std::string limiting;
    std::uint64_t requested = 0, limit = 0;
    const auto require = [&](std::uint64_t value, std::uint64_t cap, StringRef resource) {
      if (limiting.empty() && value > cap) {
        limiting = resource.str();
        requested = value;
        limit = cap;
      }
    };
    require(
        checked_add(m, owner_sites[owner], 1), options.max_sites_per_owner, "max_sites_per_owner");
    require(checked_add(m, owner_bytes[owner], r.context_bytes),
            options.max_context_bytes_per_owner,
            "max_context_bytes_per_owner");
    require(checked_add(
                m, retained.nodes, checked_add(m, local_nodes.size(), local_dependencies.size())),
            options.max_nodes_per_module,
            "max_nodes_per_module");
    require(
        checked_add(
            m,
            checked_add(m, retained.added_instructions, retained.pending_lto_guard_instructions),
            checked_add(m, plan.reserved.added_instructions, r.reserved_instructions)),
        options.max_added_ir_instructions,
        "max_added_ir_instructions");
    if (!limiting.empty()) {
      proxy_coverage_event event;
      event.identity = id;
      event.required =
          source.site.required || options.coverage_policy == proxy_coverage_policy::required;
      event.mode = source.admission.mode;
      event.binding_id = source.site.binding.binding_id;
      event.terminal_id = r.terminal_id;
      event.abi_identity = source.admission.abi_identity;
      event.code = "budget_" + limiting;
      event.diagnostic =
          limiting + " requested=" + number(requested) + " reserved=" + number(limit);
      plan.events.push_back(std::move(event));
      continue;
    }
    memberships = std::move(local_memberships);
    nodes = std::move(local_nodes);
    dependencies = std::move(local_dependencies);
    reserved_guard_functions = std::move(local_guards);
    ++owner_sites[owner];
    owner_bytes[owner] = checked_add(m, owner_bytes[owner], r.context_bytes);
    ++plan.reserved.sites;
    plan.reserved.nodes = checked_add(m, nodes.size(), dependencies.size());
    if (reserve_lto_guards)
      plan.reserved.pending_lto_guard_instructions = checked_add(
          m,
          plan.reserved.pending_lto_guard_instructions,
          checked_add(m, new_nodes, checked_add(m, dependency_guards, owner_guard ? 1 : 0)));
    plan.reserved.memberships =
        checked_add(m, plan.reserved.memberships, count + (stateful ? 2 : 0));
    plan.reserved.context_bytes = checked_add(m, plan.reserved.context_bytes, r.context_bytes);
    plan.reserved.added_instructions =
        checked_add(m, plan.reserved.added_instructions, r.reserved_instructions);
    plan.routes.push_back(std::move(r));
  }
  return plan;
}

proxy_plan plan_call_proxy_chains(Module& m,
                                  ArrayRef<admitted_proxy_site> sites,
                                  const call_proxy_options& options) {
  proxy_resource_counts retained;
  SmallPtrSet<Function*, 32> reachable;
  SmallVector<Function*, 16> work;
  for (Function& owner : m) {
    if (owner.isDeclaration() || is_call_proxy_helper(owner)) continue;
    for (Instruction& i : instructions(owner)) {
      if (i.getMetadata(operation_md)) ++retained.added_instructions;
      if (i.getMetadata(entry_md))
        if (auto* call = dyn_cast<CallInst>(&i))
          if (auto* target = call->getCalledFunction()) work.push_back(target);
      if (owner.hasFnAttribute("obf.lto.proxy.contract"))
        if (auto* call = dyn_cast<CallBase>(&i))
          if (auto* target = call->getCalledFunction();
              target && target->hasFnAttribute("obf.lto.proxy.dependency"))
            work.push_back(target);
    }
    if (owner.hasFnAttribute("obf.lto.proxy.guard.pending")) {
      bool materialized = false;
      for (Instruction& i : owner.getEntryBlock())
        if (is_exact_finalization_guard(i)) {
          if (!i.getMetadata(operation_md)) ++retained.added_instructions;
          materialized = true;
        }
      if (!materialized) ++retained.pending_lto_guard_instructions;
    }
  }
  while (!work.empty()) {
    Function* f = work.pop_back_val();
    if (!is_call_proxy_helper(*f) || !reachable.insert(f).second) continue;
    if (f->hasFnAttribute("obf.lto.proxy.dependency") && !f->hasFnAttribute("obf.lto.proxy.node")) {
      for (Instruction& i : f->getEntryBlock())
        if (is_exact_finalization_guard(i)) ++retained.added_instructions;
    } else {
      retained.added_instructions =
          checked_add(m, retained.added_instructions, f->getInstructionCount());
    }
    if (f->hasFnAttribute("obf.lto.proxy.guard.pending")) {
      bool materialized = false;
      for (Instruction& i : instructions(*f))
        if (auto* call = dyn_cast<CallInst>(&i))
          if (call->getCalledFunction() &&
              call->getCalledFunction()->getName() == "__obf_lto_finalize_required" &&
              call->arg_size() == 1 && call->getArgOperand(0) == f)
            materialized = true;
      if (!materialized) ++retained.pending_lto_guard_instructions;
    }
    for (Instruction& i : instructions(*f))
      if (auto* call = dyn_cast<CallInst>(&i))
        if (auto* target = call->getCalledFunction(); target && is_call_proxy_helper(*target))
          work.push_back(target);
  }
  retained.nodes = reachable.size();
  return plan_call_proxy_chains_impl(m, sites, options, retained, false, &reachable);
}

namespace {
struct emitted_graph {
  std::map<std::uint64_t, Function*> nodes;
  std::map<std::uint64_t, std::vector<std::pair<const proxy_route_descriptor*, unsigned>>> members;
};

void helper_attributes(Function& f,
                       const proxy_route_descriptor& r,
                       std::uint64_t id,
                       bool bridge) {
  auto* source = cast<CallBase>(static_cast<Value*>(r.source.site.replacement_call));
  f.setDSOLocal(true);
  f.setDLLStorageClass(GlobalValue::DefaultStorageClass);
  f.setVisibility(GlobalValue::DefaultVisibility);
  f.setCallingConv(source->getCallingConv());
  f.setAttributes(fresh_attributes(f.getContext(), source->getAttributes(), source->arg_size()));
  copy_codegen(*source->getFunction(), f);
  f.addFnAttr(Attribute::NoInline);
  f.addFnAttr(Attribute::OptimizeNone);
  f.addFnAttr(bridge ? "obf.call.proxy.bridge" : "obf.call.proxy.hop");
  f.addFnAttr("obf.lto.proxy.schema", number(call_proxy_schema));
  f.addFnAttr("obf.lto.proxy.role", bridge ? "bridge" : "hop");
  f.addFnAttr("obf.lto.proxy.owner", number(r.source.site.identity.owner_id));
  f.addFnAttr("obf.lto.proxy.abi", r.source.admission.abi_identity);
  f.addFnAttr("obf.lto.proxy.node", number(id));
  f.addFnAttr("obf.lto.proxy.domain", r.source.admission.security_domain);
  record_coverage_role(f,
                       source->getFunction()->getName(),
                       bridge ? "call_proxy_bridge" : "call_proxy_hop",
                       {"generated_internal", "call_proxy"});
}

void state_identity_checks(IRBuilder<>& b,
                           Value* ctx,
                           const proxy_route_descriptor& r,
                           BasicBlock* failure,
                           unsigned position,
                           bool entering) {
  equal(
      b, load(b, ctx, schema), b.getInt32(call_proxy_schema), failure, "check.schema", r.route_id);
  equal(b,
        load(b, ctx, owner_id),
        b.getInt64(r.source.site.identity.owner_id),
        failure,
        "check.owner",
        r.route_id);
  equal(b,
        load(b, ctx, site_id),
        b.getInt64(r.source.site.identity.site_id),
        failure,
        "check.site",
        r.route_id);
  equal(b, load(b, ctx, route_id), b.getInt64(r.route_id), failure, "check.route", r.route_id);
  equal(b,
        load(b, ctx, descriptor_index),
        b.getInt32(r.descriptor_index),
        failure,
        "check.descriptor",
        r.route_id);
  equal(b, load(b, ctx, phase), b.getInt32(entering ? 0 : 1), failure, "check.phase", r.route_id);
  equal(b, load(b, ctx, step), b.getInt32(position), failure, "check.step", r.route_id);
  const auto node = position < r.nodes.size() ? r.nodes[position].identity : r.terminal_id;
  equal(b, load(b, ctx, expected_node), b.getInt64(node), failure, "check.node", r.route_id);
}

void emit_target_checker(Function& f, const proxy_route_descriptor& r, Module& m) {
  IRBuilder<> b(BasicBlock::Create(m.getContext(), "entry", &f));
  auto* failure = BasicBlock::Create(m.getContext(), "proxy.trap", &f);
  IRBuilder<> fb(failure);
  trap(fb, m);
  Value* permitted = b.CreateICmpEQ(f.getArg(0), f.getArg(2));
  Value* admitted = b.CreateICmpEQ(f.getArg(0), f.getArg(1));
  check(b, b.CreateAnd(permitted, admitted), failure, "check.target.binding", r.route_id);
  b.CreateRetVoid();
}

void emit_terminal(Function& f, Function& checker, const proxy_route_descriptor& r, Module& m) {
  IRBuilder<> b(BasicBlock::Create(m.getContext(), "entry", &f));
  auto* failure = BasicBlock::Create(m.getContext(), "proxy.trap", &f);
  IRBuilder<> fb(failure);
  trap(fb, m);
  Value* ctx = f.getArg(f.arg_size() - 1);
  state_identity_checks(b, ctx, r, failure, r.nodes.size(), false);
  Value* computed_root = recompute_root(b, ctx, r);
  equal(b, load(b, ctx, root), computed_root, failure, "check.root", r.route_id);
  Value* final_prefix = prefix(b, computed_root, r, r.nodes.size());
  equal(b, load(b, ctx, token), final_prefix, failure, "check.prefix", r.route_id);
  Value* key =
      mix(b, b.CreateXor(b.CreateXor(final_prefix, computed_root), b.getInt64(r.target_salt)));
  Value* decoded =
      b.CreateXor(rotate(b, load(b, ctx, encoded_target), 23, true), key, "proxy.decoded");
  mark_value(decoded, r.route_id, "target.decode");
  Value* admitted = load(b, ctx, admitted_target);
  auto* validate = b.CreateCall(
      checker.getFunctionType(),
      &checker,
      {decoded,
       b.CreatePtrToInt(admitted, b.getInt64Ty()),
       b.CreatePtrToInt(static_cast<Value*>(r.source.admission.target), b.getInt64Ty())});
  validate->setCallingConv(checker.getCallingConv());
  validate->setAttributes(AttributeList());
  mark(*validate, r.route_id, "check.target.binding");
  mark(*store(b, ctx, phase, b.getInt32(2)), r.route_id, "state.consume");
  Value* pointer = b.CreateIntToPtr(decoded, PointerType::get(m.getContext(), 0), "proxy.target");
  auto* original = cast<CallBase>(static_cast<Value*>(r.source.site.replacement_call));
  auto args = arguments(f, true);
  auto* call = b.CreateCall(original->getFunctionType(), pointer, args);
  call->setCallingConv(f.getCallingConv());
  call->setAttributes(fresh_attributes(m.getContext(), original->getAttributes(), args.size()));
  call->setTailCallKind(CallInst::TCK_NoTail);
  call->setDebugLoc(original->getDebugLoc());
  mark(*call, r.route_id, "target.transfer");
  return_call(b, *call);
}

void emit_stateful_node(Function& f,
                        ArrayRef<std::pair<const proxy_route_descriptor*, unsigned>> members,
                        const emitted_graph& graph,
                        const call_proxy_options& options,
                        Module& m) {
  IRBuilder<> b(BasicBlock::Create(m.getContext(), "entry", &f));
  auto* failure = BasicBlock::Create(m.getContext(), "proxy.trap", &f);
  IRBuilder<> fb(failure);
  trap(fb, m);
  Value* ctx = f.getArg(f.arg_size() - 1);
  auto* dispatch = b.CreateSwitch(load(b, ctx, route_id), failure, members.size());
  for (const auto& [rp, position] : members) {
    const auto& r = *rp;
    auto* route_block = BasicBlock::Create(m.getContext(), "proxy.route", &f);
    dispatch->addCase(b.getInt64(r.route_id), route_block);
    b.SetInsertPoint(route_block);
    state_identity_checks(b, ctx, r, failure, position, position == 0);
    if (position == 0) {
      for (unsigned index : {observed_continuation, root, token, encoded_target})
        equal(b, load(b, ctx, index), b.getInt64(0), failure, "check.sentinel", r.route_id);
      equal(b,
            load(b, ctx, admitted_target),
            static_cast<Value*>(r.source.admission.target),
            failure,
            "check.entry.target",
            r.route_id);
      auto* address = b.CreateCall(Intrinsic::getOrInsertDeclaration(&m, Intrinsic::returnaddress),
                                   {b.getInt32(0)});
      mark(*address, r.route_id, "continuation.capture");
      mark(*store(b, ctx, observed_continuation, b.CreatePtrToInt(address, b.getInt64Ty())),
           r.route_id,
           "continuation.store");
      Value* rvalue = recompute_root(b, ctx, r);
      mark(*store(b, ctx, root, rvalue), r.route_id, "root.store");
      mark(*store(b, ctx, token, prefix(b, rvalue, r, 0)), r.route_id, "prefix.initial");
      Value* final_prefix = prefix(b, rvalue, r, r.nodes.size());
      Value* key =
          mix(b, b.CreateXor(b.CreateXor(final_prefix, rvalue), b.getInt64(r.target_salt)));
      Value* encoded = rotate(
          b, b.CreateXor(b.CreatePtrToInt(load(b, ctx, admitted_target), b.getInt64Ty()), key), 23);
      mark(*store(b, ctx, encoded_target, encoded), r.route_id, "target.encode");
      mark(*store(b, ctx, phase, b.getInt32(1)), r.route_id, "state.activate");
    }
    Value* expected_root = recompute_root(b, ctx, r);
    equal(b, load(b, ctx, root), expected_root, failure, "check.root", r.route_id);
    Value* expected_prefix = prefix(b, expected_root, r, position);
    equal(b, load(b, ctx, token), expected_prefix, failure, "check.prefix", r.route_id);
    decoys(b, expected_prefix, failure, options, r.route_id);
    mark(*store(b, ctx, token, transition(b, expected_prefix, r.nodes[position])),
         r.route_id,
         "prefix.advance");
    mark(*store(b, ctx, step, b.getInt32(position + 1)), r.route_id, "step.advance");
    const auto next_id =
        position + 1 < r.nodes.size() ? r.nodes[position + 1].identity : r.terminal_id;
    mark(*store(b, ctx, expected_node, b.getInt64(next_id)), r.route_id, "node.advance");
    auto args = arguments(f);
    auto* next = graph.nodes.at(next_id);
    auto* call = b.CreateCall(f.getFunctionType(), next, args);
    call->setCallingConv(f.getCallingConv());
    call->setAttributes(fresh_attributes(m.getContext(), f.getAttributes(), args.size()));
    call->setTailCallKind(CallInst::TCK_MustTail);
    mark(*call, r.route_id, "hop.transfer");
    return_call(b, *call);
  }
}

void emit_abi_node(Function& f,
                   const proxy_route_descriptor& r,
                   unsigned position,
                   const emitted_graph& graph,
                   const call_proxy_options& options,
                   Module& m) {
  IRBuilder<> b(BasicBlock::Create(m.getContext(), "entry", &f));
  auto* failure = BasicBlock::Create(m.getContext(), "proxy.trap", &f);
  IRBuilder<> fb(failure);
  trap(fb, m);
  Value* snapshot = entropy(b, m);
  decoys(b, snapshot, failure, options, r.route_id);
  auto args = arguments(f);
  Value* target = position + 1 < r.nodes.size() ? graph.nodes.at(r.nodes[position + 1].identity)
                                                : static_cast<Value*>(r.source.admission.target);
  if (position + 1 == r.nodes.size()) {
    IRBuilder<> entry(&f.getEntryBlock(), f.getEntryBlock().getFirstInsertionPt());
    auto* slot = entry.CreateAlloca(target->getType(), nullptr, "proxy.local.target");
    slot->setAlignment(m.getDataLayout().getPointerABIAlignment(0));
    auto* materialize = b.CreateStore(target, slot, true);
    materialize->setAlignment(slot->getAlign());
    mark(*materialize, r.route_id, "target.materialize.store");
    auto* pointer = b.CreateLoad(target->getType(), slot, "proxy.local.target.value");
    pointer->setVolatile(true);
    pointer->setAlignment(slot->getAlign());
    mark(*pointer, r.route_id, "target.materialize.load");
    target = pointer;
  }
  auto* call = b.CreateCall(f.getFunctionType(), target, args);
  call->setCallingConv(f.getCallingConv());
  call->setAttributes(fresh_attributes(m.getContext(), f.getAttributes(), args.size()));
  call->setTailCallKind(CallInst::TCK_MustTail);
  mark(*call, r.route_id, position + 1 == r.nodes.size() ? "target.transfer" : "hop.transfer");
  return_call(b, *call);
}

proxy_live_contract
emit_entry(Module& m, const proxy_route_descriptor& r, const emitted_graph& graph) {
  auto* original = cast<CallInst>(static_cast<Value*>(r.source.site.replacement_call));
  auto* owner = original->getFunction();
  Instruction* previous = original->getPrevNode();
  proxy_live_contract contract;
  contract.route = r;
  contract.owner = owner;
  contract.admitted_target = original->getCalledOperand();
  contract.exact_context_bytes = r.context_bytes;
  for (const auto& n : r.nodes) contract.hops.emplace_back(graph.nodes.at(n.identity));
  contract.terminal = r.source.admission.mode == proxy_route_mode::stateful
                          ? graph.nodes.at(r.terminal_id)
                          : graph.nodes.at(r.nodes.back().identity);
  if (r.source.admission.mode == proxy_route_mode::stateful)
    contract.checker = graph.nodes.at(r.checker_id);
  IRBuilder<> b(original);
  SmallVector<Value*, 16> args(original->args());
  const bool stateful = r.source.admission.mode == proxy_route_mode::stateful;
  if (stateful) {
    IRBuilder<> entry(&owner->getEntryBlock(), owner->getEntryBlock().getFirstInsertionPt());
    auto* slot = entry.CreateAlloca(context_type(m.getContext()), nullptr, "proxy.context");
    slot->setAlignment(m.getDataLayout().getABITypeAlign(context_type(m.getContext())));
    mark(*slot, r.route_id, "context.allocate");
    contract.context = slot;
    Value* snapshot = entropy(b, m);
    SmallVector<Value*, context_field_count> initial{b.getInt32(call_proxy_schema),
                                                     b.getInt32(0),
                                                     b.getInt64(r.source.site.identity.owner_id),
                                                     b.getInt64(r.source.site.identity.site_id),
                                                     b.getInt64(r.route_id),
                                                     b.getInt32(r.descriptor_index),
                                                     b.getInt32(0),
                                                     b.getInt64(r.nodes.front().identity),
                                                     snapshot,
                                                     b.getInt64(0),
                                                     b.getInt64(0),
                                                     b.getInt64(0),
                                                     original->getCalledOperand(),
                                                     b.getInt64(0)};
    for (unsigned i = 0; i < initial.size(); ++i)
      mark(*store(b, slot, i, initial[i]), r.route_id, "context.initialize");
    args.push_back(slot);
  }
  auto* entry = b.CreateCall(private_type(r), graph.nodes.at(r.nodes.front().identity), args);
  entry->setCallingConv(original->getCallingConv());
  entry->setAttributes(
      fresh_attributes(m.getContext(), original->getAttributes(), original->arg_size()));
  entry->setTailCallKind(stateful ? CallInst::TCK_NoTail : CallInst::TCK_MustTail);
  entry->setDebugLoc(original->getDebugLoc());
  mark(*entry, r.route_id, "entry.transfer");
  for (Instruction* i = previous ? previous->getNextNode() : &original->getParent()->front();
       i && i != original;
       i = i->getNextNode())
    if (!i->getMetadata(operation_md)) mark(*i, r.route_id, "caller.added");
  original->replaceAllUsesWith(entry);
  contract.entry = entry;
  contract.route.source.site.replacement_call = entry;
  if (contract.route.source.site.encoded_result == original)
    contract.route.source.site.encoded_result = entry;
  original->eraseFromParent();
  return contract;
}

}  // namespace

namespace {

StringRef md_text(const MDNode* node, unsigned index) {
  if (!node || index >= node->getNumOperands()) return {};
  if (auto* s = dyn_cast_or_null<MDString>(node->getOperand(index).get())) return s->getString();
  return {};
}

std::string global_identity(const GlobalValue& value) {
  if (const auto* object = dyn_cast<GlobalObject>(&value))
    if (const auto* id = object->getMetadata("obf.lto.proxy.value"))
      return "value:" + md_text(id, 0).str();
  if (const auto* f = dyn_cast<Function>(&value)) {
    for (StringRef key : {"obf.lto.proxy.node", "obf.lto.proxy.target"}) {
      auto attr = f->getFnAttribute(key);
      if (attr.isValid()) return key.str() + ':' + attr.getValueAsString().str();
    }
    if (f->isIntrinsic()) return "intrinsic:" + number(f->getIntrinsicID());
  }
  return "symbol:" + value.getName().str();
}

bool is_exact_finalization_guard(const Instruction& i) {
  const auto* call = dyn_cast<CallInst>(&i);
  const Function* owner = i.getFunction();
  if (!call || call->arg_size() != 1 || call->hasOperandBundles() || call->isTailCall() ||
      call->getCallingConv() != CallingConv::C || !call->getType()->isVoidTy() ||
      call->getArgOperand(0) != owner || i.getParent() != &owner->getEntryBlock())
    return false;
  const auto* callee = call->getCalledFunction();
  return callee && callee->isDeclaration() && callee->getName() == "__obf_lto_finalize_required" &&
         callee->getReturnType()->isVoidTy() && !callee->isVarArg() && callee->arg_size() == 1 &&
         callee->getFunctionType()->getParamType(0) == owner->getType();
}

bool is_proxy_lto_guard(const Instruction& i) {
  const Function* owner = i.getFunction();
  return is_call_proxy_helper(*owner) &&
         owner->getFnAttribute("obf.lto.finalize").getValueAsString() == "1" &&
         is_exact_finalization_guard(i);
}

std::string function_fingerprint(const Function& f) {
  DenseMap<const Value*, unsigned> slots;
  const Instruction* dispatch = f.getEntryBlock().getTerminator();
  const ICmpInst* dispatch_compare = nullptr;
  const Value* dispatch_condition = nullptr;
  const ConstantInt* dispatch_case = nullptr;
  const BasicBlock* dispatch_match = nullptr;
  const BasicBlock* dispatch_default = nullptr;
  if (const auto* switch_inst = dyn_cast<SwitchInst>(dispatch);
      switch_inst && switch_inst->getNumCases() == 1 && !switch_inst->getMetadata(operation_md)) {
    const auto one_case = *switch_inst->case_begin();
    dispatch_condition = switch_inst->getCondition();
    dispatch_case = one_case.getCaseValue();
    dispatch_match = one_case.getCaseSuccessor();
    dispatch_default = switch_inst->getDefaultDest();
  } else if (const auto* branch = dyn_cast<BranchInst>(dispatch);
             branch && branch->isConditional() && !branch->getMetadata(operation_md)) {
    const auto* compare = dyn_cast<ICmpInst>(branch->getCondition());
    if (compare && compare->hasOneUse() && compare->getPredicate() == CmpInst::ICMP_EQ &&
        !compare->getMetadata(operation_md) && compare->getParent() == &f.getEntryBlock()) {
      if (const auto* constant = dyn_cast<ConstantInt>(compare->getOperand(1))) {
        dispatch_compare = compare;
        dispatch_condition = compare->getOperand(0);
        dispatch_case = constant;
        dispatch_match = branch->getSuccessor(0);
        dispatch_default = branch->getSuccessor(1);
      }
    }
  }
  unsigned next = 1;
  for (const Argument& arg : f.args()) slots[&arg] = next++;
  for (const BasicBlock& block : f) {
    slots[&block] = next++;
    for (const Instruction& i : block)
      if (&i != dispatch_compare && !is_proxy_lto_guard(i)) slots[&i] = next++;
  }
  std::string text;
  raw_string_ostream out(text);
  const auto operand = [&](const Value* value, auto&& self) -> void {
    if (auto it = slots.find(value); it != slots.end()) {
      out << '%' << it->second;
      return;
    }
    if (auto* global = dyn_cast<GlobalValue>(value)) {
      out << global_identity(*global);
      return;
    }
    if (auto* constant = dyn_cast<ConstantExpr>(value)) {
      out << "ce:" << constant->getOpcode() << '(';
      for (const Use& op : constant->operands()) {
        self(op.get(), self);
        out << ',';
      }
      out << ')';
      return;
    }
    value->printAsOperand(out, false);
  };
  out << printed_type(f.getFunctionType()) << ':' << f.getCallingConv() << ':';
  print_abi(out, f.getAttributes(), f.arg_size());
  for (const BasicBlock& block : f) {
    out << "B" << slots.lookup(&block) << ':';
    for (const Instruction& i : block) {
      if (&i == dispatch_compare || is_proxy_lto_guard(i)) continue;
      if (&i == dispatch && dispatch_condition) {
        out << "finite.dispatch(";
        operand(dispatch_condition, operand);
        out << ',';
        operand(dispatch_case, operand);
        out << ',';
        operand(dispatch_match, operand);
        out << ',';
        operand(dispatch_default, operand);
        out << ");";
        continue;
      }
      out << i.getOpcode() << ':' << printed_type(i.getType()) << '(';
      for (const Use& use : i.operands()) {
        operand(use.get(), operand);
        out << ',';
      }
      out << ')';
      if (const MDNode* role = i.getMetadata(operation_md))
        out << ":role=" << md_text(role, 0) << ':' << md_text(role, 1);
      if (auto* cmp = dyn_cast<CmpInst>(&i))
        out << ':' << static_cast<unsigned>(cmp->getPredicate());
      if (auto* gep = dyn_cast<GetElementPtrInst>(&i))
        out << ':' << printed_type(gep->getSourceElementType()) << ':' << gep->isInBounds();
      if (auto* call = dyn_cast<CallInst>(&i)) {
        out << ':' << call->getCallingConv() << ':' << call->getTailCallKind() << ':'
            << printed_type(call->getFunctionType());
        print_abi(out, call->getAttributes(), call->arg_size());
      }
      if (auto* alloca = dyn_cast<AllocaInst>(&i))
        out << ':' << printed_type(alloca->getAllocatedType()) << ':' << alloca->getAlign().value();
      if (auto* load = dyn_cast<LoadInst>(&i))
        out << ':' << load->getAlign().value() << ':' << load->isVolatile() << ':'
            << unsigned(load->getOrdering());
      if (auto* store = dyn_cast<StoreInst>(&i))
        out << ':' << store->getAlign().value() << ':' << store->isVolatile() << ':'
            << unsigned(store->getOrdering());
      if (const auto* binary = dyn_cast<BinaryOperator>(&i))
        out << ':' << binary->hasNoUnsignedWrap() << ':' << binary->hasNoSignedWrap() << ':'
            << binary->isExact();
      out << ';';
    }
  }
  return number(hash(out.str()));
}

std::string serialize_route(const proxy_live_contract& contract) {
  const auto& r = contract.route;
  const auto& s = r.source.site;
  const auto& i = s.identity;
  std::ostringstream out;
  auto* target = cast<Function>(static_cast<Value*>(r.source.admission.target));
  auto* entry = cast<CallInst>(static_cast<Value*>(contract.entry));
  GlobalVariable* key = s.return_contract.role == vm_result_role::encoded_integer
                            ? entry->getModule()->getNamedGlobal(s.return_contract.key_global_name)
                            : nullptr;
  const std::string key_identity =
      key ? md_text(key->getMetadata("obf.lto.proxy.value"), 0).str() : "";
  out << call_proxy_schema << ';' << i.module_id << ';' << i.owner_id << ';' << i.site_id << ';'
      << i.instance_id << ';' << unsigned(r.source.admission.mode) << ';' << r.route_id << ';'
      << r.route_seed << ';' << r.target_salt << ';' << r.terminal_id << ';' << r.descriptor_index
      << ';' << r.context_bytes << ';' << r.reserved_instructions << ';'
      << r.source.admission.abi_identity << ';' << r.source.admission.security_domain << ';'
      << target->getFnAttribute("obf.lto.proxy.target").getValueAsString().str() << ';' << s.is_vm
      << ';' << s.binding.module_id << ';' << s.binding.owner_id << ';' << s.binding.binding_id
      << ';' << s.binding.no_cache << ';' << s.original_site_token << ';'
      << unsigned(s.return_contract.role) << ';' << s.return_contract.integer_width << ';'
      << key_identity << ';' << contract.configuration_identity << ';' << contract.platform_identity
      << ';' << r.checker_id << ';' << r.nodes.size();
  for (const auto& n : r.nodes)
    out << ';' << n.identity << ';' << n.constant << ';' << n.multiplier << ';' << n.addend << ';'
        << n.rotation;
  out << ';' << r.source.admission.dependencies.size();
  for (const auto& dependency : r.source.admission.dependencies)
    out << ';' << dependency.identity << ';' << dependency.abi_identity;
  return out.str();
}

proxy_live_contract deserialize_route(Module& m,
                                      StringRef encoded,
                                      const std::map<std::uint64_t, Function*>& nodes,
                                      const std::map<std::uint64_t, Function*>& targets,
                                      const std::map<std::uint64_t, Function*>& dependencies) {
  SmallVector<StringRef, 80> fields;
  encoded.split(fields, ';');
  unsigned cursor = 0;
  const auto word = [&]() -> StringRef {
    if (cursor == fields.size()) fail(m, "truncated retained route descriptor");
    return fields[cursor++];
  };
  const auto value = [&]() { return integer(word(), m); };
  if (value() != call_proxy_schema) fail(m, "retained schema version differs");
  proxy_live_contract c;
  auto& r = c.route;
  auto& s = r.source.site;
  auto& id = s.identity;
  id.module_id = value();
  id.owner_id = value();
  id.site_id = value();
  id.instance_id = value();
  const auto mode = value();
  if (mode > unsigned(proxy_route_mode::abi_only)) fail(m, "invalid retained route mode");
  r.source.admission.mode = static_cast<proxy_route_mode>(mode);
  r.source.admission.admitted = true;
  r.route_id = value();
  r.route_seed = value();
  r.target_salt = value();
  r.terminal_id = value();
  r.descriptor_index = value();
  r.context_bytes = value();
  r.reserved_instructions = value();
  r.source.admission.abi_identity = word().str();
  r.source.admission.security_domain = word().str();
  const auto target_id = value();
  if (!targets.contains(target_id)) fail(m, "retained permitted target identity is missing");
  r.source.admission.target = targets.at(target_id);
  s.expected_target = targets.at(target_id);
  s.is_vm = value();
  s.binding.module_id = value();
  s.binding.owner_id = value();
  s.binding.binding_id = value();
  s.binding.no_cache = value();
  s.original_site_token = value();
  s.preserved_musttail = s.is_vm && r.source.admission.mode == proxy_route_mode::abi_only;
  const auto result_role = value();
  if (result_role > unsigned(vm_result_role::encoded_integer))
    fail(m, "invalid retained result role");
  s.return_contract.role = static_cast<vm_result_role>(result_role);
  s.return_contract.integer_width = value();
  const auto retained_key = word();
  if (!retained_key.empty())
    for (GlobalVariable& global : m.globals())
      if (const auto* metadata = global.getMetadata("obf.lto.proxy.value"))
        if (md_text(metadata, 0) == retained_key) {
          if (!s.return_contract.key_global_name.empty())
            fail(m, "ambiguous retained VM return-key identity");
          s.return_contract.key_global_name = global.getName().str();
        }
  if (!retained_key.empty() && s.return_contract.key_global_name.empty())
    fail(m, "retained VM return-key identity is missing");
  s.return_contract.binding_id = s.binding.binding_id;
  s.return_contract.token = s.original_site_token;
  c.configuration_identity = word().str();
  c.platform_identity = word().str();
  r.checker_id = value();
  const auto count = value();
  if (count < 2 || count > 8) fail(m, "retained hop count is outside the bounded schema");
  for (unsigned i = 0; i < count; ++i) {
    proxy_node_descriptor n;
    n.identity = value();
    n.constant = value();
    n.multiplier = value();
    n.addend = value();
    n.rotation = value();
    if (!n.rotation || n.rotation > 63 || !(n.multiplier & 1))
      fail(m, "invalid retained node arithmetic");
    if (!nodes.contains(n.identity)) fail(m, "live retained route lost a required hop");
    r.nodes.push_back(n);
    c.hops.emplace_back(nodes.at(n.identity));
  }
  const auto dependency_count = value();
  if (dependency_count > fields.size() / 2)
    fail(m, "retained dependency count exceeds its descriptor bound");
  for (std::uint64_t i = 0; i < dependency_count; ++i) {
    proxy_dependency_descriptor dependency;
    dependency.identity = value();
    dependency.abi_identity = word().str();
    if (!dependencies.contains(dependency.identity))
      fail(m, "retained resolver dependency identity is missing");
    dependency.function = dependencies.at(dependency.identity);
    r.source.admission.dependencies.push_back(std::move(dependency));
  }
  if (cursor != fields.size()) fail(m, "retained route descriptor has trailing fields");
  const auto terminal = r.source.admission.mode == proxy_route_mode::stateful
                            ? r.terminal_id
                            : r.nodes.back().identity;
  if (!nodes.contains(terminal)) fail(m, "live retained route lost its terminal");
  c.terminal = nodes.at(terminal);
  if (r.source.admission.mode == proxy_route_mode::stateful) {
    if (!r.checker_id || !nodes.contains(r.checker_id))
      fail(m, "retained route lost its target checker");
    c.checker = nodes.at(r.checker_id);
  }
  c.exact_context_bytes = r.context_bytes;
  c.recovered = true;
  return c;
}

void mark_decode_globals(Value* value,
                         Value* boundary,
                         std::uint64_t module_id,
                         SmallPtrSetImpl<Value*>& seen) {
  if (value == boundary || !seen.insert(value).second) return;
  if (auto* global = dyn_cast<GlobalObject>(value)) {
    if (!global->getMetadata("obf.lto.proxy.value"))
      global->setMetadata(
          "obf.lto.proxy.value",
          MDNode::get(
              global->getContext(),
              {MDString::get(global->getContext(),
                             number(nonzero(global->hasLocalLinkage()
                                                ? combine(module_id, hash(global->getName()))
                                                : hash(global->getName()))))}));
    return;
  }
  if (auto* user = dyn_cast<User>(value))
    for (const Use& op : user->operands()) mark_decode_globals(op.get(), boundary, module_id, seen);
}

std::string decode_fingerprint(const Value* value, const Value* boundary) {
  DenseMap<const Value*, unsigned> visited;
  DenseMap<const BasicBlock*, unsigned> blocks;
  std::string text;
  raw_string_ostream out(text);
  const auto emit = [&](const Value* v, auto&& self) -> void {
    if (const auto* binary = dyn_cast<BinaryOperator>(v);
        binary && binary->getOpcode() == Instruction::And) {
      for (unsigned i = 0; i < 2; ++i)
        if (const auto* mask = dyn_cast<ConstantInt>(binary->getOperand(i));
            mask && mask->isMinusOne()) {
          self(binary->getOperand(1 - i), self);
          return;
        }
    }
    if (v == boundary) {
      out << "encoded-result";
      return;
    }
    if (auto* global = dyn_cast<GlobalValue>(v)) {
      out << global_identity(*global);
      return;
    }
    if (auto* block = dyn_cast<BasicBlock>(v)) {
      auto [it, inserted] = blocks.try_emplace(block, blocks.size());
      out << "block:" << it->second;
      return;
    }
    if (auto* expression = dyn_cast<ConstantExpr>(v)) {
      out << "constant:" << expression->getOpcode() << ':' << printed_type(expression->getType())
          << '(';
      for (const Use& op : expression->operands()) {
        self(op.get(), self);
        out << ',';
      }
      out << ')';
      return;
    }
    if (auto* argument = dyn_cast<Argument>(v)) {
      out << "arg:" << argument->getArgNo() << ':' << printed_type(argument->getType());
      return;
    }
    if (auto* instruction = dyn_cast<Instruction>(v)) {
      auto [it, inserted] = visited.try_emplace(v, visited.size());
      if (!inserted) {
        out << "ref:" << it->second;
        return;
      }
      out << instruction->getOpcode() << ':' << printed_type(instruction->getType()) << '(';
      for (const Use& op : instruction->operands()) {
        self(op.get(), self);
        out << ',';
      }
      if (auto* cmp = dyn_cast<CmpInst>(instruction))
        out << static_cast<unsigned>(cmp->getPredicate());
      if (auto* load = dyn_cast<LoadInst>(instruction))
        out << load->getAlign().value() << ':' << load->isVolatile() << ':'
            << unsigned(load->getOrdering());
      if (auto* gep = dyn_cast<GetElementPtrInst>(instruction))
        out << printed_type(gep->getSourceElementType()) << ':' << gep->isInBounds();
      if (auto* alloca = dyn_cast<AllocaInst>(instruction))
        out << printed_type(alloca->getAllocatedType()) << ':' << alloca->getAlign().value();
      if (auto* binary = dyn_cast<BinaryOperator>(instruction)) {
        const auto* left = dyn_cast<ConstantInt>(binary->getOperand(0));
        const auto* right = dyn_cast<ConstantInt>(binary->getOperand(1));
        const bool zero_left = left && left->isZero();
        const bool zero_right = right && right->isZero();
        const bool identity =
            (binary->getOpcode() == Instruction::Add && (zero_left || zero_right)) ||
            (binary->getOpcode() == Instruction::Sub && zero_right) ||
            (binary->getOpcode() == Instruction::Mul &&
             (zero_left || zero_right || (left && left->isOne()) || (right && right->isOne()))) ||
            ((binary->getOpcode() == Instruction::Shl || binary->getOpcode() == Instruction::LShr ||
              binary->getOpcode() == Instruction::AShr) &&
             zero_right);
        out << (identity ? false : binary->hasNoSignedWrap()) << ':'
            << (identity ? false : binary->hasNoUnsignedWrap()) << ':'
            << (identity ? false : binary->isExact());
      }
      if (auto* call = dyn_cast<CallBase>(instruction)) {
        out << call->getCallingConv() << ':' << printed_type(call->getFunctionType());
        print_abi(out, call->getAttributes(), call->arg_size());
      }
      out << ')';
      return;
    }
    v->printAsOperand(out, false);
  };
  emit(value, emit);
  return number(hash(out.str()));
}

void annotate_contract(proxy_live_contract& c) {
  auto* call = cast<CallInst>(static_cast<Value*>(c.entry));
  auto& context = call->getContext();
  auto& s = c.route.source.site;
  SmallPtrSet<Value*, 32> identities;
  mark_decode_globals(
      static_cast<Value*>(c.admitted_target), call, s.identity.module_id, identities);
  const bool vm_token = s.is_vm && !s.preserved_musttail;
  if (vm_token)
    mark_decode_globals(
        static_cast<Value*>(s.hidden_token_operand), call, s.identity.module_id, identities);
  if (auto* decode = dyn_cast_or_null<Instruction>(static_cast<Value*>(s.return_decode_root))) {
    SmallPtrSet<Value*, 32> seen;
    mark_decode_globals(decode, call, s.identity.module_id, seen);
    if (!s.return_contract.key_global_name.empty()) {
      auto* key = call->getModule()->getNamedGlobal(s.return_contract.key_global_name);
      if (!key || !key->getMetadata("obf.lto.proxy.value"))
        fail(*call->getModule(), "VM return-key identity is missing during retention");
    }
    decode->setMetadata("obf.lto.proxy.return",
                        MDNode::get(context,
                                    {MDString::get(context, number(c.route.route_id)),
                                     MDString::get(context, number(s.binding.binding_id)),
                                     MDString::get(context, number(s.original_site_token)),
                                     MDString::get(context, decode_fingerprint(decode, call))}));
  }
  call->setMetadata(
      entry_md,
      MDNode::get(
          context,
          {MDString::get(context, serialize_route(c)),
           MDString::get(context, vm_token ? "hidden-token" : ""),
           MDString::get(context, vm_token ? number(call->arg_size() - 2) : ""),
           MDString::get(context,
                         vm_token
                             ? decode_fingerprint(static_cast<Value*>(s.hidden_token_operand), call)
                             : ""),
           MDString::get(context, "admitted-target"),
           MDString::get(context,
                         decode_fingerprint(static_cast<Value*>(c.admitted_target), call))}));
}

std::string role_of(const Instruction& i, std::uint64_t route) {
  auto* metadata = i.getMetadata(operation_md);
  if (md_text(metadata, 0) != number(route)) return {};
  return md_text(metadata, 1).str();
}

bool depends_on(const Value* value, const Value* wanted, SmallPtrSetImpl<const Value*>& seen) {
  if (value == wanted) return true;
  if (!value || !seen.insert(value).second) return false;
  const auto* user = dyn_cast<User>(value);
  if (!user) return false;
  for (const Use& operand : user->operands())
    if (depends_on(operand.get(), wanted, seen)) return true;
  return false;
}
bool depends_on(const Value* value, const Value* wanted) {
  SmallPtrSet<const Value*, 32> seen;
  return depends_on(value, wanted, seen);
}

CallInst* route_transfer(Function& f, std::uint64_t route, bool terminal) {
  for (Instruction& i : instructions(f)) {
    auto* call = dyn_cast<CallInst>(&i);
    if (call && role_of(i, route) == (terminal ? "target.transfer" : "hop.transfer")) return call;
  }
  return nullptr;
}

void validate_target_checker(Module& m, Function& checker) {
  auto* expected = FunctionType::get(Type::getVoidTy(m.getContext()),
                                     {Type::getInt64Ty(m.getContext()),
                                      Type::getInt64Ty(m.getContext()),
                                      Type::getInt64Ty(m.getContext())},
                                     false);
  unsigned guards = 0;
  for (const Instruction& i : checker.getEntryBlock())
    if (is_proxy_lto_guard(i)) ++guards;
  if (guards > 1 || checker.getFunctionType() != expected || checker.size() != 3 ||
      checker.getInstructionCount() != 7 + guards ||
      (checker.getFnAttribute("obf.lto.finalize").getValueAsString() == "1" && guards != 1))
    fail(m, "target checker lost its exact scalar check ABI or body");
  auto* branch = dyn_cast<BranchInst>(checker.getEntryBlock().getTerminator());
  auto* conjunction = branch && branch->isConditional()
                          ? dyn_cast<BinaryOperator>(branch->getCondition())
                          : nullptr;
  if (!conjunction || conjunction->getOpcode() != Instruction::And)
    fail(m, "target checker lost its conjunction of exact comparisons");
  const auto comparison = [&](Value* value, unsigned right) {
    auto* compare = dyn_cast<ICmpInst>(value);
    return compare && compare->getPredicate() == CmpInst::ICMP_EQ &&
           ((compare->getOperand(0) == checker.getArg(0) &&
             compare->getOperand(1) == checker.getArg(right)) ||
            (compare->getOperand(1) == checker.getArg(0) &&
             compare->getOperand(0) == checker.getArg(right)));
  };
  if (!comparison(conjunction->getOperand(0), 2) || !comparison(conjunction->getOperand(1), 1))
    fail(m,
         "target checker no longer compares the exact decoded, admitted, and permitted operands");
  auto* success = branch->getSuccessor(0);
  auto* failure = branch->getSuccessor(1);
  if (success->size() != 1 || !isa<ReturnInst>(success->front()) || failure->size() != 2 ||
      !isa<UnreachableInst>(failure->back()))
    fail(m, "target checker no longer returns only on success or traps on mismatch");
  auto* trap_call = dyn_cast<CallInst>(&failure->front());
  if (!trap_call || trap_call->getIntrinsicID() != Intrinsic::trap)
    fail(m, "target checker lost its explicit mismatch trap");
}

Value* pointer_word_source(Value* value) {
  if (auto* cast = dyn_cast<PtrToIntInst>(value)) return cast->getOperand(0);
  if (auto* cast = dyn_cast<ConstantExpr>(value))
    if (cast->getOpcode() == Instruction::PtrToInt) return cast->getOperand(0);
  return nullptr;
}

void validate_return(Module& m, const CallInst& call, bool musttail) {
  if (musttail && !call.isMustTailCall()) fail(m, "required musttail edge changed");
  const auto* ret = dyn_cast_or_null<ReturnInst>(call.getNextNode());
  if (!ret || (!call.getType()->isVoidTy() && ret->getReturnValue() != &call))
    fail(m,
         "private transfer no longer forwards the exact result: owner=" +
             call.getFunction()->getName().str() +
             " role=" + md_text(call.getMetadata(operation_md), 1).str() +
             " tail_kind=" + number(call.getTailCallKind()) + " next=" +
             (call.getNextNode() ? std::string(call.getNextNode()->getOpcodeName()) : "missing"));
}

void validate_helper(Module& m, Function& f) {
  if (!f.hasLocalLinkage() || !f.isDSOLocal() ||
      f.getDLLStorageClass() != GlobalValue::DefaultStorageClass ||
      !f.hasFnAttribute(Attribute::NoInline) || !f.hasFnAttribute(Attribute::OptimizeNone))
    fail(m, "private helper linkage or pinning contract changed");
  unsigned guards = 0;
  for (Instruction& i : f.getEntryBlock())
    if (is_proxy_lto_guard(i)) ++guards;
  if (guards > 1 || (f.getFnAttribute("obf.lto.finalize").getValueAsString() == "1" && guards != 1))
    fail(m, "private helper lost its exact required-finalization self-address guard");
  const auto fingerprint = f.getFnAttribute(fingerprint_attr);
  const auto actual = function_fingerprint(f);
  if (!fingerprint.isValid() || fingerprint.getValueAsString() != actual)
    fail(m,
         "private helper structure or data flow changed: helper=" + f.getName().str() +
             " node_id=" + f.getFnAttribute("obf.lto.proxy.node").getValueAsString().str() +
             " expected=" +
             (fingerprint.isValid() ? fingerprint.getValueAsString().str() : "missing") +
             " actual=" + actual);
  if (f.hasFnAttribute(Attribute::Memory) || f.hasFnAttribute(Attribute::Speculatable) ||
      f.hasFnAttribute(Attribute::WillReturn) || f.hasFnAttribute(Attribute::MustProgress))
    fail(m, "private helper acquired unsupported implementation promises");
}

std::optional<unsigned> context_store_field(StoreInst& store, Value* context, Module& m) {
  std::int64_t offset = 0;
  Value* base =
      GetPointerBaseWithConstantOffset(store.getPointerOperand(), offset, m.getDataLayout());
  if (base != context) return std::nullopt;
  const auto* layout = m.getDataLayout().getStructLayout(context_type(m.getContext()));
  for (unsigned i = 0; i < context_field_count; ++i)
    if (offset >= 0 && std::uint64_t(offset) == layout->getElementOffset(i) &&
        store.getValueOperand()->getType() == context_type(m.getContext())->getElementType(i))
      return i;
  fail(m, "context store does not address one complete typed context field");
}

void validate_stateful_owner(Module& m, const proxy_live_contract& c, CallInst& entry) {
  const auto& r = c.route;
  auto* ctx = dyn_cast_or_null<AllocaInst>(static_cast<Value*>(c.context));
  if (!ctx || ctx->getFunction() != entry.getFunction() ||
      ctx->getParent() != &entry.getFunction()->getEntryBlock() || !ctx->isStaticAlloca() ||
      ctx->getAllocatedType() != context_type(m.getContext()) ||
      ctx->getAlign() < m.getDataLayout().getABITypeAlign(context_type(m.getContext())) ||
      entry.getArgOperand(entry.arg_size() - 1) != ctx || !entry.isNoTailCall())
    fail(m, "stateful entry lost its fixed entry-block allocation or notail transfer");
  DominatorTree dom(*entry.getFunction());
  std::array<StoreInst*, context_field_count> stores{};
  for (Instruction& i : instructions(*entry.getFunction())) {
    auto* s = dyn_cast<StoreInst>(&i);
    if (!s || role_of(i, r.route_id) != "context.initialize") continue;
    const auto index = context_store_field(*s, ctx, m);
    if (!index) continue;
    if (stores[*index]) fail(m, "context initialization field is ambiguous");
    stores[*index] = s;
    if (!dom.dominates(s, &entry)) fail(m, "context initialization does not dominate entry");
  }
  for (StoreInst* store : stores)
    if (!store) fail(m, "context field lost its full initialization");
  const auto constant = [&](unsigned field, std::uint64_t expected) {
    auto* value = dyn_cast<ConstantInt>(stores[field]->getValueOperand());
    if (!value || value->getZExtValue() != expected)
      fail(m, "context initializer differs from the immutable descriptor");
  };
  constant(schema, call_proxy_schema);
  constant(phase, 0);
  constant(owner_id, r.source.site.identity.owner_id);
  constant(site_id, r.source.site.identity.site_id);
  constant(route_id, r.route_id);
  constant(descriptor_index, r.descriptor_index);
  constant(step, 0);
  constant(expected_node, r.nodes.front().identity);
  for (unsigned field : {observed_continuation, root, token, encoded_target}) constant(field, 0);
  if (stores[admitted_target]->getValueOperand() != static_cast<Value*>(c.admitted_target))
    fail(m, "context target lost the admitted operand dependency");
  auto* snapshot = dyn_cast<Instruction>(stores[entropy_snapshot]->getValueOperand());
  bool accessor = false;
  for (Instruction& i : instructions(*entry.getFunction())) {
    auto* call = dyn_cast<CallInst>(&i);
    if (call && call->getCalledFunction() &&
        call->getCalledFunction()->getName() == OBF_RT_LOAD_ENTROPY_PAIR_STR &&
        depends_on(snapshot, call))
      accessor = true;
  }
  if (!accessor) fail(m, "context snapshot no longer uses the initialized entropy accessor");
  SmallVector<Value*, 8> pointers{ctx};
  SmallPtrSet<Value*, 16> visited;
  while (!pointers.empty()) {
    Value* pointer = pointers.pop_back_val();
    if (!visited.insert(pointer).second) continue;
    for (User* user : pointer->users()) {
      if (user == &entry && pointer == ctx) continue;
      if (isa<GetElementPtrInst>(user) || isa<BitCastInst>(user)) {
        pointers.push_back(user);
        continue;
      }
      if (auto* lifetime = dyn_cast<IntrinsicInst>(user))
        if (lifetime->getIntrinsicID() == Intrinsic::lifetime_start ||
            lifetime->getIntrinsicID() == Intrinsic::lifetime_end)
          continue;
      if (auto* store = dyn_cast<StoreInst>(user))
        if (store->getPointerOperand() == pointer &&
            role_of(*store, r.route_id) == "context.initialize" &&
            context_store_field(*store, ctx, m))
          continue;
      fail(m, "private context escaped its caller allocation");
    }
  }
}

proxy_resource_counts count_live_resources(Module& m, const proxy_contract_registry& registry) {
  proxy_resource_counts counts;
  SmallPtrSet<Function*, 32> helpers;
  SmallPtrSet<const Instruction*, 32> counted_caller;
  std::map<Function*, std::uint64_t> sites, contexts;
  for (const auto& c : registry.contracts) {
    auto* owner = dyn_cast_or_null<Function>(static_cast<Value*>(c.owner));
    if (!owner || owner->isDeclaration()) continue;
    ++counts.sites;
    ++sites[owner];
    contexts[owner] = checked_add(m, contexts[owner], c.exact_context_bytes);
    counts.context_bytes = checked_add(m, counts.context_bytes, c.exact_context_bytes);
    counts.memberships = checked_add(
        m,
        counts.memberships,
        c.hops.size() + (c.route.source.admission.mode == proxy_route_mode::stateful ? 2 : 0));
    for (const auto& handle : c.hops)
      if (auto* f = dyn_cast_or_null<Function>(static_cast<Value*>(handle))) helpers.insert(f);
    if (auto* f = dyn_cast_or_null<Function>(static_cast<Value*>(c.terminal))) helpers.insert(f);
    if (auto* f = dyn_cast_or_null<Function>(static_cast<Value*>(c.checker))) helpers.insert(f);
    for (const auto& dependency : c.route.source.admission.dependencies)
      if (auto* function = dyn_cast_or_null<Function>(static_cast<Value*>(dependency.function)))
        helpers.insert(function);
    for (Instruction& i : instructions(*owner))
      if (!role_of(i, c.route.route_id).empty() && counted_caller.insert(&i).second)
        ++counts.added_instructions;
  }
  for (const auto& [owner, count] : sites)
    if (owner->hasFnAttribute("obf.lto.proxy.guard.pending")) {
      bool materialized = false;
      for (Instruction& i : owner->getEntryBlock())
        if (is_exact_finalization_guard(i)) {
          if (counted_caller.insert(&i).second) ++counts.added_instructions;
          materialized = true;
        }
      if (!materialized) ++counts.pending_lto_guard_instructions;
    }
  for (Function* f : helpers) {
    for (Instruction& i : instructions(*f))
      if ((!f->hasFnAttribute("obf.lto.proxy.dependency") ||
           f->hasFnAttribute("obf.lto.proxy.node") || is_exact_finalization_guard(i)) &&
          counted_caller.insert(&i).second)
        ++counts.added_instructions;
    if (f->hasFnAttribute("obf.lto.proxy.guard.pending") && !sites.contains(f)) {
      bool materialized = false;
      for (Instruction& i : instructions(*f)) materialized |= is_proxy_lto_guard(i);
      if (!materialized) ++counts.pending_lto_guard_instructions;
    }
  }
  counts.nodes = helpers.size();
  if (registry.configured) {
    for (const auto& [owner, count] : sites)
      if (count > registry.options.max_sites_per_owner)
        fail(m, "retained sites exceed the owner resource policy");
    for (const auto& [owner, count] : contexts)
      if (count > registry.options.max_context_bytes_per_owner)
        fail(m, "retained contexts exceed the owner resource policy");
    if (counts.nodes > registry.options.max_nodes_per_module ||
        checked_add(m, counts.added_instructions, counts.pending_lto_guard_instructions) >
            registry.options.max_added_ir_instructions)
      fail(m, "live proxy resources exceed the module policy");
  }
  return counts;
}

}  // namespace

void validate_live_proxy_contracts(Module& m,
                                   const proxy_contract_registry& registry,
                                   const proxy_platform_contract& platform) {
  if (!registry.contracts.empty() && !platform.supported)
    fail(m, "live proxy platform is no longer supported");
  if (!registry.contracts.empty() && !platform.terminal_hardening)
    fail(m, "live proxy terminal hardening is no longer qualified");
  std::map<Function*, unsigned> memberships;
  SmallPtrSet<Function*, 32> checked_helpers;
  std::set<std::tuple<std::uint64_t, std::uint64_t, std::uint64_t, std::uint64_t>> instances;
  for (const auto& c : registry.contracts) {
    auto* owner = dyn_cast_or_null<Function>(static_cast<Value*>(c.owner));
    if (!owner || owner->isDeclaration()) continue;
    auto* entry = dyn_cast_or_null<CallInst>(static_cast<Value*>(c.entry));
    if (!entry || entry->getFunction() != owner || !is_call_proxy_entry(*entry))
      fail(m, "live owner lost its explicit proxy entry");
    if (owner->hasFnAttribute("obf.lto.proxy.guard.pending") &&
        owner->getFnAttribute("obf.lto.finalize").getValueAsString() == "1") {
      unsigned guards = 0;
      for (Instruction& i : owner->getEntryBlock())
        if (is_exact_finalization_guard(i)) ++guards;
      if (guards != 1 || !owner->hasFnAttribute(Attribute::NoInline) ||
          !owner->hasFnAttribute(Attribute::OptimizeNone))
        fail(m,
             "live proxy owner lost its required ABI and operand-association preservation guard");
    }
    const auto& r = c.route;
    proxy_admission observed_dependencies;
    collect_vm_proxy_dependencies(r.source.site, observed_dependencies);
    if (observed_dependencies.dependencies.size() != r.source.admission.dependencies.size())
      fail(m, "registered VM resolver dependency set changed");
    for (const auto& dependency : r.source.admission.dependencies) {
      auto* function = dyn_cast_or_null<Function>(static_cast<Value*>(dependency.function));
      if (!function || function->isDeclaration() || !function->hasLocalLinkage() ||
          function->getFnAttribute("obf.lto.proxy.dependency").getValueAsString() !=
              number(dependency.identity) ||
          dependency_abi_key(*function) != dependency.abi_identity ||
          !function->hasFnAttribute(Attribute::NoInline) ||
          !function->hasFnAttribute(Attribute::OptimizeNone))
        fail(m,
             "registered VM resolver dependency lost its exact identity, ABI, or pinning contract");
      bool observed = false;
      for (const auto& actual : observed_dependencies.dependencies)
        observed |=
            actual.identity == dependency.identity && actual.function == dependency.function;
      if (!observed)
        fail(m, "registered VM resolver dependency no longer feeds its recorded operand roles");
      if (function->getFnAttribute("obf.lto.finalize").getValueAsString() == "1") {
        unsigned guards = 0;
        for (Instruction& i : function->getEntryBlock())
          if (is_exact_finalization_guard(i)) ++guards;
        if (guards != 1)
          fail(m, "retained VM resolver dependency lost its exact required-finalization guard");
      }
    }
    for (const auto& handle : observed_dependencies.preserved_global_loads)
      if (auto* load = dyn_cast_or_null<LoadInst>(static_cast<Value*>(handle));
          !load || !load->isVolatile())
        fail(m, "registered VM operand input lost its existing bound volatile global load");
    if (c.configuration_identity != call_proxy_configuration_identity(registry.options))
      fail(m, "retained proxy configuration differs");
    if (c.platform_identity != platform.identity)
      fail(m, "retained proxy platform qualification differs");
    if (!instances
             .emplace(r.source.site.identity.module_id,
                      r.source.site.identity.owner_id,
                      r.source.site.identity.site_id,
                      r.source.site.identity.instance_id)
             .second)
      fail(m, "live proxy instance identity collision");
    if (r.nodes.size() < registry.options.min_hops || r.nodes.size() > registry.options.max_hops ||
        c.hops.size() != r.nodes.size())
      fail(m, "live route hop count differs from policy");
    if (entry->getCalledOperand() != static_cast<Value*>(c.hops.front()))
      fail(m, "proxy entry no longer reaches the permitted first hop");
    const bool stateful = r.source.admission.mode == proxy_route_mode::stateful;
    if (stateful) validate_stateful_owner(m, c, *entry);
    else
      validate_return(m, *entry, true);
    for (unsigned position = 0; position < c.hops.size(); ++position) {
      auto* f = dyn_cast_or_null<Function>(static_cast<Value*>(c.hops[position]));
      if (!f || f->isDeclaration()) fail(m, "live proxy route lost a protected hop");
      ++memberships[f];
      if (checked_helpers.insert(f).second) validate_helper(m, *f);
      if (!compatible_subtarget(*owner, *f) || !f->hasUWTable())
        fail(m, "private helper subtarget or unwind contract changed");
      if (f->getFunctionType() != entry->getFunctionType() ||
          f->getCallingConv() != entry->getCallingConv() ||
          fresh_attributes(m.getContext(), f->getAttributes(), f->arg_size()) !=
              fresh_attributes(m.getContext(), entry->getAttributes(), entry->arg_size()))
        fail(m, "proxy edge effective ABI changed");
      const bool last_abi = !stateful && position + 1 == c.hops.size();
      CallInst* transfer = route_transfer(*f, r.route_id, last_abi);
      // ABI-only suffixes have one edge shared by all members of the exact target group.
      if (!transfer && !stateful)
        for (Instruction& i : instructions(*f))
          if (auto* call = dyn_cast<CallInst>(&i); call && call->isMustTailCall()) transfer = call;
      if (!transfer) fail(m, "proxy route lost its exact transfer role");
      validate_return(m, *transfer, true);
      if (transfer->getFunctionType() != entry->getFunctionType() ||
          transfer->getCallingConv() != entry->getCallingConv())
        fail(m, "private musttail ABI changed");
      if (fresh_attributes(m.getContext(), transfer->getAttributes(), transfer->arg_size()) !=
          fresh_attributes(m.getContext(), f->getAttributes(), f->arg_size()))
        fail(m, "private musttail qualified ABI attributes changed");
      if (!last_abi) {
        Value* next = position + 1 < c.hops.size() ? static_cast<Value*>(c.hops[position + 1])
                                                   : static_cast<Value*>(c.terminal);
        if (transfer->getCalledOperand() != next)
          fail(m, "private edge no longer reaches its permitted next node");
      } else {
        auto* loaded = dyn_cast<LoadInst>(transfer->getCalledOperand());
        auto* slot = loaded ? dyn_cast<AllocaInst>(loaded->getPointerOperand()) : nullptr;
        StoreInst* materialize = nullptr;
        if (slot)
          for (User* user : slot->users()) {
            if (user == loaded) continue;
            auto* store = dyn_cast<StoreInst>(user);
            if (!store || store->getPointerOperand() != slot || materialize)
              fail(m, "ABI-only local target slot escaped or acquired an ambiguous writer");
            materialize = store;
          }
        DominatorTree dom(*f);
        if (!loaded || !loaded->isVolatile() || !slot || !slot->isStaticAlloca() ||
            slot->getParent() != &f->getEntryBlock() || !materialize ||
            !materialize->isVolatile() ||
            materialize->getValueOperand() != static_cast<Value*>(r.source.admission.target) ||
            !dom.dominates(materialize, loaded) || !dom.dominates(loaded, transfer))
          fail(m, "ABI-only terminal lost its exact local indirect target materialization");
      }
      for (unsigned i = 0; i < transfer->arg_size(); ++i)
        if (transfer->getArgOperand(i) != f->getArg(i))
          fail(m, "private edge changed an argument or hidden VM token");
      unsigned captures = 0;
      for (Instruction& i : instructions(*f))
        if (auto* call = dyn_cast<CallInst>(&i);
            call && call->getIntrinsicID() == Intrinsic::returnaddress)
          ++captures;
      if (captures != (stateful && position == 0 ? 1U : 0U))
        fail(m, "continuation must be captured exactly once in the designated first hop");
    }
    if (stateful) {
      auto* terminal = dyn_cast_or_null<Function>(static_cast<Value*>(c.terminal));
      if (!terminal) fail(m, "terminal bridge is missing");
      if (checked_helpers.insert(terminal).second) validate_helper(m, *terminal);
      auto* transfer = route_transfer(*terminal, r.route_id, true);
      if (!transfer || transfer->isMustTailCall() ||
          transfer->arg_size() + 1 != terminal->arg_size())
        fail(m, "stateful terminal lost its ordinary exact target call");
      validate_return(m, *transfer, false);
      Instruction* decode = nullptr;
      StoreInst* consume = nullptr;
      CallInst* validation = nullptr;
      for (Instruction& i : instructions(*terminal)) {
        const auto role = role_of(i, r.route_id);
        if (role == "target.decode") decode = &i;
        if (role == "state.consume") consume = dyn_cast<StoreInst>(&i);
        if (role == "check.target.binding") validation = dyn_cast<CallInst>(&i);
      }
      auto* checker = dyn_cast_or_null<Function>(static_cast<Value*>(c.checker));
      if (!checker || !decode || !consume || !validation ||
          validation->getCalledFunction() != checker || validation->arg_size() != 3 ||
          validation->getArgOperand(0) != decode ||
          !depends_on(transfer->getCalledOperand(), decode))
        fail(m, "terminal lost its exact target-check call or decoded-target data flow");
      if (checked_helpers.insert(checker).second) validate_helper(m, *checker);
      validate_target_checker(m, *checker);
      if (checker->getCallingConv() != validation->getCallingConv() ||
          !compatible_subtarget(*terminal, *checker))
        fail(m, "target checker calling convention or subtarget changed");
      auto* admitted_load =
          dyn_cast_or_null<LoadInst>(pointer_word_source(validation->getArgOperand(1)));
      std::int64_t admitted_offset = 0;
      if (!admitted_load ||
          GetPointerBaseWithConstantOffset(
              admitted_load->getPointerOperand(), admitted_offset, m.getDataLayout()) !=
              terminal->getArg(terminal->arg_size() - 1) ||
          admitted_offset != std::int64_t(m.getDataLayout()
                                              .getStructLayout(context_type(m.getContext()))
                                              ->getElementOffset(admitted_target)) ||
          pointer_word_source(validation->getArgOperand(2)) !=
              static_cast<Value*>(r.source.admission.target))
        fail(m, "target checker lost the exact admitted context field or permitted target");
      DominatorTree dom(*terminal);
      if (!dom.dominates(validation, consume) || !dom.dominates(validation, transfer))
        fail(m, "target validation no longer dominates consumption and transfer");
      if (!dom.dominates(consume, transfer))
        fail(m, "terminal no longer consumes the context before transfer");
      for (unsigned i = 0; i < transfer->arg_size(); ++i)
        if (transfer->getArgOperand(i) != terminal->getArg(i))
          fail(m, "terminal changed an original argument");
      auto* target = cast<Function>(static_cast<Value*>(r.source.admission.target));
      if (transfer->getFunctionType() != target->getFunctionType() ||
          transfer->getCallingConv() != target->getCallingConv() ||
          fresh_attributes(m.getContext(), transfer->getAttributes(), transfer->arg_size()) !=
              fresh_attributes(m.getContext(), target->getAttributes(), target->arg_size()))
        fail(m, "terminal target effective ABI changed");
    }
    const auto& s = r.source.site;
    if (md_text(entry->getMetadata(entry_md), 4) != "admitted-target" ||
        md_text(entry->getMetadata(entry_md), 5) !=
            decode_fingerprint(static_cast<Value*>(c.admitted_target), entry))
      fail(m, "entry target lost its registered resolver dependency");
    if (s.is_vm && !s.preserved_musttail) {
      if (!s.binding.binding_id || !s.hidden_token_operand ||
          entry->getArgOperand(entry->arg_size() - (stateful ? 2 : 1)) !=
              static_cast<Value*>(s.hidden_token_operand))
        fail(m, "VM hidden token or binding association changed");
      if (auto* token_value = dyn_cast<ConstantInt>(static_cast<Value*>(s.hidden_token_operand)))
        if (token_value->getZExtValue() != s.original_site_token)
          fail(m, "VM hidden token differs from its immutable site contract");
      const auto* roles = entry->getMetadata(entry_md);
      if (md_text(roles, 1) != "hidden-token" ||
          md_text(roles, 2) != number(entry->arg_size() - 2) ||
          md_text(roles, 3) !=
              decode_fingerprint(static_cast<Value*>(s.hidden_token_operand), entry))
        fail(m, "VM hidden token lost its registered operand provenance");
      if (s.return_contract.role == vm_result_role::encoded_integer) {
        auto* decode = dyn_cast_or_null<Instruction>(static_cast<Value*>(s.return_decode_root));
        if (!decode || decode->getFunction() != owner || !depends_on(decode, entry))
          fail(m, "VM encoded result lost its original caller decode");
        if (md_text(decode->getMetadata("obf.lto.proxy.return"), 3) !=
            decode_fingerprint(decode, entry))
          fail(m, "VM caller return-decode structure or data flow changed");
        GlobalVariable* key = owner->getParent()->getNamedGlobal(s.return_contract.key_global_name);
        if (!key)
          for (GlobalVariable& global : m.globals())
            if (md_text(global.getMetadata("obf.lto.proxy.value"), 0) ==
                s.return_contract.key_global_name)
              key = &global;
        if (!key || !depends_on(decode, key) ||
            !depends_on(decode, static_cast<Value*>(s.hidden_token_operand)))
          fail(m, "VM return decode lost its exact key or hidden-token dependency");
        bool retained_key_load = false;
        for (Instruction& i : instructions(*owner))
          if (auto* load = dyn_cast<LoadInst>(&i))
            if (load->isVolatile() && load->getPointerOperand()->stripPointerCasts() == key &&
                depends_on(decode, load))
              retained_key_load = true;
        if (!retained_key_load)
          fail(m, "VM return decode lost its original bound volatile key load");
        SmallPtrSet<const Value*, 32> visited;
        SmallVector<const Value*, 16> encoded_uses{entry};
        while (!encoded_uses.empty()) {
          const Value* value = encoded_uses.pop_back_val();
          if (value == decode || !visited.insert(value).second) continue;
          for (const User* user : value->users()) {
            if (!depends_on(decode, user))
              fail(m, "VM encoded result bypasses its single recorded decode");
            encoded_uses.push_back(user);
          }
        }
        for (User* user : entry->users())
          if (!depends_on(decode, user))
            fail(m, "VM encoded result escaped its single recorded caller decode");
      }
    }
  }
  for (const auto& [node, count] : memberships)
    if (count > registry.options.max_routes_per_shared_node)
      fail(m, "shared node exceeds its finite route membership policy");
  count_live_resources(m, registry);
}

void retain_call_proxy_contracts(Module& m,
                                 const proxy_contract_registry& registry,
                                 const call_proxy_options& options) {
  if (registry.configured && call_proxy_configuration_identity(registry.options) !=
                                 call_proxy_configuration_identity(options))
    fail(m, "retention configuration differs from emitted policy");
  for (const auto& c : registry.contracts) {
    auto* owner = dyn_cast_or_null<Function>(static_cast<Value*>(c.owner));
    if (!owner || owner->isDeclaration()) continue;
    auto* entry = dyn_cast_or_null<CallInst>(static_cast<Value*>(c.entry));
    if (!entry || !entry->getMetadata(entry_md)) fail(m, "retention lost a live proxy entry");
    owner->addFnAttr("obf.lto.proxy.schema", number(call_proxy_schema));
    owner->addFnAttr("obf.lto.proxy.owner", number(c.route.source.site.identity.owner_id));
    owner->addFnAttr("obf.lto.proxy.config", call_proxy_configuration_identity(options));
    std::string ledger = owner->getFnAttribute("obf.lto.proxy.contract").getValueAsString().str();
    const std::string item = number(c.route.route_id) + ',';
    if (StringRef(ledger).find(item) == StringRef::npos) ledger += item;
    owner->addFnAttr("obf.lto.proxy.contract", ledger);
  }
}

void recover_call_proxy_contracts(Module& m,
                                  proxy_contract_registry& registry,
                                  const call_proxy_options& options) {
  registry.options = options;
  registry.configured = true;
  std::map<std::uint64_t, Function*> nodes, targets, dependencies;
  for (Function& f : m) {
    if (f.hasFnAttribute("obf.lto.proxy.node")) {
      const auto id = integer(f.getFnAttribute("obf.lto.proxy.node").getValueAsString(), m);
      if (nodes.contains(id) && nodes[id] != &f) fail(m, "ambiguous imported proxy node identity");
      nodes[id] = &f;
    }
    if (f.hasFnAttribute("obf.lto.proxy.target")) {
      const auto id = integer(f.getFnAttribute("obf.lto.proxy.target").getValueAsString(), m);
      if (targets.contains(id) && targets[id] != &f)
        fail(m, "ambiguous imported permitted target identity");
      targets[id] = &f;
    }
    if (f.hasFnAttribute("obf.lto.proxy.dependency")) {
      const auto id = integer(f.getFnAttribute("obf.lto.proxy.dependency").getValueAsString(), m);
      if (dependencies.contains(id) && dependencies[id] != &f)
        fail(m, "ambiguous imported resolver dependency identity");
      dependencies[id] = &f;
    }
  }
  std::set<const Instruction*> known;
  using instance_key = std::tuple<std::uint64_t, std::uint64_t, std::uint64_t, std::uint64_t>;
  std::map<instance_key, unsigned> source_instances;
  std::set<instance_key> assigned_instances;
  for (const auto& c : registry.contracts)
    if (auto* i = dyn_cast_or_null<Instruction>(static_cast<Value*>(c.entry))) known.insert(i);
  for (const auto& c : registry.contracts) {
    const auto& id = c.route.source.site.identity;
    const instance_key key{id.module_id, id.owner_id, id.site_id, id.instance_id};
    ++source_instances[key];
    assigned_instances.insert(key);
  }
  for (Function& owner : m) {
    if (owner.isDeclaration() || is_call_proxy_helper(owner)) continue;
    const bool obligation = owner.hasFnAttribute("obf.lto.proxy.contract");
    bool found = false;
    std::set<std::uint64_t> found_routes;
    for (Instruction& i : instructions(owner)) {
      auto* metadata = i.getMetadata(entry_md);
      if (!metadata) continue;
      found = true;
      if (!options.enabled)
        fail(m, "retained proxy obligations require the same enabled configuration");
      auto* entry = dyn_cast<CallInst>(&i);
      if (!entry) fail(m, "retained entry metadata no longer identifies a call");
      if (known.contains(entry)) {
        for (const auto& c : registry.contracts)
          if (static_cast<Value*>(c.entry) == entry) found_routes.insert(c.route.route_id);
        continue;
      }
      auto contract = deserialize_route(m, md_text(metadata, 0), nodes, targets, dependencies);
      auto& identity = contract.route.source.site.identity;
      instance_key original{
          identity.module_id, identity.owner_id, identity.site_id, identity.instance_id};
      const auto occurrence = source_instances[original]++;
      if (occurrence) identity.instance_id = nonzero(combine(identity.instance_id, occurrence + 1));
      if (!assigned_instances
               .emplace(
                   identity.module_id, identity.owner_id, identity.site_id, identity.instance_id)
               .second)
        fail(m, "deterministic imported clone instance identity collision");
      contract.owner = &owner;
      contract.entry = entry;
      const bool stateful = contract.route.source.admission.mode == proxy_route_mode::stateful;
      if (stateful && entry->arg_size())
        contract.context = entry->getArgOperand(entry->arg_size() - 1);
      contract.admitted_target = static_cast<Value*>(contract.route.source.admission.target);
      for (Instruction& role : instructions(owner)) {
        if (role_of(role, contract.route.route_id) != "context.initialize") continue;
        auto* store = dyn_cast<StoreInst>(&role);
        if (!store) continue;
        const auto index = context_store_field(*store, static_cast<Value*>(contract.context), m);
        if (index && *index == admitted_target) contract.admitted_target = store->getValueOperand();
      }
      auto& site = contract.route.source.site;
      found_routes.insert(contract.route.route_id);
      site.owner_function = &owner;
      site.source_owner_function = &owner;
      site.replacement_call = entry;
      site.decoded_target = static_cast<Value*>(contract.admitted_target);
      if (site.is_vm && !site.preserved_musttail && entry->arg_size() >= (stateful ? 2U : 1U))
        site.hidden_token_operand = entry->getArgOperand(entry->arg_size() - (stateful ? 2 : 1));
      for (Instruction& role : instructions(owner))
        if (auto* md = role.getMetadata("obf.lto.proxy.return"))
          if (md_text(md, 0) == number(contract.route.route_id) && depends_on(&role, entry)) {
            if (site.return_decode_root) fail(m, "ambiguous retained VM return-decode association");
            if (md_text(md, 1) != number(site.binding.binding_id) ||
                md_text(md, 2) != number(site.original_site_token))
              fail(m, "retained VM return-decode binding differs");
            site.return_decode_root = &role;
          }
      site.encoded_result = entry;
      site.effective_abi = make_proxy_abi_descriptor(*entry);
      if (contract.configuration_identity != call_proxy_configuration_identity(options))
        fail(m, "retained call proxy configuration identity differs");
      registry.contracts.push_back(std::move(contract));
    }
    if (obligation) {
      if (!found) fail(m, "live retained owner lost all explicit proxy entry facts");
      SmallVector<StringRef, 16> expected;
      owner.getFnAttribute("obf.lto.proxy.contract")
          .getValueAsString()
          .split(expected, ',', -1, false);
      for (StringRef route : expected)
        if (!found_routes.contains(integer(route, m)))
          fail(m, "live retained owner lost a required route obligation");
    }
  }
  registry.exact = count_live_resources(m, registry);
  if (!registry.contracts.empty())
    validate_live_proxy_contracts(m, registry, proxy_platform_contract_for(m));
  for (auto& c : registry.contracts) {
    auto* entry = dyn_cast_or_null<CallInst>(static_cast<Value*>(c.entry));
    if (!entry || !c.recovered) continue;
    const auto* old = entry->getMetadata(entry_md);
    SmallVector<Metadata*, 8> operands;
    operands.push_back(MDString::get(m.getContext(), serialize_route(c)));
    for (unsigned i = 1; i < old->getNumOperands(); ++i)
      operands.push_back(old->getOperand(i).get());
    entry->setMetadata(entry_md, MDNode::get(m.getContext(), operands));
  }
}

void release_call_proxy_metadata(Module& m) {
  for (Function& f : m) {
    SmallVector<std::string, 16> attrs;
    for (Attribute a : f.getAttributes().getFnAttrs())
      if (a.isStringAttribute() && (a.getKindAsString().starts_with("obf.lto.proxy.") ||
                                    a.getKindAsString().starts_with("obf.call.proxy.")))
        attrs.push_back(a.getKindAsString().str());
    for (const auto& name : attrs) f.removeFnAttr(name);
    f.setMetadata("obf.lto.proxy.value", nullptr);
    for (Instruction& i : instructions(f)) {
      i.setMetadata(entry_md, nullptr);
      i.setMetadata(operation_md, nullptr);
      i.setMetadata("obf.lto.proxy.return", nullptr);
      i.setMetadata("obf.call.proxy.source", nullptr);
      i.setMetadata("obf.call.proxy.site", nullptr);
      i.setMetadata("obf.call.proxy.roles", nullptr);
    }
  }
  for (GlobalVariable& global : m.globals()) global.setMetadata("obf.lto.proxy.value", nullptr);
}

proxy_stage_result apply_call_proxy_chain_stage(Module& m,
                                                const call_proxy_options& options,
                                                live_proxy_site_registry& sites,
                                                proxy_contract_registry& registry) {
  proxy_stage_result result;
  registry.options = options;
  registry.configured = true;
  if (!options.enabled) {
    if (!registry.contracts.empty())
      fail(m, "enabled policy changed for retained proxy obligations");
    return result;
  }
  const auto platform = proxy_platform_contract_for(m);
  std::set<std::tuple<std::uint64_t, std::uint64_t, std::uint64_t, std::uint64_t>> invalid;
  const auto key = [](const source_site_identity& i) {
    return std::make_tuple(i.module_id, i.owner_id, i.site_id, i.instance_id);
  };
  const auto record = [&](proxy_coverage_event event) {
    const bool required_failure = event.required && !event.protected_site && event.code != "dead";
    if (required_failure) {
      std::string owner = number(event.identity.owner_id), target = number(event.identity.site_id);
      for (const auto& site : sites.sites())
        if (site.identity == event.identity) {
          if (auto* function =
                  dyn_cast_or_null<Function>(static_cast<Value*>(site.source_owner_function)))
            owner = function->getName().str();
          if (auto* function =
                  dyn_cast_or_null<Function>(static_cast<Value*>(site.expected_target)))
            target = function->getName().str();
          break;
        }
      record_coverage_event(m,
                            "emission",
                            "call_proxy",
                            owner,
                            target,
                            "unsupported",
                            event.code + ": " + event.diagnostic +
                                " module_id=" + number(event.identity.module_id) +
                                " owner_id=" + number(event.identity.owner_id) +
                                " site_id=" + number(event.identity.site_id) +
                                " instance_id=" + number(event.identity.instance_id),
                            event.hops);
    }
    result.events.push_back(std::move(event));
    if (required_failure) fail(m, result.events.back().diagnostic);
  };
  for (const auto& issue : sites.rebuild(m)) {
    bool strict = options.coverage_policy == proxy_coverage_policy::required;
    for (const auto& site : sites.sites())
      if (site.identity == issue.identity) strict |= site.required;
    invalid.insert(key(issue.identity));
    proxy_coverage_event event;
    event.identity = issue.identity;
    event.required = strict;
    event.code = issue.code;
    event.diagnostic = issue.diagnostic;
    record(std::move(event));
  }
  std::vector<admitted_proxy_site> admitted;
  for (auto& site : sites.sites()) {
    if (!site.selected || site.consumed || invalid.contains(key(site.identity))) continue;
    proxy_coverage_event event;
    event.identity = site.identity;
    event.binding_id = site.binding.binding_id;
    event.abi_identity = number(site.effective_abi.identity);
    event.required = site.required || options.coverage_policy == proxy_coverage_policy::required;
    if (site.dead) {
      event.code = "dead";
      event.diagnostic = "site has an explicit dead-obligation proof";
      record(std::move(event));
      continue;
    }
    auto admission = analyze_proxy_site(site, platform, options);
    if (!admission.admitted) {
      if (admission.code == "already_protected" ||
          (admission.code == "infrastructure" && !site.is_vm))
        continue;
      event.code = admission.code;
      event.diagnostic = admission.diagnostic;
      record(std::move(event));
      continue;
    }
    admitted.push_back({site, std::move(admission)});
  }
  registry.exact = count_live_resources(m, registry);
  result.exact = registry.exact;
  if (admitted.empty()) {
    result.exact = registry.exact;
    return result;
  }
  SmallPtrSet<Function*, 16> retained_dependencies;
  for (const auto& contract : registry.contracts) {
    auto* owner = dyn_cast_or_null<Function>(static_cast<Value*>(contract.owner));
    if (!owner || owner->isDeclaration()) continue;
    for (const auto& dependency : contract.route.source.admission.dependencies)
      if (auto* function = dyn_cast_or_null<Function>(static_cast<Value*>(dependency.function)))
        retained_dependencies.insert(function);
  }
  auto plan = plan_call_proxy_chains_impl(
      m, admitted, options, registry.exact, registry.reserve_lto_guards, &retained_dependencies);
  for (auto& event : plan.events) record(std::move(event));
  if (plan.routes.empty()) {
    result.exact = registry.exact;
    return result;
  }
  SmallPtrSet<Function*, 16> changed_dependencies;
  for (const auto& route : plan.routes) {
    for (const auto& dependency : route.source.admission.dependencies) {
      auto* function = cast<Function>(static_cast<Value*>(dependency.function));
      if (!changed_dependencies.insert(function).second) continue;
      function->addFnAttr("obf.lto.proxy.dependency", number(dependency.identity));
      function->removeFnAttr(Attribute::AlwaysInline);
      function->removeFnAttr(Attribute::InlineHint);
      function->removeFnAttr(Attribute::OptimizeForSize);
      function->removeFnAttr(Attribute::MinSize);
      function->addFnAttr(Attribute::NoInline);
      function->addFnAttr(Attribute::OptimizeNone);
      if (registry.reserve_lto_guards) function->addFnAttr("obf.lto.proxy.guard.pending");
      function->setMetadata(
          "obf.lto.proxy.value",
          MDNode::get(m.getContext(),
                      {MDString::get(m.getContext(), number(dependency.identity))}));
    }
    for (const auto& handle : route.source.admission.preserved_global_loads) {
      auto* load = dyn_cast_or_null<LoadInst>(static_cast<Value*>(handle));
      if (!load || load->isAtomic() ||
          !isa<GlobalVariable>(getUnderlyingObject(load->getPointerOperand())))
        fail(m, "planned VM operand input no longer names its existing global load");
      load->setVolatile(true);
    }
  }
  for (const auto& route : plan.routes) {
    const auto& site = route.source.site;
    if (!site.is_vm || site.preserved_musttail ||
        site.return_contract.role != vm_result_role::encoded_integer)
      continue;
    auto* owner = cast<Function>(static_cast<Value*>(site.owner_function));
    auto* decode = cast<Instruction>(static_cast<Value*>(site.return_decode_root));
    auto* key = m.getNamedGlobal(site.return_contract.key_global_name);
    bool found = false;
    for (Instruction& i : instructions(*owner))
      if (auto* load = dyn_cast<LoadInst>(&i))
        if (load->getType()->isIntegerTy(64) && key &&
            load->getPointerOperand()->stripPointerCasts() == key && depends_on(decode, load)) {
          load->setVolatile(true);
          found = true;
        }
    if (!found) fail(m, "selected VM return decode has no exact original key load to retain");
  }
  emitted_graph graph;
  for (auto& r : plan.routes) {
    auto* target = cast<Function>(static_cast<Value*>(r.source.admission.target));
    if (!target->hasFnAttribute("obf.lto.proxy.target"))
      target->addFnAttr(
          "obf.lto.proxy.target",
          number(nonzero(target->hasLocalLinkage()
                             ? combine(r.source.site.identity.module_id, hash(target->getName()))
                             : hash(target->getName()))));
    for (unsigned position = 0; position < r.nodes.size(); ++position) {
      const auto id = r.nodes[position].identity;
      if (!graph.nodes.contains(id)) {
        auto* f = Function::Create(
            private_type(r), GlobalValue::InternalLinkage, "__obf_proxy_" + number(id), m);
        helper_attributes(*f, r, id, false);
        graph.nodes[id] = f;
      }
      graph.members[id].push_back({&r, position});
    }
    if (r.source.admission.mode == proxy_route_mode::stateful) {
      if (graph.nodes.contains(r.terminal_id)) fail(m, "terminal and node identity collision");
      auto* terminal = Function::Create(private_type(r),
                                        GlobalValue::InternalLinkage,
                                        "__obf_proxy_bridge_" + number(r.terminal_id),
                                        m);
      helper_attributes(*terminal, r, r.terminal_id, true);
      graph.nodes[r.terminal_id] = terminal;
      if (graph.nodes.contains(r.checker_id)) fail(m, "target checker identity collision");
      auto* check_type = FunctionType::get(Type::getVoidTy(m.getContext()),
                                           {Type::getInt64Ty(m.getContext()),
                                            Type::getInt64Ty(m.getContext()),
                                            Type::getInt64Ty(m.getContext())},
                                           false);
      auto* checker = Function::Create(
          check_type, GlobalValue::InternalLinkage, "__obf_proxy_check_" + number(r.checker_id), m);
      helper_attributes(*checker, r, r.checker_id, true);
      checker->setAttributes(
          AttributeList::get(m.getContext(), checker->getAttributes().getFnAttrs(), {}, {}));
      checker->addFnAttr("obf.lto.proxy.role", "check");
      checker->addFnAttr("obf.lto.proxy.contract", number(r.route_id) + ":target-check");
      graph.nodes[r.checker_id] = checker;
    }
  }
  if (registry.reserve_lto_guards)
    for (auto& [id, function] : graph.nodes) function->addFnAttr("obf.lto.proxy.guard.pending");
  for (auto& [id, members] : graph.members) {
    auto* f = graph.nodes.at(id);
    const auto& r = *members.front().first;
    std::string membership;
    for (const auto& [route, position] : members)
      membership += number(route->route_id) + ':' + number(position) + ',';
    f->addFnAttr("obf.lto.proxy.contract", membership);
    if (r.source.admission.mode == proxy_route_mode::stateful)
      emit_stateful_node(*f, members, graph, options, m);
    else
      emit_abi_node(*f, r, members.front().second, graph, options, m);
  }
  for (const auto& r : plan.routes)
    if (r.source.admission.mode == proxy_route_mode::stateful) {
      auto* terminal = graph.nodes.at(r.terminal_id);
      terminal->addFnAttr("obf.lto.proxy.contract", number(r.route_id) + ":terminal");
      auto* checker = graph.nodes.at(r.checker_id);
      emit_target_checker(*checker, r, m);
      emit_terminal(*terminal, *checker, r, m);
    }
  SmallVector<Function*, 16> changed;
  for (Function* function : changed_dependencies) changed.push_back(function);
  for (const auto& r : plan.routes) {
    auto contract = emit_entry(m, r, graph);
    if (registry.reserve_lto_guards)
      cast<Function>(static_cast<Value*>(contract.owner))->addFnAttr("obf.lto.proxy.guard.pending");
    contract.configuration_identity = call_proxy_configuration_identity(options);
    contract.platform_identity = platform.identity;
    changed.push_back(cast<Function>(static_cast<Value*>(contract.owner)));
    registry.contracts.push_back(std::move(contract));
    for (auto& site : sites.sites())
      if (site.identity == r.source.site.identity) site.consumed = true;
    proxy_coverage_event event;
    event.identity = r.source.site.identity;
    event.required = r.source.site.required;
    event.protected_site = true;
    event.mode = r.source.admission.mode;
    event.hops = r.nodes.size();
    event.route_id = r.route_id;
    event.code = "protected";
    event.binding_id = r.source.site.binding.binding_id;
    event.terminal_id = r.terminal_id;
    event.abi_identity = r.source.admission.abi_identity;
    event.diagnostic = event.mode == proxy_route_mode::stateful ? "stateful context route"
                                                                : "exact-signature ABI-only route";
    record(std::move(event));
  }
  invalidate_effects(m, changed);
  for (auto& contract : registry.contracts)
    if (!contract.recovered) annotate_contract(contract);
  for (auto& [id, f] : graph.nodes) f->addFnAttr(fingerprint_attr, function_fingerprint(*f));
  registry.exact = count_live_resources(m, registry);
  const auto added = registry.exact.added_instructions - result.exact.added_instructions;
  if (graph.nodes.size() > plan.reserved.nodes || added > plan.reserved.added_instructions)
    fail(m, "emission exceeded its complete pre-mutation reservation");
  retain_call_proxy_contracts(m, registry, options);
  validate_live_proxy_contracts(m, registry, platform);
  result.changed = true;
  result.exact = registry.exact;
  return result;
}

}  // namespace obf
