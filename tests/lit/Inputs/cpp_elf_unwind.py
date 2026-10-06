"""Check real C++ exceptions across independently built native ELF modules."""

import argparse
import json
import os
from pathlib import Path
import platform
import sys
import tempfile

from report_contract import coverage_contract
from vm_incoming_abi import run_process


CXX_FLAGS = (
    "-std=c++17", "-fexceptions", "-fcxx-exceptions", "-fno-inline",
    "-g",
)
VM_OWNERS = ("unwind_import", "unwind_callback")
EXCLUDED_OWNERS = (
    "unwind_cleanup_import", "unwind_cleanup_callback",
    "unwind_catch_import", "unwind_catch_callback",
)
INCOMING_OWNER = "unwind_incoming"
RUNTIME_SEED = 0x8123456789ABCDEF

HEADER = r'''
#pragma once
#include <stdint.h>
using U = uint64_t;
#define NOINLINE __attribute__((noinline))
struct Payload {
  U code;
  U cookie;
  int32_t input;
  uint32_t origin;
  U witness;
};
struct Effects {
  U value;
  U store;
  unsigned calls;
  unsigned completed;
  unsigned local_cleanups;
  unsigned local_catches;
  unsigned payload_failures;
};
struct CleanupLog {
  unsigned count;
  unsigned overflow;
  unsigned ids[8];
};
static NOINLINE void append_cleanup(CleanupLog *log, unsigned id) noexcept {
  unsigned index = log->count++;
  if (index < 8) log->ids[index] = id;
  else ++log->overflow;
}
using ThrowCB = U (*)(int, U, Effects *, CleanupLog *);
extern "C" {
U provider_throw(int, U, Effects *, CleanupLog *);
U unwind_import(int, U, Effects *, CleanupLog *);
U unwind_callback(ThrowCB, int, U, Effects *, CleanupLog *);
U unwind_cleanup_import(int, U, Effects *, CleanupLog *);
U unwind_cleanup_callback(ThrowCB, int, U, Effects *, CleanupLog *);
U unwind_catch_import(int, U, Effects *, CleanupLog *);
U unwind_catch_callback(ThrowCB, int, U, Effects *, CleanupLog *);
U unwind_incoming(int, U, Effects *, CleanupLog *);
U unwind_incoming_caller(int, U, Effects *, CleanupLog *);
}
'''

PROVIDER_SOURCE = r'''
#include "unwind.h"
struct ProviderGuard {
  CleanupLog *log;
  NOINLINE ~ProviderGuard() noexcept { append_cleanup(log, 31); }
};
extern "C" NOINLINE U provider_throw(int x, U cookie, Effects *e, CleanupLog *log) {
  ProviderGuard guard{log};
  U word = U(uint32_t(x));
  U effect = word + cookie * 3;
  e->value += effect;
  e->store = effect ^ cookie;
  ++e->calls;
  if (x < 0)
    throw Payload{word ^ 0x13579bdf2468ace0ULL, cookie, x, 1,
                  (cookie * 17) ^ word ^ 0x1020304050607080ULL};
  return word * 5 + cookie;
}
'''

LOCAL_GUARD = r'''
struct LocalGuard {
  Effects *e;
  CleanupLog *log;
  unsigned id;
  NOINLINE ~LocalGuard() noexcept {
    ++e->local_cleanups;
    append_cleanup(log, id);
  }
};
'''

POSITIVE_SOURCE = r'''
#include "unwind.h"
extern "C" NOINLINE U unwind_import(int x, U cookie, Effects *e, CleanupLog *log) {
  U result = provider_throw(x, cookie, e, log);
  e->value ^= cookie + 13;
  ++e->completed;
  return result + 17;
}
extern "C" NOINLINE U unwind_callback(ThrowCB cb, int x, U cookie, Effects *e,
                                      CleanupLog *log) {
  U result = cb(x, cookie, e, log);
  e->value ^= cookie + 19;
  ++e->completed;
  return result + 23;
}
''' + LOCAL_GUARD + r'''
extern "C" NOINLINE U unwind_cleanup_import(int x, U cookie, Effects *e,
                                            CleanupLog *log) {
  LocalGuard guard{e, log, 41};
  U result = provider_throw(x, cookie, e, log);
  e->value ^= cookie + 29;
  ++e->completed;
  return result + 31;
}
extern "C" NOINLINE U unwind_cleanup_callback(ThrowCB cb, int x, U cookie,
                                              Effects *e, CleanupLog *log) {
  LocalGuard guard{e, log, 42};
  U result = cb(x, cookie, e, log);
  e->value ^= cookie + 37;
  ++e->completed;
  return result + 41;
}
extern "C" NOINLINE U unwind_catch_import(int x, U cookie, Effects *e,
                                          CleanupLog *log) {
  try {
    LocalGuard guard{e, log, 41};
    U result = provider_throw(x, cookie, e, log);
    e->value ^= cookie + 43;
    ++e->completed;
    return result + 47;
  } catch (const Payload &p) {
    ++e->local_catches;
    U word = U(uint32_t(x));
    if (p.code != (word ^ 0x13579bdf2468ace0ULL) || p.cookie != cookie ||
        p.input != x || p.origin != 1 ||
        p.witness != ((cookie * 17) ^ word ^ 0x1020304050607080ULL))
      ++e->payload_failures;
    return (p.code + p.cookie * 7) ^ p.witness;
  }
}
extern "C" NOINLINE U unwind_catch_callback(ThrowCB cb, int x, U cookie,
                                            Effects *e, CleanupLog *log) {
  try {
    LocalGuard guard{e, log, 42};
    U result = cb(x, cookie, e, log);
    e->value ^= cookie + 53;
    ++e->completed;
    return result + 59;
  } catch (const Payload &p) {
    ++e->local_catches;
    U word = U(uint32_t(x));
    if (p.code != (word ^ 0x3579bdf12468ace0ULL) || p.cookie != cookie ||
        p.input != x || p.origin != 2 ||
        p.witness != ((cookie * 23) ^ word ^ 0x8070605040302010ULL))
      ++e->payload_failures;
    return (p.code + p.cookie * 7) ^ p.witness;
  }
}
'''

# The caller and target must share a compilation unit: this is an actual
# incoming invoke, not an ordinary external call from the native consumer.
INCOMING_SOURCE = r'''
#include "unwind.h"
extern "C" NOINLINE U unwind_incoming(int x, U cookie, Effects *e, CleanupLog *log) {
  U result = provider_throw(x, cookie, e, log);
  e->value ^= cookie + 61;
  ++e->completed;
  return result + 67;
}
''' + LOCAL_GUARD + r'''
extern "C" NOINLINE U unwind_incoming_caller(int x, U cookie, Effects *e,
                                             CleanupLog *log) {
  try {
    LocalGuard guard{e, log, 43};
    U result = unwind_incoming(x, cookie, e, log);
    e->value ^= cookie + 71;
    return result + 73;
  } catch (const Payload &p) {
    ++e->local_catches;
    U word = U(uint32_t(x));
    if (p.code != (word ^ 0x13579bdf2468ace0ULL) || p.cookie != cookie ||
        p.input != x || p.origin != 1 ||
        p.witness != ((cookie * 17) ^ word ^ 0x1020304050607080ULL))
      ++e->payload_failures;
    return (p.code + p.cookie * 7) ^ p.witness;
  }
}
'''

CONSUMER_SOURCE = r'''
#include <stdio.h>
#include <stdlib.h>
#include "unwind.h"
static void check(bool ok, const char *what) {
  if (!ok) { fprintf(stderr, "C++ ELF unwind failure: %s\n", what); exit(1); }
}
#ifndef INCOMING
struct CallbackGuard {
  CleanupLog *log;
  NOINLINE ~CallbackGuard() noexcept { append_cleanup(log, 32); }
};
static NOINLINE U throw_callback(int x, U cookie, Effects *e, CleanupLog *log) {
  CallbackGuard guard{log};
  U word = U(uint32_t(x));
  U effect = word * 3 + cookie * 5;
  e->value += effect;
  e->store = effect ^ cookie;
  ++e->calls;
  if (x < 0)
    throw Payload{word ^ 0x3579bdf12468ace0ULL, cookie, x, 2,
                  (cookie * 23) ^ word ^ 0x8070605040302010ULL};
  return word * 7 + cookie * 2;
}
#endif
struct HostGuard {
  CleanupLog *log;
  unsigned id;
  NOINLINE ~HostGuard() noexcept { append_cleanup(log, id); }
};
static NOINLINE U host_inner(unsigned mode, int x, U cookie, Effects *e,
                              CleanupLog *log) {
  HostGuard guard{log, 21};
#ifdef INCOMING
  (void)mode;
  return unwind_incoming_caller(x, cookie, e, log);
#else
  switch (mode) {
    case 0: return unwind_import(x, cookie, e, log);
    case 1: return unwind_callback(throw_callback, x, cookie, e, log);
    case 2: return unwind_cleanup_import(x, cookie, e, log);
    case 3: return unwind_cleanup_callback(throw_callback, x, cookie, e, log);
    case 4: return unwind_catch_import(x, cookie, e, log);
    default: return unwind_catch_callback(throw_callback, x, cookie, e, log);
  }
#endif
}
static NOINLINE U host_outer(unsigned mode, int x, U cookie, Effects *e,
                              CleanupLog *log) {
  HostGuard guard{log, 11};
  return host_inner(mode, x, cookie, e, log);
}
static void cleanup_order(const CleanupLog &log, unsigned native, unsigned local) {
  check(log.overflow == 0, "cleanup log overflow");
  check(log.count == (local ? 4u : 3u), "exact-once cleanup count");
  unsigned index = 0;
  check(log.ids[index++] == native, "native thrower cleanup order");
  if (local) check(log.ids[index++] == local, "protected local cleanup order");
  check(log.ids[index++] == 21, "inner host cleanup order");
  check(log.ids[index++] == 11, "outer host cleanup order");
}
int main(int argc, char **argv) {
  check(argc == 2, "runtime seed argument");
  char *end = nullptr;
  U seed = strtoull(argv[1], &end, 0);
  check(end && *end == 0, "numeric runtime seed");
  const int inputs[] = {17, -37, 23, -1009, 0, -1, 67, -37};
  unsigned checks = 0, escapes = 0, local_catches = 0, cleanup_events = 0;
  U digest = seed;
#ifdef INCOMING
  const unsigned modes = 1;
#else
  const unsigned modes = 6;
  const U post_xor[] = {13, 19, 29, 37, 43, 53};
  const U post_add[] = {17, 23, 31, 41, 47, 59};
#endif
  for (unsigned round = 0; round < 3; ++round) {
    for (unsigned index = 0; index < sizeof(inputs) / sizeof(inputs[0]); ++index) {
      for (unsigned mode = 0; mode < modes; ++mode) {
        int x = inputs[index];
        U word = U(uint32_t(x));
        U cookie = seed + round * 0x11223344556677ULL + index * 97 + mode * 101;
        U start = seed ^ (cookie * 11);
        Effects e{start, start ^ cookie, 0, 0, 0, 0, 0};
        CleanupLog log{};
#ifdef INCOMING
        bool callback = false, local_catch = true;
        unsigned local = 43;
#else
        bool callback = (mode & 1) != 0, local_catch = mode >= 4;
        unsigned local = mode >= 2 ? (callback ? 42 : 41) : 0;
#endif
        U expected_code = word ^ (callback ? 0x3579bdf12468ace0ULL : 0x13579bdf2468ace0ULL);
        U expected_witness = (cookie * (callback ? 23 : 17)) ^ word ^
                             (callback ? 0x8070605040302010ULL : 0x1020304050607080ULL);
        U effect = callback ? word * 3 + cookie * 5 : word + cookie * 3;
        bool expected_escape = x < 0 && !local_catch;
        bool caught = false;
        U sentinel = cookie ^ 0xfedcba9876543210ULL;
        U result = sentinel;
        try {
          result = host_outer(mode, x, cookie, &e, &log);
        } catch (const Payload &p) {
          caught = true;
          check(expected_escape, "unexpected escaping typed exception");
          check(p.code == expected_code && p.cookie == cookie && p.input == x &&
                p.origin == (callback ? 2u : 1u) && p.witness == expected_witness,
                "exact custom exception type and payload");
          cleanup_order(log, callback ? 32 : 31, local);
          ++escapes;
        } catch (...) {
          check(false, "exception type changed");
        }
        check(caught == expected_escape, "throw/nonthrow transition");
        if (!caught) cleanup_order(log, callback ? 32 : 31, local);
        U expected_value = start + effect;
        if (x >= 0) {
          U expected_return = callback ? word * 7 + cookie * 2 : word * 5 + cookie;
#ifdef INCOMING
          expected_value ^= cookie + 61;
          expected_value ^= cookie + 71;
          expected_return += 67 + 73;
#else
          expected_value ^= cookie + post_xor[mode];
          expected_return += post_add[mode];
#endif
          check(result == expected_return, "exact nonthrow return");
        } else if (local_catch) {
          check(result == ((expected_code + cookie * 7) ^ expected_witness),
                "local catch payload and return");
        } else {
          check(result == sentinel, "throw did not complete host assignment");
        }
        check(e.value == expected_value && e.store == (effect ^ cookie) && e.calls == 1,
              "exact memory effects and native call count");
        check(e.completed == unsigned(x >= 0), "postcall effects skipped on throw");
        check(e.local_cleanups == unsigned(local != 0), "protected cleanup exact-once");
        check(e.local_catches == unsigned(x < 0 && local_catch) && e.payload_failures == 0,
              "local handler type and exact payload");
        ++checks;
        local_catches += e.local_catches;
        cleanup_events += log.count;
        digest = ((digest << 9) | (digest >> 55)) ^ result ^ e.value ^ e.store ^ log.count;
      }
    }
  }
  printf("{\"ok\":true,\"checks\":%u,\"escapes\":%u,\"local_catches\":%u,"
         "\"cleanup_events\":%u,\"digest\":%llu}\n",
         checks, escapes, local_catches, cleanup_events, (unsigned long long)digest);
}
'''


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def policy(path, owners, level):
    # Exact target rules deliberately retain the frontend's local-EH downgrade.
    # A generic function override would select a different policy boundary.
    lines = ["seed: 8675309", "default_level: none", "targets:"]
    for owner in owners:
        lines += [f"  - match: {owner}", f"    level: {level}"]
    lines += ["vm:", "  max_mba_depth: 0", "security:", "  fail_on_public_obf_symbol: true"]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def selected(data, owner):
    matches = [event for event in data["requested_policy"]
               if event["owner"] == owner and event["phase"] == "selected"]
    require(len(matches) == 1, f"missing/ambiguous selected policy for {owner}")
    event = matches[0]
    return event["policy"]


def events(data, stage, owner, mechanism):
    return [event for event in data[stage]
            if event["owner"] == owner and event["mechanism"] == mechanism]


def vm_emitted(data, owner):
    return any(event["status"] == "emitted" for event in events(data, "emission", owner, "vm"))


def check_emission(data, owner, level):
    choice = selected(data, owner)
    require(choice["allow_vm"] and choice["level"] == level, f"lost requested VM policy: {owner}")
    admitted = events(data, "admission", owner, "vm")
    emitted = events(data, "emission", owner, "vm")
    require(any(event["status"] == "admitted" and event["scope"] == "whole_function"
                for event in admitted),
            f"supported owner not admitted: {owner}")
    require(any(event["status"] == "emitted" and event["scope"] == "whole_function"
                for event in emitted),
            f"supported owner did not emit whole-function VM: {owner}")


def check_security(data):
    require(any(event["mechanism"] == "security_gates" and event["status"] == "validated"
                for event in data["finalization"]), "compiler security gates were not validated")


def check_positive(data, level):
    for owner in VM_OWNERS:
        check_emission(data, owner, level)
    for owner in EXCLUDED_OWNERS:
        choice = selected(data, owner)
        require(not choice["allow_vm"],
                f"local-EH rule was not excluded from VM: {owner}")
        require(not events(data, "admission", owner, "vm") and not vm_emitted(data, owner),
                f"local-EH exclusion reached VM: {owner}")
    check_security(data)


def check_incoming(data, strict):
    choice = selected(data, INCOMING_OWNER)
    require(choice["allow_vm"] and choice["level"] == ("strong_vm" if strict else "vm"),
            "incoming target lost its requested VM policy")
    incoming = events(data, "admission", INCOMING_OWNER, "vm_incoming_site")
    require(any(event["status"] == ("rejected" if strict else "preserved") for event in incoming),
            "incoming invoke did not reach the semantic preservation/rejection boundary")
    require(vm_emitted(data, INCOMING_OWNER) == (not strict), "wrong incoming VM emission state")
    if not strict:
        check_emission(data, INCOMING_OWNER, "vm")
        check_security(data)


class Harness:
    def __init__(self, args, work):
        self.args = args
        self.work = work
        self.raw = [args.clang, "--driver-mode=g++"]
        self.commands = work / "commands.jsonl"
        self.result_path = work / "result.json"
        self.results = {
            "work": str(work), "commands": str(self.commands), "status": "running",
            "sources": {name: str(work / name) for name in
                        ("unwind.h", "provider.cpp", "positive.cpp", "incoming.cpp", "consumer.cpp")},
            "runtime_seed": str(RUNTIME_SEED), "cases": [],
            "vm_execution": "requires_independent_trace",
        }
        self.save()

    def save(self):
        self.result_path.write_text(json.dumps(self.results, indent=2) + "\n", encoding="utf-8")

    def run(self, command, *, report=None, succeeds=True):
        env = {key: value for key, value in os.environ.items() if not key.upper().startswith("OBF_")}
        if report is not None:
            env["OBF_COVERAGE_REPORT"] = str(report)
        command = [str(value) for value in command]
        result = run_process(command, cwd=self.work, env=env, timeout=300)
        with self.commands.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps({"command": command, "cwd": str(self.work),
                                     "exit": result.returncode, "stdout": result.stdout,
                                     "stderr": result.stderr,
                                     "report": str(report) if report else None}) + "\n")
        if succeeds:
            require(result.returncode == 0,
                    f"unexpected exit {result.returncode}: {command!r}\n{result.stdout}\n{result.stderr}")
        else:
            # A signal, timeout or launch failure is not a semantic rejection.
            require(result.returncode > 0,
                    f"expected compiler rejection, got {result.returncode}: {command!r}\n"
                    f"{result.stdout}\n{result.stderr}")
        return result

    def report(self, path):
        require(path.is_file(), f"missing compiler report: {path}")
        data = coverage_contract(json.loads(path.read_text(encoding="utf-8")))
        require(data["capture"] == "enabled", f"compiler ledger not captured: {path}")
        return data

    def raw_inputs(self, optimization):
        folder = self.work / f"raw-o{optimization}"
        folder.mkdir()
        provider_obj = folder / "provider.o"
        provider = folder / "libunwind-provider.so"
        flags = [*CXX_FLAGS, f"-O{optimization}"]
        self.run([*self.raw, *flags, "-fPIC", "-c", self.work / "provider.cpp", "-o", provider_obj])
        self.run([*self.raw, *CXX_FLAGS, "-shared", "-fuse-ld=lld", provider_obj,
                  "-Wl,-soname,libunwind-provider.so", "-o", provider])
        consumers = {}
        for kind in ("positive", "incoming"):
            obj = folder / f"consumer-{kind}.o"
            define = ["-DINCOMING"] if kind == "incoming" else []
            self.run([*self.raw, *flags, *define, "-c", self.work / "consumer.cpp", "-o", obj])
            consumers[kind] = obj
        return {"folder": folder, "provider": provider, "provider_object": provider_obj,
                "consumers": consumers}

    def build_case(self, inputs, kind, optimization, *, level=None, reports=False):
        name = f"{kind}-{level or 'raw'}-o{optimization}-reports-{'on' if reports else 'off'}"
        folder = self.work / name
        folder.mkdir()
        source = self.work / f"{kind}.cpp"
        obj = folder / "protected.o"
        lib = folder / "libunwind-protected.so"
        image = folder / "consumer"
        config = folder / "policy.yaml" if level else None
        report = folder / "coverage.json" if reports else None
        strict = kind == "incoming" and level == "strong_vm"
        record = {
            "name": name, "kind": kind, "optimization": optimization,
            "level": level or "raw", "reports": reports,
            "status": "running", "folder": str(folder), "source": str(source),
            "provider": str(inputs["provider"]), "provider_object": str(inputs["provider_object"]),
            "object": str(obj), "library": str(lib), "consumer": str(image),
            "consumer_object": str(inputs["consumers"][kind]),
            "config": str(config) if config else None, "report": str(report) if report else None,
            "runtime_command": [str(image), str(RUNTIME_SEED)] if not strict else None,
        }
        self.results["cases"].append(record)
        self.save()
        if config:
            owners = (*VM_OWNERS, *EXCLUDED_OWNERS) if kind == "positive" else (INCOMING_OWNER,)
            policy(config, owners, level)
        driver = [self.args.wrapper, f"--obf-config={config}"] if level else self.raw
        compiled = self.run([*driver, *CXX_FLAGS, f"-O{optimization}", "-fPIC",
                             "-c", source, "-o", obj], report=report, succeeds=not strict)
        if strict:
            require(not obj.exists(), "forbidden incoming invoke produced an object")
            data = self.report(report) if report else None
            if data is not None:
                check_incoming(data, True)
            record.update(status="rejected", compile_exit=compiled.returncode,
                          rejection="incoming_invoke", compiler_evidence="semantic_report" if data else "not_available",
                          library=None, consumer=None)
            self.save()
            return record
        if report:
            data = self.report(report)
            if kind == "positive":
                check_positive(data, level)
            else:
                check_incoming(data, False)
            record["compiler_evidence"] = "compiler_report"
        else:
            record["compiler_evidence"] = "not_requested"
        map_path = folder / "protected.map"
        # Keep normal ELF/C++ startup, default C++ exception runtime, and the
        # configured wrapper runtime/checksum binder. There is no -nostdlib,
        # custom entry point, or raw-runtime replacement for managed modules.
        self.run([*driver, *CXX_FLAGS, "-shared", "-fuse-ld=lld", obj, inputs["provider"],
                  "-Wl,-soname,libunwind-protected.so",
                  f"-Wl,-rpath,$ORIGIN/../raw-o{optimization}",
                  f"-Wl,-Map,{map_path},--cref", "-o", lib])
        self.run([*self.raw, *CXX_FLAGS, "-fuse-ld=lld", inputs["consumers"][kind], lib,
                  inputs["provider"], "-Wl,-rpath,$ORIGIN",
                  f"-Wl,-rpath,$ORIGIN/../raw-o{optimization}", "-o", image])
        native = self.run(record["runtime_command"])
        outcome = json.loads(native.stdout)
        expected = {"ok": True, "checks": 144, "escapes": 48, "local_catches": 24,
                    "cleanup_events": 528} if kind == "positive" else {
                        "ok": True, "checks": 24, "escapes": 0, "local_catches": 12,
                        "cleanup_events": 96}
        require(all(outcome.get(key) == value for key, value in expected.items()),
                f"missing native semantic checks: {name}: {outcome}")
        require(type(outcome.get("digest")) is int, f"missing native outcome digest: {name}")
        record.update(status="passed", native=outcome, map=str(map_path))
        self.save()
        return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wrapper", required=True, help="configured obf-clang++ launcher")
    parser.add_argument("--clang", required=True, help="canonical Clang (g++ mode is explicit)")
    parser.add_argument("--work", required=True, help="parent of the retained isolated evidence directory")
    args = parser.parse_args()
    require(sys.platform.startswith("linux") and platform.machine().lower() in ("x86_64", "amd64"),
            "this regression requires native Linux x86-64")
    parent = Path(args.work).resolve()
    parent.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix="cpp-elf-unwind-", dir=parent))
    print(f"CPP_ELF_UNWIND_WORK {work}", flush=True)
    harness = Harness(args, work)
    try:
        for name, content in (("unwind.h", HEADER), ("provider.cpp", PROVIDER_SOURCE),
                              ("positive.cpp", POSITIVE_SOURCE), ("incoming.cpp", INCOMING_SOURCE),
                              ("consumer.cpp", CONSUMER_SOURCE)):
            (work / name).write_text(content, encoding="utf-8")
        for optimization in (0, 2):
            inputs = harness.raw_inputs(optimization)
            baselines = {kind: harness.build_case(inputs, kind, optimization)["native"]
                         for kind in ("positive", "incoming")}
            for reports in (True, False):
                for level in ("vm", "strong_vm"):
                    positive = harness.build_case(inputs, "positive", optimization, level=level, reports=reports)
                    require(positive["native"] == baselines["positive"],
                            "protected throw/nonthrow outcomes differ from the raw baseline")
                    incoming = harness.build_case(inputs, "incoming", optimization, level=level, reports=reports)
                    if level == "vm":
                        require(incoming["native"] == baselines["incoming"],
                                "preserved incoming invoke outcomes differ from the raw baseline")
                    print(f"CPP_ELF_UNWIND_PASS O{optimization} {level} reports={'on' if reports else 'off'} "
                          f"native=checked local_eh=excluded incoming={'rejected' if level == 'strong_vm' else 'preserved'}",
                          flush=True)
        harness.results["status"] = "passed"
        harness.save()
    except Exception as error:
        harness.results.update(status="failed", error=str(error))
        harness.save()
        raise
    print(f"CPP_ELF_UNWIND_COMPLETE result={harness.result_path} "
          "vm_execution=requires_independent_trace", flush=True)


if __name__ == "__main__":
    main()
