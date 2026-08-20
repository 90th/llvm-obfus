#include "obf/frontend/config.h"

#include "llvm/Config/llvm-config.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Error.h"
#include "llvm/Support/InitLLVM.h"
#include "llvm/Support/raw_ostream.h"

#include <optional>

int main(int argc, char** argv) {
  llvm::InitLLVM init_llvm(argc, argv);

  llvm::cl::OptionCategory driver_category("llvm-obfus options");
  llvm::cl::opt<std::string> config_path("config",
                                         llvm::cl::desc("Path to llvm-obfus milestone-zero config"),
                                         llvm::cl::init(""),
                                         llvm::cl::cat(driver_category));
  llvm::cl::opt<std::string> frontend(
      "frontend",
      llvm::cl::desc("Frontend invoking the driver (generic, rust, zig, or tinygo)"),
      llvm::cl::init(""),
      llvm::cl::cat(driver_category));
  llvm::cl::opt<std::string> required_frontend(
      "require-frontend",
      llvm::cl::desc("Require the loaded config to select this frontend"),
      llvm::cl::init(""),
      llvm::cl::cat(driver_category));
  llvm::cl::opt<bool> quiet("quiet",
                            llvm::cl::desc("Suppress successful driver output"),
                            llvm::cl::init(false),
                            llvm::cl::cat(driver_category));
  llvm::cl::opt<bool> query_self_checksum(
      "query-self-checksum",
      llvm::cl::desc("Print whether the resolved config enables self_checksum"),
      llvm::cl::init(false),
      llvm::cl::cat(driver_category));
  llvm::cl::HideUnrelatedOptions(driver_category);
  llvm::cl::ParseCommandLineOptions(argc, argv, "llvm-obfus driver scaffold\n");

  if (!frontend.empty() && frontend != "generic" && frontend != "rust" && frontend != "zig" &&
      frontend != "tinygo") {
    llvm::errs() << "unsupported frontend: " << frontend << '\n';
    return 1;
  }
  if (!required_frontend.empty() && !frontend.empty() && required_frontend != frontend) {
    llvm::errs() << "--require-frontend and --frontend must name the same frontend\n";
    return 1;
  }
  if (!required_frontend.empty() && config_path.empty()) {
    llvm::errs() << "--require-frontend requires --config\n";
    return 1;
  }
  if (!required_frontend.empty() && required_frontend != "generic" && required_frontend != "rust" &&
      required_frontend != "zig" && required_frontend != "tinygo") {
    llvm::errs() << "unsupported required frontend: " << required_frontend << '\n';
    return 1;
  }

  if (!quiet && !query_self_checksum) {
    llvm::outs() << "llvm-obfus driver scaffold\n";
    llvm::outs() << "LLVM version target: " << LLVM_VERSION_STRING << "\n";
  }

  std::optional<obf::obfuscation_config> loaded_config;
  if (!config_path.empty()) {
    llvm::Expected<obf::obfuscation_config> config = obf::load_config_from_file(config_path);
    if (!config) {
      llvm::errs() << llvm::toString(config.takeError()) << '\n';
      return 1;
    }
    const llvm::StringRef expected_frontend =
        !required_frontend.empty() ? llvm::StringRef(required_frontend) : llvm::StringRef(frontend);
    if (!expected_frontend.empty() && obf::to_string(config->frontend) != expected_frontend) {
      llvm::errs() << "config frontend is " << obf::to_string(config->frontend) << "; expected "
                   << expected_frontend << '\n';
      return 1;
    }
    loaded_config.emplace(*config);

    if (!quiet && !query_self_checksum) {
      llvm::outs() << "Loaded config from " << config_path << "\n";
      llvm::outs() << obf::summarize_config(*loaded_config);
    }
  } else if (!quiet && !query_self_checksum) {
    llvm::outs() << "No config provided. Using default milestone-zero policy "
                    "inputs.\n";
  }

  if (query_self_checksum) {
    const bool enabled =
        loaded_config.has_value() && loaded_config->self_checksum.enabled;
    llvm::outs() << (enabled ? "enabled\n" : "disabled\n");
    return 0;
  }

  if (!quiet) {
    llvm::outs() << "Initial workflow: build the pass plugin and run policy-aware "
                    "feature reporting or block splitting through opt.\n";
  }
  return 0;
}
