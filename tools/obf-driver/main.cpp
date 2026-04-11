#include "obf/frontend/config.h"

#include "llvm/Config/llvm-config.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Error.h"
#include "llvm/Support/InitLLVM.h"
#include "llvm/Support/raw_ostream.h"

int main(int argc, char **argv) {
  llvm::InitLLVM init_llvm(argc, argv);

  llvm::cl::OptionCategory driver_category("llvm-obfus options");
  llvm::cl::opt<std::string> config_path(
      "config", llvm::cl::desc("Path to llvm-obfus milestone-zero config"),
      llvm::cl::init(""), llvm::cl::cat(driver_category));
  llvm::cl::HideUnrelatedOptions(driver_category);
  llvm::cl::ParseCommandLineOptions(argc, argv,
                                    "llvm-obfus driver scaffold\n");

  llvm::outs() << "llvm-obfus driver scaffold\n";
  llvm::outs() << "LLVM version target: " << LLVM_VERSION_STRING << "\n";

  if (!config_path.empty()) {
    llvm::Expected<obf::obfuscation_config> config =
        obf::load_config_from_file(config_path);
    if (!config) {
      llvm::errs() << llvm::toString(config.takeError()) << '\n';
      return 1;
    }

    llvm::outs() << "Loaded config from " << config_path << "\n";
    llvm::outs() << obf::summarize_config(*config);
  } else {
    llvm::outs() << "No config provided. Using default milestone-zero policy "
                    "inputs.\n";
  }

  llvm::outs() << "Initial workflow: build the pass plugin and run policy-aware "
                  "feature reporting or block splitting through opt.\n";
  return 0;
}
