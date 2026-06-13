#include "obf/support/mba_config_builder.h"

#include "obf/frontend/config.h"
#include "obf/transforms/mba.h"

namespace obf::support {

mba::builder_context make_mba_context(llvm::Function& function,
                                       llvm::StringRef prefix,
                                       std::uint64_t seed_base,
                                       const mba_config& cfg) {
  mba::builder_context ctx = mba::get_or_create_builder_context(function, prefix, seed_base);
  ctx.depth = cfg.depth;
  configure_context_overrides(ctx, cfg);
  return ctx;
}

}  // namespace obf::support
