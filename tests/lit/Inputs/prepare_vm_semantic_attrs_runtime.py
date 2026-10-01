"""Prepare the VM attribute fixture with the host's x86-64 stack-probe ABI."""

import argparse
from pathlib import Path


parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("source", type=Path)
parser.add_argument("output", type=Path)
parser.add_argument("target_triple")
args = parser.parse_args()

# The source fixture checks propagation of the Linux inline-probe attribute.
# Windows lowers that value as a literal external symbol, not an inline probe.
# Select its real ABI probe before virtualization, keeping the probe threshold
# and all semantic/protection attributes intact in the generated functions.
probe = "inline-asm"
if "windows" in args.target_triple.split("-"):
    probe = "___chkstk_ms" if args.target_triple.endswith("-gnu") else "__chkstk"

source = args.source.read_text(encoding="utf-8")
runtime_source = "".join(
    line.replace('"probe-stack"="inline-asm"', f'"probe-stack"="{probe}"')
    if line.startswith("attributes #")
    else line
    for line in source.splitlines(keepends=True)
)
args.output.write_text(runtime_source, encoding="utf-8")
