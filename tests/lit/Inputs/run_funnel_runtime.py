"""Run the exact funnel oracle module with its real runtime dependencies.

Usage: run_funnel_runtime.py CLANG LLI [lli options] MODULE [program arguments]
Pass the expanded lit lli command, including its extra runtime objects.
Non-Windows hosts execute that command unchanged. Windows x86-64 hosts compile
its module with raw Clang, the real compiler-rt builtins archive, and the normal
Microsoft CRT, then run the resulting executable. No VM lowering is repeated.
"""

import argparse
import os
from pathlib import Path
import subprocess
import tempfile


parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("clang")
parser.add_argument("lli_command", nargs=argparse.REMAINDER)
args = parser.parse_args()
if not args.lli_command:
    parser.error("the expanded lli command and module are required")

command = args.lli_command
if os.name != "nt":
    os.execvp(command[0], command)

# Only lli options before the module are runner options. Everything after the
# module belongs to the program, including arguments that resemble lli options.
extra_objects = []
index = 1
while index < len(command):
    argument = command[index]
    if argument in ("--extra-object", "-extra-object"):
        index += 1
        if (
            index == len(command)
            or not command[index]
            or command[index].startswith("-")
        ):
            parser.error(f"{argument} requires an object path")
        extra_objects.append(command[index])
    elif argument.startswith(("--extra-object=", "-extra-object=")):
        object_path = argument.split("=", 1)[1]
        if not object_path:
            parser.error("extra-object requires an object path")
        extra_objects.append(object_path)
    elif argument == "--":
        index += 1
        break
    elif argument.startswith("-"):
        parser.error(f"unsupported Windows lli option: {argument}")
    else:
        break
    index += 1

if index == len(command):
    parser.error("the LLVM module is required")
module = command[index]
program_arguments = command[index + 1 :]

resource = subprocess.run(
    [args.clang, "-print-resource-dir"], stdout=subprocess.PIPE, text=True
)
if resource.returncode != 0:
    raise SystemExit(resource.returncode)
resource_dir = resource.stdout.strip()
if not resource_dir:
    raise SystemExit("configured Clang returned an empty resource directory")
archive = Path(resource_dir) / "lib" / "windows" / "clang_rt.builtins-x86_64.lib"
if not archive.is_file():
    raise SystemExit(f"required Windows compiler-rt builtins archive not found: {archive}")

# Use the configured compiler directly, not the plugin-enabled lit wrapper.
# Default libraries supply the CRT, including the real security-cookie support.
with tempfile.TemporaryDirectory(prefix="funnel-runtime-") as directory:
    executable = Path(directory) / "funnel.exe"
    result = subprocess.call(
        [
            args.clang,
            "-O0",
            "-fuse-ld=lld",
            "-o",
            str(executable),
            "--",
            module,
            *extra_objects,
            str(archive),
        ]
    )
    if result == 0:
        result = subprocess.call([str(executable), *program_arguments])
raise SystemExit(result)
