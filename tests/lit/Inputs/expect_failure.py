import subprocess
import sys


completed = subprocess.run(sys.argv[1:])
if completed.returncode == 0:
    print("expected command failure", file=sys.stderr)
    raise SystemExit(1)
