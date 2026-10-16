import os
import subprocess
import sys

os.environ["OBF_COVERAGE_REPORT"] = sys.argv[1]
raise SystemExit(subprocess.run(sys.argv[2:]).returncode)
