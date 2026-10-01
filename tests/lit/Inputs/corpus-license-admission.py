#!/usr/bin/env python3

import argparse
import os
from pathlib import Path
import re
import subprocess


def admission_cases():
    yield ("delta-7",), True
    yield (), False
    yield ("",), False
    yield ("fdlta-7",), False
    yield ("delta-4",), False
    yield ("xxxxxxx",), False
    for length in range(1, 7):
        yield ("delta-7"[:length],), False
    yield ("delta-70",), False
    yield ("delta-7" + "x" * 256,), False
    for token in (
        "Delta-7",
        "dflta-7",
        "demta-7",
        "delua-7",
        "deltb-7",
        "delta.7",
        "delta-6",
        "\u00e9elta-7",
        "d\u00e9lta7",
    ):
        yield (token,), False


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("binaries", nargs="+", type=Path)
    args = parser.parse_args()
    environment = os.environ.copy()
    environment.pop("OBF_BENCH_ITERS", None)

    for argv, accepted in admission_cases():
        expected_status = 0 if accepted else 1
        expected_message = "ACCESS GRANTED" if accepted else "ACCESS DENIED"
        reference = None
        for binary in args.binaries:
            result = subprocess.run(
                [str(binary), *argv],
                check=False,
                capture_output=True,
                text=True,
                env=environment,
                timeout=30,
            )
            observed = (result.returncode, result.stdout, result.stderr)
            if (
                result.returncode != expected_status
                or re.fullmatch(rf"{expected_message}\n[0-9]+\n", result.stdout) is None
                or result.stderr
            ):
                raise AssertionError(
                    f"{binary.name} argv={argv!r}: expected status {expected_status} "
                    f"and {expected_message!r}, got {observed!r}"
                )
            if reference is not None and observed != reference:
                raise AssertionError(
                    f"{binary.name} argv={argv!r}: admission/score output {observed!r} "
                    f"differs from {reference!r}"
                )
            reference = observed


if __name__ == "__main__":
    main()
