#!/usr/bin/env python3

from __future__ import annotations

import argparse
import importlib.util
import sys
from pathlib import Path


def load_analyzer(path: Path):
    specification = importlib.util.spec_from_file_location("binary_recovery", path)
    if specification is None or specification.loader is None:
        raise SystemExit("unable to load analyzer")
    module = importlib.util.module_from_spec(specification)
    sys.modules[specification.name] = module
    specification.loader.exec_module(module)
    return module


def block(module, index: int, successors: list[int], unknown_successor: bool = False):
    return module.BasicBlock(index, (), successors, unknown_successor, "fallthrough")


def dispatcher(module):
    return module.DispatcherEvidence(
        ("direct", 0), (0, 1), (2, 3), (), False, True, 0
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--analyzer", required=True)
    arguments = parser.parse_args()
    module = load_analyzer(Path(arguments.analyzer))

    shared_tail_blocks = [
        block(module, 0, [2, 3]),
        block(module, 1, [2, 3]),
        block(module, 2, [3]),
        block(module, 3, [4]),
        block(module, 4, [0]),
    ]
    ownership = module.full_handler_ownership(dispatcher(module), shared_tail_blocks)
    if ownership is None or ownership.get(2) != (2,) or ownership.get(3) != (2, 3):
        raise SystemExit("shared handler entry ownership is invalid")
    if ownership.get(4) != (2, 3) or 0 in ownership:
        raise SystemExit("shared handler tail ownership is invalid")

    unknown_tail_blocks = [
        block(module, 0, [2, 3]),
        block(module, 1, [2, 3]),
        block(module, 2, [3]),
        block(module, 3, [4]),
        block(module, 4, [0], unknown_successor=True),
    ]
    if module.full_handler_ownership(dispatcher(module), unknown_tail_blocks) is not None:
        raise SystemExit("unknown handler path must fail closed")

    unknown_outside_reentry_blocks = [
        block(module, 0, [2, 3]),
        block(module, 1, [2, 3]),
        block(module, 2, [4, 5]),
        block(module, 3, [6]),
        block(module, 4, [0]),
        block(module, 5, [], unknown_successor=True),
        block(module, 6, [0]),
    ]
    if (
        module.full_handler_ownership(dispatcher(module), unknown_outside_reentry_blocks)
        is not None
    ):
        raise SystemExit("unknown path outside the reentry graph must fail closed")

    saved_limit = module.MAX_HANDLER_OWNERSHIP_TRAVERSALS
    module.MAX_HANDLER_OWNERSHIP_TRAVERSALS = 2
    try:
        if module.full_handler_ownership(dispatcher(module), shared_tail_blocks) is not None:
            raise SystemExit("limited ownership traversal must fail closed")
    finally:
        module.MAX_HANDLER_OWNERSHIP_TRAVERSALS = saved_limit

    print("shared_tail_ownership=pass")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
