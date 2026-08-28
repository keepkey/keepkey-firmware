#!/usr/bin/env python3

"""Reject generated firmware token tables that contain no usable rows."""

from __future__ import print_function

import os
import sys


def verify(path):
    if not os.path.isfile(path):
        raise RuntimeError("token definition was not generated: %s" % path)

    with open(path, "r") as source:
        lines = [line.strip() for line in source]

    if not any(line.startswith("X(") for line in lines):
        raise RuntimeError("token definition contains zero rows: %s" % path)


def main(argv):
    if len(argv) < 2:
        print("usage: %s TOKEN_DEF [...]" % argv[0], file=sys.stderr)
        return 2
    try:
        for path in argv[1:]:
            verify(path)
    except (IOError, OSError, RuntimeError) as error:
        print(str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
