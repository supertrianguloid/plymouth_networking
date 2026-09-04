#!/usr/bin/env python3
"""Run every test suite. Exits non-zero if anything fails."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import test_e2e
import test_units

SUITES = [
    ("unit tests (DER structures, openssl wrapper)", test_units.run),
    ("end-to-end tests (mock SCEP CA + CLI)", test_e2e.run),
]


def main():
    failures = []
    for title, runner in SUITES:
        print("\n== %s ==" % title)
        failures.extend("%s: %s" % (title, f) for f in runner())
    print()
    if failures:
        print("FAILED (%d):" % len(failures))
        for failure in failures:
            print("  - %s" % failure)
        return 1
    print("all suites passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
