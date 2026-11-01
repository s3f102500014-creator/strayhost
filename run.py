#!/usr/bin/env python3
"""Entry point: python run.py {run,synth,score} ..."""
import sys

if sys.version_info < (3, 10):
    sys.exit(f"StrayHost needs Python 3.10 or later; this is Python {sys.version.split()[0]}. "
             "See Step 1 of the README.")

from strayhost.cli import main

if __name__ == "__main__":
    sys.exit(main())
