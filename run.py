#!/usr/bin/env python3
"""Entry point: python run.py {run,synth,score} ..."""
import sys

from strayhost.cli import main

if __name__ == "__main__":
    sys.exit(main())
