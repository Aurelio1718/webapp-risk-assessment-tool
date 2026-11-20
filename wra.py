#!/usr/bin/env python3
"""Entry point: ./wra.py <command> [options]  (equivalent to: python3 -m wra)."""
import sys

from wra.cli import main

if __name__ == "__main__":
    sys.exit(main())
