#!/usr/bin/env python3
"""
whippet.py — drop-and-run launcher for Whippet.

The implementation lives in the `whippet/` package next to this file, so you can
still just copy the folder onto a box and run `python3 whippet.py …` with no
install step and no third-party dependencies (the optional browser GUI aside).

    python3 whippet.py bloodhound.zip
    python3 whippet.py /sharphound/output/ --from "JSMITH@CORP.LOCAL" --to "DOMAIN ADMINS@CORP.LOCAL"
    python3 whippet.py bloodhound.zip --serve        # optional browser visualizer

See `python3 whippet.py --help` for the full option list.
"""
import os
import sys

# Ensure the package next to this script is importable even when invoked by path.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from whippet.cli import main

if __name__ == "__main__":
    main()
