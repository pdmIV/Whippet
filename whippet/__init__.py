"""
Whippet — a lean, fast in-memory Active Directory graph pathfinder.

The lightweight sibling to BloodHound: ingests SharpHound JSON and answers the
reachability / shortest-path / privilege-chain questions straight from RAM.

Public API:
    ADGraph           — the in-memory graph (storage + traversal primitives)
    SharpHoundLoader  — SharpHound v1/v2 JSON → ADGraph
    QueryEngine       — structured queries shared by the CLI and the web GUI
    TextReporter      — the console report
"""
from __future__ import annotations

from .graph import ADGraph, IGRAPH
from .loader import SharpHoundLoader
from .queries import QueryEngine
from .report import TextReporter

__version__ = "0.2.0"

__all__ = [
    "ADGraph",
    "IGRAPH",
    "SharpHoundLoader",
    "QueryEngine",
    "TextReporter",
    "__version__",
]
