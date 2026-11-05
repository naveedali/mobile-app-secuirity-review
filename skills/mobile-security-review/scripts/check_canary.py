#!/usr/bin/env python3
"""Check local test captures for the exact bytes of a synthetic canary."""

import argparse
import json
from pathlib import Path
import re
import sys

CHUNK_SIZE = 64 * 1024
CANARY = re.compile(rb"MSR_CANARY_[A-Za-z0-9_-]{16,128}")


def read_canary(path):
    if not path.is_file():
        raise ValueError("Canary input must be a regular file.")
    with path.open("rb") as source:
        marker = source.read(256).removesuffix(b"\n").removesuffix(b"\r")
    if not CANARY.fullmatch(marker):
        raise ValueError("Expected one MSR_CANARY_ marker with a 16–128 character suffix.")
    return marker


def scan_capture(source, marker):
    """Return the first match offset and whether the capture was empty."""
    consumed = 0
    tail = b""
    while chunk := source.read(CHUNK_SIZE):
        window = tail + chunk
        offset = window.find(marker)
        if offset >= 0:
            return consumed - len(tail) + offset, False
        consumed += len(chunk)
        tail = window[-(len(marker) - 1):]
    return None, consumed == 0


def inspect_capture(path, kind, marker_path, marker):
    result = {
        "kind": kind,
        "path": str(path).replace(marker.decode("ascii"), "[CANARY]"),
    }
    try:
        if not path.is_file():
            raise ValueError("Expected a readable regular capture file.")
        if path.samefile(marker_path):
            raise ValueError("The canary file cannot also be a capture.")
        with path.open("rb") as source:
            offset, empty = scan_capture(source, marker)
        if kind == "logcat" and empty:
            raise ValueError("Logcat capture is empty. Verify collection and retry.")
    except OSError:
        return {**result, "status": "incomplete", "error": "Capture could not be read."}
    except ValueError as error:
        return {**result, "status": "incomplete", "error": str(error)}

    if offset is None:
        return {**result, "status": "no-match"}
    return {**result, "status": "match", "first_byte_offset": offset}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--canary-file", required=True, type=Path)
    parser.add_argument("--logcat", action="append", default=[], type=Path)
    parser.add_argument("--storage", action="append", default=[], type=Path)
    args = parser.parse_args(argv)
    if not (args.logcat or args.storage):
        parser.error("Provide at least one --logcat or --storage capture.")

    try:
        marker = read_canary(args.canary_file)
    except OSError:
        parser.error("Canary file could not be read.")
    except ValueError as error:
        parser.error(str(error))

    inputs = []
    for kind, paths in (("logcat", args.logcat), ("storage", args.storage)):
        for path in dict.fromkeys(paths):
            inputs.append(inspect_capture(path, kind, args.canary_file, marker))

    incomplete = any(item["status"] == "incomplete" for item in inputs)
    matched = any(item["status"] == "match" for item in inputs)
    report = {
        "schema_version": "1.0",
        "completion": "incomplete" if incomplete else "completed-limited-checks",
        "inputs": inputs,
        "limitations": [
            "Exact ASCII byte matching in supplied captures only.",
            "Capture provenance, flow execution, and collection completeness require independent verification.",
            "A match establishes marker presence. Impact depends on the destination and test context.",
        ],
    }
    print(json.dumps(report, indent=2))
    if incomplete:
        return 2
    return 1 if matched else 0


if __name__ == "__main__":
    sys.exit(main())
