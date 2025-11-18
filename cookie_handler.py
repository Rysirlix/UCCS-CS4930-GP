#!/usr/bin/env python3
"""
cookie_handler.py

Command-line interface for extracting cookies and web storage using extractor.py.

Examples
--------
Basic usage (headless, 8s wait):

    python cookie_handler.py https://www.amazon.com

Specify wait time and output file:

    python cookie_handler.py https://example.com -w 12 -o example_storage.json

Show the browser window (non-headless):

    python cookie_handler.py https://example.com --no-headless

Mask values in console output (better for demos / privacy):

    python cookie_handler.py https://example.com --mask-values
"""

import argparse
import json
import sys
from typing import Any, Dict

from extractor import extract_cookies_and_storage


def _truncate(value: str, max_len: int = 60) -> str:
    """Truncate a string for console display."""
    if value is None:
        return ""
    if len(value) <= max_len:
        return value
    return value[: max_len - 3] + "..."


def _mask(value: str, visible: int = 4) -> str:
    """Mask a value, keeping only the first `visible` characters."""
    if value is None:
        return ""
    if len(value) <= visible:
        return "*" * len(value)
    return value[:visible] + "…" + "*" * max(0, len(value) - visible)


def _print_summary(result: Dict[str, Any], mask_values: bool = False) -> None:
    """Print a human-readable summary of the extraction result."""
    url = result.get("url", "<unknown>")
    counts = result.get("counts") or {}
    cookies = result.get("http_cookies") or []
    local_storage = result.get("local_storage") or {}
    session_storage = result.get("session_storage") or {}

    print("\n" + "=" * 72)
    print(f"Extraction summary for: {url}")
    print("=" * 72)
    print(
        f"HTTP cookies     : {counts.get('http_cookies', len(cookies))}\n"
        f"localStorage keys: {counts.get('local_storage', len(local_storage))}\n"
        f"sessionStorage   : {counts.get('session_storage', len(session_storage))}\n"
        f"Total items      : {counts.get('total', 0)}"
    )

    print("\n" + "=" * 72)
    print("HTTP COOKIES")
    print("-" * 72)
    if not cookies:
        print("(none)")
    else:
        for c in cookies:
            name = c.get("name", "<no-name>")
            domain = c.get("domain", "")
            raw_value = c.get("value", "")
            value = _mask(raw_value) if mask_values else _truncate(raw_value)

            print(f"\n{name}")
            print(f"  Domain  : {domain}")
            print(f"  Value   : {value}")
            print(f"  Secure  : {c.get('secure')}")
            print(f"  HttpOnly: {c.get('httpOnly')}")

    print("\n" + "=" * 72)
    print("LOCAL STORAGE (keys and sample values)")
    print("-" * 72)
    if not local_storage:
        print("(none)")
    else:
        for key, raw_value in local_storage.items():
            value = _mask(str(raw_value)) if mask_values else _truncate(str(raw_value))
            print(f"\nKey   : {key}")
            print(f"Value : {value}")

    print("\n" + "=" * 72)
    print("SESSION STORAGE (keys and sample values)")
    print("-" * 72)
    if not session_storage:
        print("(none)")
    else:
        for key, raw_value in session_storage.items():
            value = _mask(str(raw_value)) if mask_values else _truncate(str(raw_value))
            print(f"\nKey   : {key}")
            print(f"Value : {value}")

    print("\n" + "=" * 72)
    print("NOTE: Values printed here may contain identifiers or session data.")
    if mask_values:
        print("      (Console output is masked, but any JSON output file will contain full values.)")
    else:
        print("      Use --mask-values for privacy-friendly console output.")
    print("=" * 72 + "\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Extract cookies, localStorage, and sessionStorage from a web page.",
    )
    parser.add_argument(
        "url",
        help="URL to analyze (e.g., https://www.amazon.com). "
             "If missing a scheme, https:// will be prefixed automatically.",
    )
    parser.add_argument(
        "-w",
        "--wait",
        type=int,
        default=8,
        help="Seconds to wait after page load before extracting (default: 8).",
    )
    parser.add_argument(
        "--no-headless",
        action="store_true",
        help="Run Chrome in non-headless mode (browser window will be visible).",
    )
    parser.add_argument(
        "-o",
        "--output",
        metavar="FILE",
        help="Optional JSON file to save full extraction results (raw values).",
    )
    parser.add_argument(
        "--mask-values",
        action="store_true",
        help="Mask cookie and storage values in console output (JSON output remains unmasked).",
    )

    args = parser.parse_args(argv)

    print("=== Cookie & Storage Extraction ===\n")
    print(f"Target URL   : {args.url}")
    print(f"Headless     : {not args.no_headless}")
    print(f"Wait (sec)   : {args.wait}")
    if args.output:
        print(f"Output file  : {args.output}")
    print()

    result = extract_cookies_and_storage(
        url=args.url,
        headless=not args.no_headless,
        wait_time=args.wait,
    )

    if not result.get("success"):
        print("❌ Extraction failed.")
        print(f"   Error type: {result.get('error_type', 'Error')}")
        print(f"   Message   : {result.get('error', '')}")
        return 1

    # Optional JSON output
    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as f:
                json.dump(result, f, indent=2, ensure_ascii=False)
            print(f"✓ Full results saved to: {args.output}")
        except OSError as e:
            print(f"⚠ Failed to save JSON output to '{args.output}': {e}")

    # Human-readable summary
    _print_summary(result, mask_values=args.mask_values)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
