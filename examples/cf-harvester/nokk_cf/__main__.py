"""CLI: ``python -m nokk_cf harvest <url> [--proxy ...]`` → clearance as JSON.

The JSON is shaped so a consumer (e.g. a nokk session importer) can replay the
cookie under the same IP + User-Agent it was minted with.
"""

from __future__ import annotations

import argparse
import asyncio
import dataclasses
import json
import sys

from .harvester import harvest


def _cmd_harvest(args: argparse.Namespace) -> int:
    try:
        result = asyncio.run(
            harvest(
                args.url,
                proxy=args.proxy,
                headless=args.headless,
                timeout=args.timeout,
                out_path=args.out,
            )
        )
    except Exception as exc:  # surface a clean, non-tracebacky failure to the CLI
        print(f"error: {exc}", file=sys.stderr)
        return 1
    json.dump(dataclasses.asdict(result), sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="nokk-cf",
        description="Harvest a Cloudflare cf_clearance cookie with a real browser.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    h = sub.add_parser("harvest", help="solve the challenge at URL and print the clearance")
    h.add_argument("url", help="target URL behind the Cloudflare challenge")
    h.add_argument("--proxy", help="scheme://host:port residential/mobile proxy")
    h.add_argument(
        "--headless",
        action="store_true",
        help="run headless (managed challenges usually need headful; default off)",
    )
    h.add_argument("--timeout", type=float, default=180.0, help="seconds to wait")
    h.add_argument(
        "--out",
        default="cf_clearance.json",
        help="write the clearance JSON here the instant it's found (default: ./cf_clearance.json)",
    )
    h.set_defaults(func=_cmd_harvest)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
