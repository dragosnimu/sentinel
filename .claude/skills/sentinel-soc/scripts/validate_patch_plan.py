#!/usr/bin/env python3
"""Validate a patch plan before returning it.

This is a thin CLI over `sentinel.patch.validator` — deliberately, so that the
plan is checked against *exactly* the rules the runtime will apply. A separate
copy of the rules here would drift, and plans would pass validation in the skill
and be rejected at execution time.

Always run this before emitting a plan. A plan that fails twice is stored as
`rejected_invalid` and the operator is told the AI could not produce a safe
procedure — which is an acceptable outcome. A plan that looks fine and breaks
production is not.

Usage:
    validate_patch_plan.py --file plan.json
    cat plan.json | validate_patch_plan.py --stdin

Exit codes:
    0  valid
    1  invalid — errors printed as JSON on stdout
    2  could not run (bad input, package not importable)
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

try:
    from sentinel.patch.validator import validate_plan
except ImportError:
    print(
        json.dumps(
            {
                "valid": False,
                "errors": [
                    {
                        "path": "$",
                        "code": "validator_unavailable",
                        "message": (
                            "sentinel.patch.validator is not importable. Run this with "
                            "the Sentinel venv: /opt/sentinel/venv/bin/python "
                            "validate_patch_plan.py --file <plan>"
                        ),
                    }
                ],
            },
            indent=2,
        )
    )
    raise SystemExit(2) from None


def load(args: argparse.Namespace) -> Any:
    raw = sys.stdin.read() if args.stdin else Path(args.file).read_text(encoding="utf-8")
    if not raw.strip():
        print(json.dumps({"valid": False, "errors": [{"path": "$", "code": "empty",
                                                      "message": "no input"}]}, indent=2))
        raise SystemExit(2)
    # Tolerate a fenced block, since that is the most common way a plan arrives
    # slightly wrong. Everything else must be exact.
    stripped = raw.strip()
    if stripped.startswith("```"):
        lines = stripped.splitlines()
        stripped = "\n".join(lines[1 : -1 if lines[-1].strip() == "```" else None])
    try:
        return json.loads(stripped)
    except json.JSONDecodeError as exc:
        print(
            json.dumps(
                {
                    "valid": False,
                    "errors": [
                        {
                            "path": f"$ (line {exc.lineno}, col {exc.colno})",
                            "code": "invalid_json",
                            "message": exc.msg,
                        }
                    ],
                },
                indent=2,
            )
        )
        raise SystemExit(2) from None


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--file", help="path to the plan JSON")
    group.add_argument("--stdin", action="store_true", help="read the plan from stdin")
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="print nothing on success; rely on the exit code",
    )
    args = parser.parse_args()

    plan = load(args)
    result = validate_plan(plan)

    if result.valid:
        if not args.quiet:
            print(
                json.dumps(
                    {
                        "valid": True,
                        "plan_hash": result.plan_hash,
                        "warnings": [w.as_dict() for w in result.warnings],
                        "summary": result.summary,
                    },
                    ensure_ascii=False,
                    indent=2,
                )
            )
        raise SystemExit(0)

    print(
        json.dumps(
            {
                "valid": False,
                "errors": [e.as_dict() for e in result.errors],
                "warnings": [w.as_dict() for w in result.warnings],
                "hint": (
                    "Fix every error and re-run. Common causes: argv given as a "
                    "string instead of a list; argv[0] not in the binary allowlist; "
                    "a forbidden path; a missing rollback while risk.reversible is "
                    "true; a missing timeout_s."
                ),
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    raise SystemExit(1)


if __name__ == "__main__":
    main()
