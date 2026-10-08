#!/usr/bin/env python3
"""Compare two JSON results from Network VAPT scans.

This compares rule-based observations; it does not prove exploitability.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def finding_key(item: dict) -> tuple:
    return (
        item.get("host", ""),
        item.get("port", 0),
        item.get("service", ""),
        item.get("title", ""),
    )


def load(path: Path) -> dict:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def main() -> int:
    parser = argparse.ArgumentParser(description="Compare baseline and retest Network VAPT JSON results.")
    parser.add_argument("baseline")
    parser.add_argument("retest")
    parser.add_argument("-o", "--output", default="retest_results.json")
    args = parser.parse_args()

    baseline = load(Path(args.baseline))
    retest = load(Path(args.retest))

    old = {finding_key(x): x for x in baseline.get("findings", [])}
    new = {finding_key(x): x for x in retest.get("findings", [])}

    results = []
    for key in sorted(set(old) | set(new)):
        if key in old and key in new:
            status = "OPEN"
        elif key in old and key not in new:
            status = "FIXED"
        else:
            status = "CHANGED"

        source = new.get(key) or old.get(key)
        results.append(
            {
                "status": status,
                "host": source.get("host", ""),
                "port": source.get("port", 0),
                "service": source.get("service", ""),
                "title": source.get("title", ""),
                "severity": source.get("severity", ""),
                "baseline_present": key in old,
                "retest_present": key in new,
            }
        )

    summary = {
        "baseline_target": baseline.get("target"),
        "retest_target": retest.get("target"),
        "baseline_findings": len(old),
        "retest_findings": len(new),
        "fixed": sum(x["status"] == "FIXED" for x in results),
        "open": sum(x["status"] == "OPEN" for x in results),
        "changed": sum(x["status"] == "CHANGED" for x in results),
        "results": results,
    }

    with Path(args.output).open("w", encoding="utf-8") as handle:
        json.dump(summary, handle, indent=2)

    print(
        f"Retest comparison: fixed={summary['fixed']} "
        f"open={summary['open']} changed={summary['changed']}"
    )
    print(f"[+] Report: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
