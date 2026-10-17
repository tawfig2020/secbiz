"""Generate a CycloneDX 1.4 SBOM (stdlib-only).

Answers "what's in this release?" — the first question every BFSI security
review asks. Reads `requirements.txt` (and optional `requirements.lock`) and
emits a CycloneDX JSON document.

Usage:
    python sbom.py [--out sbom.cdx.json]
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent

_REQ = re.compile(r"^\s*([A-Za-z0-9_.\-]+)\s*(?:[<>=!~]=?|==)\s*([^\s;#]+)")


def _parse_requirements(path: Path) -> list[dict]:
    components = []
    if not path.exists():
        return components
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        m = _REQ.match(line)
        if m:
            components.append({"name": m.group(1), "version": m.group(2)})
        else:
            components.append({"name": line, "version": "unknown"})
    return components


def build_sbom() -> dict:
    components = _parse_requirements(ROOT / "requirements.txt")
    lock = _parse_requirements(ROOT / "requirements.lock")
    if lock:
        components = lock
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "serialNumber": "urn:uuid:aegis-sbom-0001",
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "name": "aegis",
                "version": "1.0.0",
            },
        },
        "components": [
            {"type": "library", "name": c["name"], "version": c["version"]}
            for c in components
        ],
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", default="sbom.cdx.json")
    args = ap.parse_args()
    sbom = build_sbom()
    Path(args.out).write_text(json.dumps(sbom, indent=2), encoding="utf-8")
    print(f"wrote SBOM with {len(sbom['components'])} components to {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
