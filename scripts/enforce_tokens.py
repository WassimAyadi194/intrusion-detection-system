#!/usr/bin/env python3
"""
scripts/enforce_tokens.py
─────────────────────────
Static enforcement scanner for the Antigravity IDS design-token system.

Scans Python source files and QSS strings for violations of the
design-token rules defined in frontend/theme.py.

Usage:
    python scripts/enforce_tokens.py [paths ...]

    Default paths: frontend/

Exit codes:
    0  — no violations found
    1  — one or more violations found (CI should treat this as a failure)

Rules checked
─────────────
  R01  Raw pixel literal in QSS              e.g. padding: 12px
  R02  Raw pixel literal in Python           e.g. setFixedHeight(40)
  R03  Arithmetic expression on token        e.g. {F["md"] - 1}px
  R04  Hardcoded border-radius without token e.g. border-radius: 6px
  R05  Hardcoded letter-spacing without tok  e.g. letter-spacing: 2px
  R06  Hardcoded max-width without token     e.g. max-width: 38px
  R07  Import of removed SIZES namespace     e.g. from frontend.theme import SIZES
  R08  Use of removed SIZES namespace        e.g. SIZES["alert_timestamp_w"]
"""

from __future__ import annotations

import re
import sys
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator


# ── Violation model ────────────────────────────────────────────────────────

@dataclass
class Violation:
    rule:    str
    file:    str
    line:    int
    content: str
    hint:    str = ""

    def __str__(self) -> str:
        loc = f"{self.file}:{self.line}"
        msg = f"[{self.rule}] {loc}\n    {self.content.strip()}"
        if self.hint:
            msg += f"\n    → {self.hint}"
        return msg


# ── Rule definitions ───────────────────────────────────────────────────────

@dataclass
class Rule:
    id:      str
    pattern: re.Pattern
    hint:    str
    # file extensions this rule applies to
    exts:    tuple[str, ...] = (".py",)


# Matches raw <digits>px literals NOT already wrapped in an f-string token call.
# Negative lookbehind prevents false-positives on already-tokenised values like
# {_s["lg"]}px which legitimately end in }px.
_RAW_PX = re.compile(r'(?<!\})\b\d+px\b')

RULES: list[Rule] = [
    Rule(
        id="R01",
        pattern=_RAW_PX,
        hint="Replace with a SPACING / COMPONENT_SIZES token: {_s['lg']}px",
        exts=(".py",),
    ),
    Rule(
        id="R02",
        # setFixedHeight(NN) / setFixedWidth(NN) with a bare integer
        pattern=re.compile(r'setFixed(?:Height|Width)\s*\(\s*\d+\s*\)'),
        hint=(
            "Replace with a token: "
            "setFixedHeight(LAYOUT_SIZES['row_h']) or "
            "setFixedWidth(COMPONENT_SIZES['timestamp_col_w'])"
        ),
        exts=(".py",),
    ),
    Rule(
        id="R03",
        # Arithmetic on token values inside f-strings: {F["md"] - 1} or {S["lg"] + 4}
        pattern=re.compile(r'\{[A-Z_]+\s*\[.*?\]\s*[\+\-\*\/]\s*\d+\s*\}'),
        hint="Never compute on tokens. Define a dedicated token for the value instead.",
        exts=(".py",),
    ),
    Rule(
        id="R04",
        # border-radius with a bare literal (not a token reference)
        pattern=re.compile(r'border(?:-[a-z]+)*-radius\s*:\s*\d+px(?!\s*\})'),
        hint="Replace with COMPONENT_SIZES token: border-radius: {_cs['border_radius_lg']}px",
        exts=(".py",),
    ),
    Rule(
        id="R05",
        # letter-spacing with a bare literal
        pattern=re.compile(r'letter-spacing\s*:\s*[\d.]+px(?!\s*\})'),
        hint="Replace with COMPONENT_SIZES token: letter-spacing: {_cs['letter_md']}px",
        exts=(".py",),
    ),
    Rule(
        id="R06",
        # max-width with a bare literal
        pattern=re.compile(r'max-width\s*:\s*\d+px(?!\s*\})'),
        hint="Replace with COMPONENT_SIZES token: max-width: {_cs['badge_w']}px",
        exts=(".py",),
    ),
    Rule(
        id="R07",
        # import of the old SIZES namespace (now split into LAYOUT_SIZES / COMPONENT_SIZES)
        pattern=re.compile(r'\bfrom\s+frontend\.theme\s+import\b[^\n]*\bSIZES\b'),
        hint=(
            "SIZES has been replaced. "
            "Import LAYOUT_SIZES and/or COMPONENT_SIZES instead."
        ),
        exts=(".py",),
    ),
    Rule(
        id="R08",
        # direct use of SIZES["..."] dict access
        pattern=re.compile(r'\bSIZES\s*\['),
        hint=(
            "SIZES has been replaced. "
            "Use LAYOUT_SIZES['...'] or COMPONENT_SIZES['...'] instead."
        ),
        exts=(".py",),
    ),
]


# ── Scanner ────────────────────────────────────────────────────────────────

def _scan_file(path: Path) -> Iterator[Violation]:
    """Yield all violations found in *path*."""
    try:
        source = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return

    ext = path.suffix.lower()
    lines = source.splitlines()

    for rule in RULES:
        if ext not in rule.exts:
            continue
        for lineno, line in enumerate(lines, start=1):
            # Skip comment lines (Python and QSS)
            stripped = line.lstrip()
            if stripped.startswith("#") or stripped.startswith("/*"):
                continue
            if rule.pattern.search(line):
                yield Violation(
                    rule=rule.id,
                    file=str(path),
                    line=lineno,
                    content=line,
                    hint=rule.hint,
                )


def scan(roots: list[Path]) -> list[Violation]:
    violations: list[Violation] = []
    for root in roots:
        if root.is_file():
            violations.extend(_scan_file(root))
        else:
            for py_file in root.rglob("*.py"):
                violations.extend(_scan_file(py_file))
    return violations


# ── Entry point ────────────────────────────────────────────────────────────

def main(argv: list[str] | None = None) -> int:
    args = argv if argv is not None else sys.argv[1:]
    roots = [Path(a) for a in args] if args else [Path("frontend")]

    missing = [r for r in roots if not r.exists()]
    if missing:
        for m in missing:
            print(f"enforce_tokens: path not found: {m}", file=sys.stderr)
        return 2

    violations = scan(roots)

    if not violations:
        print("✓  enforce_tokens: no violations found.")
        return 0

    print(f"✗  enforce_tokens: {len(violations)} violation(s) found:\n")
    for v in violations:
        print(v)
        print()

    # Summary table
    from collections import Counter
    counts = Counter(v.rule for v in violations)
    print("─" * 60)
    print("Rule  │ Count │ Description")
    print("──────┼───────┼" + "─" * 40)
    rule_desc = {r.id: r.hint[:38] for r in RULES}
    for rule_id, count in sorted(counts.items()):
        print(f"{rule_id:<6}│ {count:<6}│ {rule_desc.get(rule_id, '')}")

    return 1


if __name__ == "__main__":
    sys.exit(main())