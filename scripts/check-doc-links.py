#!/usr/bin/env python3
"""Fail if a relative Markdown link points to a file that does not exist.

Only links to local files are checked. External URLs, mail links, and
in-page anchors are ignored, because they depend on the network or on
rendering rules. Links inside fenced code blocks and inline code are skipped.
"""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCAN = ["README.md", "CONTRIBUTING.md", "SECURITY.md", "CHANGELOG.md", "docs", "research", "book/src", "submission"]
LINK = re.compile(r"(?<!!)\[[^\]]*\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)")
SKIP_PREFIXES = ("http://", "https://", "mailto:", "#")


def markdown_files():
    for entry in SCAN:
        path = ROOT / entry
        if path.is_file():
            yield path
        elif path.is_dir():
            yield from sorted(path.rglob("*.md"))


def links_outside_code(text):
    in_fence = False
    for number, line in enumerate(text.splitlines(), start=1):
        if line.lstrip().startswith("```"):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        stripped = re.sub(r"`[^`]*`", "", line)
        for match in LINK.finditer(stripped):
            yield number, match.group(1)


def main():
    failures = []
    checked = 0
    for source in markdown_files():
        for number, target in links_outside_code(source.read_text(encoding="utf-8")):
            if target.startswith(SKIP_PREFIXES):
                continue
            checked += 1
            relative = target.split("#", 1)[0]
            if not relative:
                continue
            if not (source.parent / relative).resolve().exists():
                failures.append(f"{source.relative_to(ROOT)}:{number}: missing target {target}")
    for failure in failures:
        print(failure)
    print(f"checked {checked} relative links, {len(failures)} broken")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
