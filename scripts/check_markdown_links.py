from __future__ import annotations

import pathlib
import re
import sys


ROOT = pathlib.Path(__file__).resolve().parents[1]
LINK = re.compile(r"(?<!!)\[[^]]+\]\(([^)]+)\)")


def local_target(document: pathlib.Path, raw_target: str) -> pathlib.Path | None:
    target = raw_target.strip().split("#", 1)[0]
    if not target or "://" in target or target.startswith(("mailto:", "#")):
        return None
    target = target.split(" ", 1)[0].strip("<>")
    return (document.parent / target).resolve()


def main() -> int:
    failures: list[str] = []
    for document in ROOT.rglob("*.md"):
        if any(part in {"_build", "_opam", ".git"} for part in document.parts):
            continue
        text = document.read_text(encoding="utf-8")
        for match in LINK.finditer(text):
            target = local_target(document, match.group(1))
            if target is not None and not target.exists():
                failures.append(f"{document.relative_to(ROOT)}: missing {match.group(1)}")
    if failures:
        print("\n".join(failures), file=sys.stderr)
        return 1
    print("All local Markdown links resolve.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
