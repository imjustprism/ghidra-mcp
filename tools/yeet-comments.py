#!/usr/bin/env python3
"""Strip all comments from project source. Doc-comments become attributes first.

  - Rust field ///  -> #[schemars(description = "...")] when JsonSchema-ish
  - Rust /// before #[arg(...)] -> help = "..." inside the arg attribute
  - Then remove // /// //! /* */ from .rs and // /* */ from .java (string-aware)

Usage:
  python tools/yeet-comments.py           # write in place
  python tools/yeet-comments.py --check   # exit 1 if any comments remain
  python tools/yeet-comments.py --dry-run
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RUST_GLOBS = ["src/**/*.rs"]
JAVA_GLOBS = ["plugin/src/**/*.java"]


def rust_escape(s: str) -> str:
    return s.replace("\\", "\\\\").replace('"', '\\"')


def convert_rust_docs(src: str) -> str:
    allow_schemars = "schemars" in src
    lines = src.splitlines(keepends=True)
    out: list[str] = []
    i = 0
    n = len(lines)

    def peek_nonempty(j: int) -> tuple[int, str] | None:
        while j < n:
            t = lines[j].strip()
            if t == "":
                j += 1
                continue
            return j, lines[j]
        return None

    while i < n:
        m = re.match(r"^(\s*)///\s?(.*)$", lines[i].rstrip("\n\r"))
        if not m:
            out.append(lines[i])
            i += 1
            continue

        indent, first = m.group(1), m.group(2)
        docs = [first]
        i += 1
        while i < n:
            m2 = re.match(r"^\s*///\s?(.*)$", lines[i].rstrip("\n\r"))
            if not m2:
                break
            docs.append(m2.group(1))
            i += 1
        text = " ".join(d.strip() for d in docs if d is not None).strip()
        text = re.sub(r"\s+", " ", text)

        nxt = peek_nonempty(i)
        if nxt is None:
            continue
        j, line = nxt
        stripped = line.strip()

        if stripped.startswith("#[arg(") or stripped.startswith("#[arg ("):
            # fold into help=
            block = [line]
            k = j + 1
            depth = line.count("[") - line.count("]")
            while depth > 0 and k < n:
                block.append(lines[k])
                depth += lines[k].count("[") - lines[k].count("]")
                k += 1
            joined = "".join(block)
            help_lit = rust_escape(text)
            if re.search(r"\bhelp\s*=", joined):
                new_attr = joined
            elif joined.rstrip().endswith(")]"):
                # insert before closing )]
                new_attr = re.sub(
                    r"\)\]\s*$",
                    f', help = "{help_lit}")]',
                    joined.rstrip(),
                    count=1,
                )
                if not joined.endswith("\n") and lines[j].endswith("\n"):
                    new_attr += "\n"
                elif joined.endswith("\n"):
                    new_attr = new_attr.rstrip("\n") + "\n"
            else:
                # multi-line arg attr: inject before final )]
                new_attr = re.sub(
                    r"\)\](\s*)$",
                    f', help = "{help_lit}")]\\1',
                    joined,
                    count=1,
                )
            out.append(new_attr if new_attr.endswith("\n") else new_attr + "\n")
            i = k
            continue

        # field docs for JsonSchema structs only — otherwise drop (zero comments)
        if allow_schemars and (
            re.search(r"\b(pub\s+)?(struct|enum)\b", stripped)
            or re.match(r"^(pub(\s*\([^)]*\))?\s+)?(const|static|type|fn|async|struct|enum|trait)\b", stripped)
            is None
            or re.match(
                r"^(pub(\s*\([^)]*\))?\s+)?([A-Za-z_][A-Za-z0-9_]*|\w+)\s*[:{=]",
                stripped,
            )
            or stripped.startswith("#[")
        ):
            # Prefer attaching only to field-like lines or attrs leading to fields
            if stripped.startswith("#[") or re.search(r":\s*", stripped) or stripped.endswith(","):
                out.append(f'{indent}#[schemars(description = "{rust_escape(text)}")]\n')
        # else: drop the doc comment entirely
        continue

    return "".join(out)


def strip_module_docs(src: str) -> str:
    lines = src.splitlines(keepends=True)
    out: list[str] = []
    i = 0
    while i < len(lines):
        if re.match(r"^\s*//!", lines[i]):
            i += 1
            continue
        out.append(lines[i])
        i += 1
    return "".join(out)


def strip_comments_generic(src: str, line_comment: str = "//") -> str:
    """String-aware strip of // and /* */ comments. Preserves string/char contents."""
    out: list[str] = []
    i = 0
    n = len(src)
    state = "code"  # code | line | block | str | raw | char

    while i < n:
        c = src[i]
        nxt = src[i + 1] if i + 1 < n else ""

        if state == "code":
            if c == "/" and nxt == "/" and line_comment == "//":
                # not /// already handled? still strip any remaining
                state = "line"
                i += 2
                continue
            if c == "/" and nxt == "*":
                state = "block"
                i += 2
                continue
            if c == '"':
                # raw string r#"..."# or r"..."
                # check for r# prefixes behind
                out.append(c)
                state = "str"
                i += 1
                continue
            if c == "'":
                out.append(c)
                state = "char"
                i += 1
                continue
            # rust raw strings: r" or r#" or br" etc
            if c in "rb" or (c == "r"):
                # try match raw string start
                m = re.match(r'(b?r|#)*r(#*)"', src[i:])
                # simpler: r#* " 
                m2 = re.match(r'b?r(#*)"', src[i:])
                if m2:
                    hashes = m2.group(1)
                    out.append(m2.group(0))
                    i += len(m2.group(0))
                    # read until " + hashes
                    end = '"' + hashes
                    while i < n:
                        if src.startswith(end, i):
                            out.append(end)
                            i += len(end)
                            break
                        out.append(src[i])
                        i += 1
                    continue
            out.append(c)
            i += 1
            continue

        if state == "line":
            if c == "\n":
                out.append(c)
                state = "code"
            i += 1
            continue

        if state == "block":
            if c == "*" and nxt == "/":
                state = "code"
                i += 2
            else:
                # preserve newlines to keep line numbers somewhat stable
                if c == "\n":
                    out.append(c)
                i += 1
            continue

        if state == "str":
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(src[i + 1])
                i += 2
                continue
            if c == '"':
                state = "code"
            i += 1
            continue

        if state == "char":
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(src[i + 1])
                i += 2
                continue
            if c == "'":
                state = "code"
            i += 1
            continue

        i += 1

    # collapse 3+ blank lines -> 2, strip trailing whitespace on empty-comment lines
    text = "".join(out)
    text = re.sub(r"[ \t]+\n", "\n", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text


def process_rust(src: str) -> str:
    src = strip_module_docs(src)
    src = convert_rust_docs(src)
    src = strip_comments_generic(src)
    return src


def process_java(src: str) -> str:
    return strip_comments_generic(src)


def iter_sources() -> list[Path]:
    files: list[Path] = []
    for g in RUST_GLOBS:
        files.extend(ROOT.glob(g))
    for g in JAVA_GLOBS:
        files.extend(ROOT.glob(g))
    return sorted({p for p in files if p.is_file()})


def still_has_comments(path: Path, text: str) -> list[str]:
    hits: list[str] = []
    # crude check outside strings is hard; scan lines that look like comments
    for n, line in enumerate(text.splitlines(), 1):
        s = line.strip()
        if not s:
            continue
        if path.suffix == ".rs":
            if s.startswith("//") or s.startswith("///") or s.startswith("//!"):
                hits.append(f"{path}:{n}: {s[:80]}")
            if s.startswith("/*") or s.startswith("*") and "*/" in s:
                # allow * in code; only flag /* 
                if s.startswith("/*"):
                    hits.append(f"{path}:{n}: {s[:80]}")
        else:
            if s.startswith("//") or s.startswith("/*") or s.startswith("* "):
                if s.startswith("*") and not s.startswith("*/"):
                    # might be leftover javadoc middle
                    if re.match(r"^\*\s", s) or s == "*":
                        hits.append(f"{path}:{n}: {s[:80]}")
                elif s.startswith("//") or s.startswith("/*"):
                    hits.append(f"{path}:{n}: {s[:80]}")
    return hits


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    changed = 0
    remaining: list[str] = []
    for path in iter_sources():
        raw = path.read_text(encoding="utf-8")
        if path.suffix == ".rs":
            new = process_rust(raw)
        else:
            new = process_java(raw)
        if new != raw:
            changed += 1
            if not args.dry_run and not args.check:
                path.write_text(new, encoding="utf-8", newline="\n")
        remaining.extend(still_has_comments(path, new if not args.check else (new if new != raw else raw)))
        if args.check:
            remaining.extend(still_has_comments(path, raw))

    if args.check:
        # re-read after would-be; for check mode scan current files
        remaining = []
        for path in iter_sources():
            remaining.extend(still_has_comments(path, path.read_text(encoding="utf-8")))
        if remaining:
            print(f"comments still present ({len(remaining)}):")
            for h in remaining[:50]:
                print(" ", h)
            if len(remaining) > 50:
                print(f"  ... +{len(remaining) - 50} more")
            return 1
        print("ok: zero comments")
        return 0

    mode = "dry-run" if args.dry_run else "wrote"
    print(f"{mode}: {changed} files changed, {len(iter_sources())} scanned")
    if not args.dry_run:
        left = []
        for path in iter_sources():
            left.extend(still_has_comments(path, path.read_text(encoding="utf-8")))
        if left:
            print(f"warning: {len(left)} comment-like lines remain:")
            for h in left[:40]:
                print(" ", h)
            return 1
        print("ok: zero comments")
    return 0


if __name__ == "__main__":
    sys.exit(main())
