#!/usr/bin/env python3
"""Extract EchoGather C2 URL from an EchoGather PE (or any binary that embeds it).

The EchoGather beacon stores its C2 config as three consecutive UTF-16LE,
nul-terminated strings in .rdata: scheme ("https"), host ("fast-eda.my"),
path ("dostavka/..."). The config is not obfuscated, so we scan the file
for UTF-16LE strings and pick the first (scheme, host, path) triple that
matches.

Usage:
    extract_c2.py <file> [<file> ...]
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

# RFC 1035-ish hostname (2+ labels, total <=253, TLD 2-63 letters).
DOMAIN_RE = re.compile(
    r"^(?=.{4,253}$)"
    r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z]{2,63}$",
    re.IGNORECASE,
)
SCHEMES = {"http", "https"}


def iter_wide_strings(data: bytes, min_len: int = 4):
    """Yield (offset, text) for printable UTF-16LE nul-terminated strings."""
    i, n = 0, len(data) - 1
    while i < n:
        if 0x20 <= data[i] < 0x7F and data[i + 1] == 0:
            start = i
            chars = []
            while i < n and 0x20 <= data[i] < 0x7F and data[i + 1] == 0:
                chars.append(chr(data[i]))
                i += 2
            if i + 1 < len(data) and data[i] == 0 and data[i + 1] == 0 and len(chars) >= min_len:
                yield start, "".join(chars)
        else:
            i += 1


def looks_like_path(s: str) -> bool:
    return "/" in s and " " not in s and "://" not in s


def extract_c2(path: Path) -> dict | None:
    data = path.read_bytes()
    strings = list(iter_wide_strings(data))

    for i, (_, s) in enumerate(strings):
        if s.lower() not in SCHEMES:
            continue
        scheme = s.lower()
        for j in range(i + 1, min(i + 32, len(strings))):
            _, host = strings[j]
            if not DOMAIN_RE.match(host):
                continue
            url_path = None
            if j + 1 < len(strings):
                _, nxt = strings[j + 1]
                if looks_like_path(nxt):
                    url_path = nxt
            url = f"{scheme}://{host}"
            if url_path:
                url += "/" + url_path.lstrip("/")
            return {"scheme": scheme, "host": host, "path": url_path, "url": url}
    return None


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print(f"Usage: {argv[0]} <file> [<file> ...]", file=sys.stderr)
        return 1

    rc = 0
    for arg in argv[1:]:
        p = Path(arg)
        if not p.is_file():
            print(f"{arg}\t<not a file>", file=sys.stderr)
            rc = 2
            continue
        result = extract_c2(p)
        if result is None:
            print(f"{arg}\t<no C2 found>")
            rc = rc or 3
        else:
            print(f"{arg}\t{result['host']}\t{result['url']}")
    return rc


if __name__ == "__main__":
    sys.exit(main(sys.argv))
