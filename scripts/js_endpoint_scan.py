#!/usr/bin/env python3
"""js_endpoint_scan.py — 前端 JS 接口清单提取（自包含内置版，纯标准库）。

替代 v7 07-tools/js-analysis/cli.mjs 的清单化提取职责（混淆还原仍用本包
js_unpack.py：先 unpack 再对本脚本跑清单）。

产物素材（candidate_only）：URL/路径字面量、fetch/axios 调用、加密/盐信号。
接口清单与可控账仍以 js-collection.json 为准——本脚本只是采集器，不顶硬账。
"""
from __future__ import annotations

import sys

sys.dont_write_bytecode = True

import argparse
import json
import re
import sys
from pathlib import Path

JS_EXT = {".js", ".jsx", ".ts", ".tsx", ".vue", ".mjs", ".cjs"}
SKIP_DIRS = {"node_modules", "dist", "build", ".git", "__pycache__", ".idea", ".vscode"}
MAX_FILE_BYTES = 2_000_000
MAX_RECORDS = 2000

# 路径字面量：引号内以 / 开头、至少两段、含字母，排除静态资源/纯图片
PATH_LITERAL_RE = re.compile(
    r"['\"](/(?:[A-Za-z0-9_\-.$ {}]+/)+[A-Za-z0-9_\-.$ {}]+)['\"]"
)
# 静态资源与杂项排除
PATH_EXCLUDE_RE = re.compile(
    r"\.(?:png|jpe?g|gif|svg|ico|css|scss|less|woff2?|ttf|eot|mp4|mp3|webm|map)(?:[?'\"]|$)",
    re.I,
)
HTTP_URL_RE = re.compile(r"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+")
CALL_RE = re.compile(
    r"\b(?:fetch|axios(?:\.(?:get|post|put|delete|patch))?)\s*\(\s*['\"`]([^'\"`]+)",
    re.I,
)
CRYPTO_SIGNAL_RE = re.compile(
    r"\b(?:md5|sha1|sha256|aes|des|rsa|encrypt|decrypt|cipher|hmac|base64|"
    r"sign|secret|salt|tokenize|jav\(?:a\)?lang|CryptoJS|JSEncrypt|sm[234])\b",
    re.I,
)


def iter_js_files(root: Path):
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        try:
            rel_parts = path.relative_to(root).parts
        except ValueError:
            continue
        if any(p.lower() in SKIP_DIRS for p in rel_parts[:-1]):
            continue
        if path.suffix.lower() not in JS_EXT:
            continue
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                continue
        except OSError:
            continue
        yield path


def scan(root: Path) -> dict:
    endpoints: list[dict] = []
    crypto: list[dict] = []
    seen_endpoint: set[tuple[str, str, int]] = set()
    files_scanned = 0
    truncated = False

    for path in iter_js_files(root):
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        files_scanned += 1
        rel = path.relative_to(root).as_posix()
        for i, line in enumerate(text.splitlines(), 1):
            if len(endpoints) < MAX_RECORDS:
                for m in CALL_RE.finditer(line):
                    key = ("call", rel, i)
                    if key not in seen_endpoint:
                        seen_endpoint.add(key)
                        endpoints.append(
                            {
                                "file": rel,
                                "line": i,
                                "kind": "http_call",
                                "raw": m.group(0)[:200],
                                "path": m.group(1)[:200],
                                "candidate_only": True,
                            }
                        )
                for m in PATH_LITERAL_RE.finditer(line):
                    val = m.group(1)
                    if len(val) < 4 or PATH_EXCLUDE_RE.search(val):
                        continue
                    if not re.search(r"[A-Za-z]", val):
                        continue
                    key = ("path", rel, i)
                    if key not in seen_endpoint:
                        seen_endpoint.add(key)
                        endpoints.append(
                            {
                                "file": rel,
                                "line": i,
                                "kind": "path_literal",
                                "raw": val[:200],
                                "path": val[:200],
                                "candidate_only": True,
                            }
                        )
                for m in HTTP_URL_RE.finditer(line):
                    key = ("url", rel, i)
                    if key not in seen_endpoint:
                        seen_endpoint.add(key)
                        endpoints.append(
                            {
                                "file": rel,
                                "line": i,
                                "kind": "absolute_url",
                                "raw": m.group(0)[:200],
                                "path": m.group(0)[:200],
                                "candidate_only": True,
                            }
                        )
            if len(crypto) < MAX_RECORDS and CRYPTO_SIGNAL_RE.search(line):
                ckey = (rel, i)
                if ckey not in {(c["file"], c["line"]) for c in crypto}:
                    crypto.append(
                        {
                            "file": rel,
                            "line": i,
                            "raw": line.strip()[:200],
                            "candidate_only": True,
                        }
                    )
        if len(endpoints) >= MAX_RECORDS:
            truncated = True
            break

    return {
        "schema": "js-endpoint-scan-v1",
        "root": root.as_posix(),
        "files_scanned": files_scanned,
        "endpoint_count": len(endpoints),
        "endpoints": endpoints,
        "crypto_signal_count": len(crypto),
        "crypto_signals": crypto[:200],
        "truncated": truncated,
        "candidate_only": True,
        "note": "采集素材；接口清单与可控账仍以 js-collection.json 为准，不顶硬账",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True, help="前端目录/解包产物目录")
    parser.add_argument("--out", type=Path, help="JSON 输出路径（缺省打 stdout）")
    args = parser.parse_args(argv)
    root = args.root.resolve()
    if not root.is_dir():
        print(
            json.dumps({"status": "failed", "reason": f"root missing: {root}"}, ensure_ascii=False),
            file=sys.stderr,
        )
        return 2
    result = scan(root)
    payload = json.dumps(result, ensure_ascii=False, indent=2)
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(payload + "\n", encoding="utf-8")
        print(
            json.dumps(
                {
                    "status": "ok",
                    "out": str(args.out),
                    "files_scanned": result["files_scanned"],
                    "endpoint_count": result["endpoint_count"],
                    "crypto_signal_count": result["crypto_signal_count"],
                },
                ensure_ascii=False,
            )
        )
    else:
        print(payload)
    return 0


if __name__ == "__main__":
    sys.exit(main())
