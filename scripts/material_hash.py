#!/usr/bin/env python3
"""Hash a zip, a single file, or a directory (SKILL 步 1 写的「ZIP或目录」由此兑现).

目录形态：递归收集文件（排序、跳 node_modules/.git/__pycache__），逐文件 sha256，
总哈希 = 对「排序的 (相对路径, 类型, 文件哈希/空目录标记) 清单」再算一次 sha256
（2026-10-16 修复批：目录结构与空目录入账、reparse/symlink 目录不跟入只记链接条目、
每文件二读校验——被改写中的文件记 unstable 且退出非零）。不把源码树读进模型。

退出码：0 正常；2 zip 结构坏（BadZipFile/加密等，结构化 zip_error 字段）；3 有 unstable 文件。"""
from __future__ import annotations
import sys
sys.dont_write_bytecode = True  # 2026-10-13 新6: 禁 pyc 落包目录（包卫生）

import argparse
import hashlib
import json
import os
import stat
from pathlib import Path

_SKIP_DIRS = {"node_modules", ".git", "__pycache__"}
_REPARSE_POINT = 0x400  # FILE_ATTRIBUTE_REPARSE_POINT：Windows junction/symlink 皆置位


def _is_link(path: Path) -> bool:
    # 2026-10-16 修复批（第 7 条）：reparse/symlink 判定——os.walk 的 followlinks=False
    # 不识别 junction（mount point），必须按文件属性自剪枝；文件链接同样只记不哈希，
    # 否则 junction 指向包外目录=账外注入、循环 junction=同一文件重复入账。
    try:
        st = os.stat(path, follow_symlinks=False)
    except OSError:
        return False
    if getattr(st, "st_file_attributes", 0) & _REPARSE_POINT:
        return True
    return stat.S_ISLNK(st.st_mode)  # POSIX 兜底


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _stable_sha256(path: Path) -> tuple[str, bool]:
    # 2026-10-16 修复批（第 8 条）：二读比对——扫描期间被改写的文件两次哈希不一致，
    # 该文件记 unstable 且整体退出非零，杜绝静默漂移账（产出的账必须可复现）
    d1 = sha256_file(path)
    d2 = sha256_file(path)
    return (d2, d1 == d2)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--file", required=True)
    # 批四十一（红队七轮 P5 工具调用缺口）：--out 落盘——H-22/批三十五要求开局落
    # run/material-manifest.json（目录/单件 ZIP 原档账同构），此前只打印 stdout，
    # 全包没有一行落盘命令，执行者第一次不知道产出放哪、拿什么喂 env 回执锚。
    parser.add_argument("--out", help="落盘目标 JSON 路径（如 run/material-manifest.json / run/material-manifest-src.json）；不传仍打印 stdout")
    args = parser.parse_args()
    path = Path(args.file)
    if path.is_file():
        # 2026-10-16 修复批（第 10 条）：单文件补 "kind":"file"，与 directory/zip 口径对齐
        digest, stable = _stable_sha256(path)
        out = {
            "path": str(path.resolve()),
            "kind": "file",
            "sha256": digest,
            "size_bytes": path.stat().st_size,
        }
        rc = 0
        if not stable:
            out["unstable"] = True
            rc = 3
        # 批三十七（红队三轮 P0-3 前置）：ZIP 条目账——防「解压后开局投毒」：原档逐成员哈希
        # 落 run/material-manifest-src.json，close 对 source_refs 出处双账比对（解压树投毒 =
        # 出处 sha 在原档账中不存在）
        if path.suffix.lower() == ".zip":
            import zipfile as _zf
            entries = []
            # 2026-10-16 修复批（第 9 条）：坏 zip 结构化报错——CRC 损坏（BadZipFile）、
            # 加密条目（RuntimeError）等不再裸 traceback，落 zip_error 字段并 exit 2
            try:
                with _zf.ZipFile(path) as z:
                    for info in z.infolist():
                        if info.is_dir():
                            continue
                        h = hashlib.sha256()
                        with z.open(info) as fh:
                            for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                                h.update(chunk)
                        entries.append({"path": info.filename, "sha256": h.hexdigest(), "size_bytes": info.file_size})
                out["kind"] = "zip"
                out["zip_entries"] = entries
            except (_zf.BadZipFile, RuntimeError, OSError, EOFError, ValueError) as exc:
                out["kind"] = "zip"
                out["zip_error"] = f"{type(exc).__name__}: {exc}"
                _emit(out, args)
                return 2
        _emit(out, args)
        return rc
    if path.is_dir():
        # 2026-10-16 修复批（第 7 条）：os.walk 自剪 reparse/symlink 目录不跟入——
        # junction 指包外=账外注入、循环 junction=重复入账；链接（目录/文件）记 links 不哈希。
        files: list[Path] = []
        links: list[str] = []
        dir_rows: list[str] = []
        for dirpath, dirnames, filenames in os.walk(path):
            keep = []
            for dn in sorted(dirnames):
                if dn in _SKIP_DIRS:
                    continue
                full = Path(dirpath) / dn
                if _is_link(full):
                    links.append(full.relative_to(path).as_posix())
                else:
                    keep.append(dn)
                    dir_rows.append(full.relative_to(path).as_posix())
            dirnames[:] = keep
            for fn in sorted(filenames):
                full = Path(dirpath) / fn
                if _is_link(full):
                    links.append(full.relative_to(path).as_posix())
                else:
                    files.append(full)
        files.sort(key=lambda p: p.relative_to(path).as_posix())
        total = hashlib.sha256()
        entries = []
        unstable: list[str] = []
        for p in files:
            digest, stable = _stable_sha256(p)
            rel = p.relative_to(path).as_posix()
            entries.append({"path": rel, "sha256": digest, "size_bytes": p.stat().st_size})
            if not stable:
                unstable.append(rel)
        # 2026-10-16 修复批（第 11 条）：总账含目录结构——排序的 (相对路径, 类型,
        # 文件哈希/空目录标记) 串联再哈希，空目录与「只含空子目录」两种形态可区分
        rows = [(e["path"], "file", e["sha256"]) for e in entries]
        rows += [(r, "dir", "-") for r in dir_rows]
        rows += [(r, "link", "-") for r in links]
        for rel, kind, mark in sorted(rows):
            total.update(f"{rel}\t{kind}\t{mark}\n".encode("utf-8"))
        payload = {
            "path": str(path.resolve()),
            "kind": "directory",
            "sha256": total.hexdigest(),
            "file_count": len(entries),
            "files": entries,
        }
        if links:
            payload["links"] = sorted(links)
        if unstable:
            payload["unstable"] = True
            payload["unstable_files"] = sorted(unstable)
        _emit(payload, args)
        return 3 if unstable else 0
    raise SystemExit(f"not a file or directory: {path}")


def _emit(payload: dict, args) -> None:
    text = json.dumps(payload, ensure_ascii=False, indent=2)
    if args.out:
        dest = Path(args.out)
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(text + "\n", encoding="utf-8")
        print(f"written: {dest} ({dest.stat().st_size} bytes)")
    print(text)


if __name__ == "__main__":
    sys.exit(main())
