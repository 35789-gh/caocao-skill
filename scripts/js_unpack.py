#!/usr/bin/env python3
"""js_unpack.py — 前端 bundle 程序化解包（混淆是机器变换，先用程序变回去，模型只读还原产物）。

候选哲学与 auto_chain_scan.py 同构：产物只是素材（candidate_only），不顶五套硬账，
接口清单仍以 js-collection.json 为准；解不动 ≠ 不完成，unresolved 分类落账 + 运行态
hook（scripts/vis-tools/hook-capture.js）对账补面。

四步（对每个 bundle）：
  1. sourcemap 探测：.map 同名件 / sourceMappingURL 注释；sourcesContent 在 → 直接还原源码树。
  2. 混淆特征检测：hex/unicode 转义密度、字符串数组、webpack 模块表、obfuscator.io 特征。
  3. webcrack 可用（npx --no-install 探测，绝不联网装包）→ 交给 webcrack；不可用 → 自带
     fallback：webpack 模块平衡扫描切分 + 字符串字面量明文转储（strings.txt）。
  4. 加密 API 字面量扫描 → key-bindings.json（candidate，由模型逐条核对确认）。

安全边界：本脚本不执行任何目标 JS（webcrack 本体是静态 AST 工具）；产物落 --out 目录。
用法:
  py -3 scripts/js_unpack.py --root <前端目录> --out 01-guo-jia
  py -3 scripts/js_unpack.py --bundle <单个.js> --out 09-si-ma-yi
产出:
  <out>/js-unpacked/<bundle>/...   还原产物（sourcemap 源码树 / modules/ / strings.txt）
  <out>/deobf-report.json          机械账（还原计数 + unresolved 分类）
  <out>/key-bindings.json          加密 key 候选（candidate）
"""
from __future__ import annotations
import sys
sys.dont_write_bytecode = True  # 禁 pyc 落包目录（包卫生，同 auto_chain_scan）

import argparse
import json
import re
import shutil
import subprocess
from pathlib import Path

BUNDLE_MIN_BYTES = 100_000        # 超过视为打包产物（src 明文小文件不进管线）
STRINGS_MIN_LEN = 4
STRINGS_CAP = 5000
SCAN_EXT = {".js", ".mjs", ".cjs"}
SKIP_DIRS = {".git", "node_modules", "vendor", "dist_backup", "__pycache__"}

RE_SOURCEURL = re.compile(r"//[#@]\s*sourceMappingURL=(\S+)\s*$", re.M)
RE_MODULE_KEY = re.compile(r'(?:"([A-Za-z0-9_\-/.]+)"|(\d+))\s*:\s*(function\s*\(|\(|async\s+function|\w+\s*=>)')
RE_WEBPACK = re.compile(r"__webpack_require__|webpackChunk|__NEXT_DATA__|window\.webpackJsonp")
RE_OBF_IO = re.compile(r"while\s*\(\s*!!\[\]\s*\)|_0x[0-9a-f]{4,6}")
RE_STR_ARRAY = re.compile(r"\[\s*(?:'[^']{0,120}'|\"[^\"]{0,120}\")\s*(?:,\s*(?:'[^']{0,120}'|\"[^\"]{0,120}\")\s*){49,}\]")
HEX_ESC = re.compile(r"\\x[0-9a-fA-F]{2}")
UNI_ESC = re.compile(r"\\u[0-9a-fA-F]{4}")

# 加密 API 字面量候选（kind=candidate，误报多没关系，模型逐条核对）
RE_KEY_CAND = re.compile(
    r"(?:parse|setPublicKey|setPrivateKey|setKey|genKey|encrypt|decrypt|encode|decode)"
    r"\s*\(\s*['\"]([A-Za-z0-9+/=_\-]{8,80})['\"]"
    r"|(?:key|secret|iv|salt)\s*[:=]\s*['\"]([A-Za-z0-9+/=_\-]{8,80})['\"]",
    re.I,
)


def scan_strings(text: str):
    """状态机扫描字符串字面量（跳过引号/转义/注释），解码 \\x 与 \\u。"""
    out, i, n = [], 0, len(text)
    line = 1
    while i < n:
        c = text[i]
        if c == "\n":
            line += 1
            i += 1
            continue
        if c in "'\"`":
            quote, j, buf = c, i + 1, []
            while j < n and text[j] != quote:
                if text[j] == "\\" and j + 1 < n:
                    nxt = text[j + 1]
                    if nxt == "x" and j + 3 < n:
                        try:
                            buf.append(chr(int(text[j + 2:j + 4], 16)))
                            j += 4
                            continue
                        except ValueError:
                            pass
                    if nxt == "u" and j + 5 < n:
                        try:
                            buf.append(chr(int(text[j + 2:j + 6], 16)))
                            j += 6
                            continue
                        except ValueError:
                            pass
                    buf.append(nxt)
                    j += 2
                    continue
                if text[j] == "\n":
                    line += 1
                buf.append(text[j])
                j += 1
            if j < n:  # 未闭合（模板串跨行按整体截住）也收
                out.append((line, "".join(buf)))
                i = j + 1
                continue
            i = j
            continue
        i += 1
    return out


# 2026-10-16 r16：块配对扫描上限窗口（约 1MB）。旧版无上限——「命中区在文件头 +
# 10MB 未闭合长尾」结构（webpack 信号 + 数千个失配模块键 + 超长 pad）每次命中都
# 全扫尾部，O(n²) 退化把病理样本拖到 300s 超时、--root 全批被单文件卡死。
# 正常 webpack 模块体远小于 1MB，窗口内闭不上=畸形块，放弃即可。
BAL_SCAN_WINDOW = 1_000_000


def _balanced_block(text: str, open_idx: int, limit: int = BAL_SCAN_WINDOW) -> int:
    """text[open_idx] 是 { 或 (，返回配对闭符号下标；跳过字符串与注释。失配返回 -1。

    r16：扫描不超过 open_idx+limit 的窗口（含字符串/注释内扫描）——超窗未闭合按
    失配返回 -1，防长尾结构 O(n²)。"""
    pairs = {"{": "}", "(": ")", "[": "]"}
    close_c = pairs[text[open_idx]]
    depth = 0
    i, n = open_idx, min(len(text), open_idx + limit)
    while i < n:
        c = text[i]
        if c in "'\"`":
            q = c
            i += 1
            while i < n and text[i] != q:
                if text[i] == "\\":
                    i += 1
                i += 1
            i += 1
            continue
        if c == "/" and i + 1 < n and text[i + 1] == "/":
            j = text.find("\n", i)
            i = n if j < 0 else j
            continue
        if c == "/" and i + 1 < n and text[i + 1] == "*":
            j = text.find("*/", i + 2)
            i = n if j < 0 else j + 2
            continue
        if c in "{([":
            depth += 1
        elif c in "})]":
            depth -= 1
            if depth == 0 and c == close_c:
                return i
        i += 1
    return -1


def split_webpack_modules(text: str):
    """找模块表条目（不限包裹深度：兼容 push([[id],{..}]) / webpackJsonp / 老式对象）。

    匹配 `引号key|数字key : function/箭头`，值体用平衡扫描闭合；普通对象方法误切
    的代价只是多出可读片段，无害。返回 [(module_id, body, line)]，上限 2000（同 walker）。
    """
    mods = []
    pos = 0
    while len(mods) < 2000:
        m = RE_MODULE_KEY.search(text, pos)
        if not m:
            break
        brace = text.find("{", m.end() - 1)
        if brace == -1:
            break
        end = _balanced_block(text, brace)
        if end == -1:
            # r16：失配时旧版 pos=m.end() 小步前进——「命中区在文件头 + 超长未闭合尾」
            # 每次命中全扫尾部 → O(n²)。改为跳过整个扫描窗：窗内的后续命中本就落在这个
            # 不闭合块的体内；代价 = 超 1MB 仍未闭合的畸形块之后的模块不再抢救（正常
            # 模块体远小于窗口，实际无损）。
            pos = brace + BAL_SCAN_WINDOW
            continue
        mid = m.group(1) or m.group(2)
        body = text[m.start():end + 1]
        if len(body.strip()) >= 30:  # 排除琐碎 getter
            mods.append((mid, body, text.count("\n", 0, m.start()) + 1))
        pos = end + 1
    return mods


def try_webcrack(bundle: Path, outdir: Path):
    """npx --no-install 探测 webcrack（绝不联网装包）；可用则解包。

    返回 (工具名|None, 原因|None)。2026-10-16 r16 修：Windows npm 只发布 npx.cmd
    无 npx.exe，旧版列表形式 ["npx",...] 经 CreateProcess 不解析 .cmd → 恒
    FileNotFoundError 被吞 → webcrack 分支全平台死代码且不留原因。现先 shutil.which
    解析全路径再用；which 不到/探测失败/运行失败都在 reason 里带 cause 落 report
    （tool_used 仍可为 none，但不再是"无解释的 none"）。"""
    npx = shutil.which("npx")
    if not npx:
        return None, "npx not on PATH (shutil.which)"
    try:
        probe = subprocess.run(
            [npx, "--no-install", "webcrack", "--help"],
            capture_output=True, timeout=60,
        )
        if probe.returncode != 0:
            return None, f"webcrack probe rc={probe.returncode} (npx={npx})"
    except subprocess.TimeoutExpired:
        return None, "webcrack probe timeout (60s)"
    except OSError as e:
        return None, f"npx spawn failed: {type(e).__name__}"
    try:
        run = subprocess.run(
            [npx, "--no-install", "webcrack", "-o", str(outdir / "webcrack-out"), str(bundle)],
            capture_output=True, timeout=600,
        )
        if run.returncode == 0 and (outdir / "webcrack-out").is_dir():
            return "webcrack", None
        return None, f"webcrack rc={run.returncode}, out dir missing"
    except subprocess.TimeoutExpired:
        return None, "webcrack run timeout (600s)"
    except OSError as e:
        return None, f"npx spawn failed: {type(e).__name__}"


def restore_sourcemap(bundle: Path, outdir: Path) -> str:
    """有 map 且 sourcesContent 在 → 还原源码树（不需要 vlq 解码）。

    返回 restored|present_no_content|missing|none（r16：sourceMappingURL 引用的 map
    不存在报 missing，与「压根没引用」的 none 区分）。"""
    m = RE_SOURCEURL.search(bundle.read_text(encoding="utf-8", errors="ignore"))
    map_path = None
    if m:
        cand = (bundle.parent / m.group(1)).resolve()
        if cand.is_file():
            map_path = cand
    if map_path is None and bundle.with_suffix(bundle.suffix + ".map").is_file():
        map_path = bundle.with_suffix(bundle.suffix + ".map")
    if map_path is None:
        return "missing" if m else "none"
    try:
        data = json.loads(map_path.read_text(encoding="utf-8", errors="ignore"))
    except (json.JSONDecodeError, OSError):
        return "present_no_content"
    contents = data.get("sourcesContent") or []
    sources = data.get("sources") or []
    if not any(contents):
        return "present_no_content"
    src_root = outdir / "sourcemap-sources"
    index = []
    for idx, (src, content) in enumerate(zip(sources, contents)):
        if not content:
            continue
        base = re.sub(r"[^A-Za-z0-9_\-./]", "_", src.split("?")[0]) or f"src_{idx}"
        # r16 修：只剥 "./" 前缀——旧版 lstrip("./") 按字符集剥，把 '../lib/b.js' 的
        # 前导 .. 也吞掉（'..' 恰好全由集合内字符组成），下面的 __up__ 分支成死代码
        while base.startswith("./"):
            base = base[2:]
        if ".." in base:  # 防路径穿越，拍平
            base = base.replace("../", "__up__/")
        dst = src_root / f"{idx:04d}_{base.replace('/', '__')}"
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_text(content, encoding="utf-8")
        index.append({"source": src, "written": dst.name})
    (src_root / "index.json").write_text(
        json.dumps(index, ensure_ascii=False, indent=1), encoding="utf-8")
    return "restored"


def process_bundle(bundle: Path, out_root: Path, webcrack_ok_scan: bool = True) -> dict:
    text = bundle.read_text(encoding="utf-8", errors="ignore")
    signals = {
        "bytes": bundle.stat().st_size,
        "hex_escapes": len(HEX_ESC.findall(text)),
        "unicode_escapes": len(UNI_ESC.findall(text)),
        "string_array": bool(RE_STR_ARRAY.search(text)),
        "webpack": bool(RE_WEBPACK.search(text)),
        "obfuscator_io": bool(RE_OBF_IO.search(text)),
        "module_table_hits": sum(1 for _ in RE_MODULE_KEY.finditer(text[:2_000_000])),
    }
    obfuscated = (
        signals["string_array"]
        or signals["obfuscator_io"]
        or (signals["hex_escapes"] + signals["unicode_escapes"]) > 200
    )
    entry = {
        "file": str(bundle),
        "size_bytes": signals["bytes"],
        "packer": "webpack" if signals["webpack"] else "unknown",
        "obfuscation": obfuscated,
        "signals": signals,
        "modules_total": 0,
        "modules_recovered": 0,
        "strings_count": 0,
        "sourcemap": "none",
        "tool_used": "none",
        "unresolved_by_type": {},
        "candidate_only": True,
    }
    # r16 修：stem 消毒——文件名 '...js' 在 Python<=3.13 下 stem='..'，旧版 outdir
    # 直接解析成 out_root 本身（产物散落父目录）。re.sub 消掉非法字符后再 strip('.')
    # 兜住纯点名（'..'/'.'——sub 对它们是恒等变换，必须再剥点才根除），空则 'bundle'。
    safe_stem = re.sub(r"[^\w.-]", "_", bundle.stem)[:60].strip(".")
    outdir = out_root / "js-unpacked" / (safe_stem or "bundle")
    outdir.mkdir(parents=True, exist_ok=True)

    entry["sourcemap"] = restore_sourcemap(bundle, outdir)

    tool, wc_reason = try_webcrack(bundle, outdir) if webcrack_ok_scan else (None, "webcrack scan disabled")
    if tool:
        entry["tool_used"] = tool
        entry["modules_recovered"] = sum(1 for _ in (outdir / "webcrack-out").rglob("*.js"))
        return entry
    if wc_reason:  # r16：tool_used=none 不再无解释——探测失败原因落 report
        entry["webcrack_reason"] = wc_reason

    # ---- fallback：模块切分 + 字符串明文转储（不执行任何目标 JS）----
    mods = split_webpack_modules(text) if signals["webpack"] else []
    entry["modules_total"] = len(mods)
    if mods:
        moddir = outdir / "modules"
        moddir.mkdir(parents=True, exist_ok=True)
        ok = 0
        for mid, body, line in mods:
            head = (
                f"// webpack module {mid} — 自 {bundle.name}:{line} 机械切分"
                f"（边界可能有误差；仅供检索与抽读，禁整树进模型）\n"
            )
            safe_mid = re.sub(r"[^A-Za-z0-9_\-]", "_", mid) or "mod"
            (moddir / f"{safe_mid}.js").write_text(head + body, encoding="utf-8", errors="ignore")
            ok += 1
        entry["modules_recovered"] = ok
    if obfuscated:
        entry["unresolved_by_type"]["needs_dynamic_decoder"] = 1
        entry["unresolved_by_type"]["needs_runtime_crosscheck"] = 1

    strings = scan_strings(text)
    seen, lines = set(), []
    for line_no, s in strings:
        s = s.strip()
        if len(s) < STRINGS_MIN_LEN or len(s) > 500:
            continue
        if not re.search(r"[A-Za-z0-9\u4e00-\u9fff]", s):
            continue
        if s in seen:
            continue
        seen.add(s)
        lines.append(f"{line_no}\t{s}")
        if len(lines) >= STRINGS_CAP:
            break
    if lines:
        (outdir / "strings.txt").write_text(
            "\n".join(lines), encoding="utf-8", errors="ignore")
        entry["strings_count"] = len(lines)
    return entry


def scan_key_candidates(bundles: list[Path], out_root: Path) -> list[dict]:
    hits, seen = [], set()
    for bundle in bundles:
        text = bundle.read_text(encoding="utf-8", errors="ignore")
        line_no = 1
        last_nl = 0
        for m in RE_KEY_CAND.finditer(text):
            line_no += text.count("\n", last_nl, m.start())
            last_nl = m.start()
            literal = m.group(1) or m.group(2)
            key = (str(bundle), literal)
            if key in seen:
                continue
            seen.add(key)
            hits.append({
                "candidate_only": True,
                "kind": "key_candidate",
                "file": str(bundle),
                "line": line_no,
                "literal": literal,
                "context": text[max(0, m.start() - 60):m.end() + 20].replace("\n", " ")[:160],
                "note": "程序扫出的加密 API 字面量候选——由模型逐条核对（是不是真密钥/盐/IV），"
                        "核对结论写回 key-bindings 确认段；运行态抓到的真值优先",
            })
    return hits[:500]


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--root", type=Path, help="前端工程目录（自动收集 bundle 候选）")
    ap.add_argument("--bundle", type=Path, action="append", help="指定单个/多个 bundle 文件")
    ap.add_argument("--out", type=Path, required=True, help="账与产物落点（01-guo-jia 或 09-si-ma-yi）")
    ap.add_argument("--all-files", action="store_true", help="不过 100KB 门槛，全部 js 进管（小工程用）")
    args = ap.parse_args(argv)

    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

    if not args.root and not args.bundle:
        print(json.dumps({"status": "failed", "reason": "需要 --root 或 --bundle"}, ensure_ascii=False))
        return 2
    root = args.root.resolve() if args.root else None
    if root and not root.is_dir():
        print(json.dumps({"status": "failed", "reason": f"root missing: {root}"}, ensure_ascii=False))
        return 2

    bundles: list[Path] = []
    if args.bundle:
        bundles = [b.resolve() for b in args.bundle if b.is_file()]
    else:
        for p in sorted(root.rglob("*")):
            if not p.is_file() or p.suffix.lower() not in SCAN_EXT:
                continue
            rel_parts = p.relative_to(root).parts[:-1]
            if any(part.lower() in SKIP_DIRS for part in rel_parts):
                continue
            if not args.all_files and p.stat().st_size < BUNDLE_MIN_BYTES:
                continue
            bundles.append(p)

    if not bundles:
        report = {
            "schema_version": "1.0", "candidate_only": True,
            "bundles_scanned": 0, "bundles": [], "obfuscation_any": False,
            "notes": "未收集到 bundle 候选（--all-files 可放宽 100KB 门槛）；"
                     "明文 src 源码场不强制跑本管线，直接抽接口清单。",
        }
        args.out.mkdir(parents=True, exist_ok=True)
        (args.out / "deobf-report.json").write_text(
            json.dumps(report, ensure_ascii=False, indent=1), encoding="utf-8")
        print(json.dumps({"status": "ok", "bundles": 0, "report": str(args.out / "deobf-report.json")}, ensure_ascii=False))
        return 0

    out_root = args.out
    out_root.mkdir(parents=True, exist_ok=True)
    entries = [process_bundle(b, out_root) for b in bundles]
    keys = scan_key_candidates(bundles, out_root)

    report = {
        "schema_version": "1.0",
        "candidate_only": True,
        "root": str(root) if root else None,
        "bundles_scanned": len(entries),
        "bundles": entries,
        "obfuscation_any": any(e["obfuscation"] for e in entries),
        "notes": "解包产物是素材不是账：接口清单仍以 js-collection.json 为准；"
                 "obfuscation_any=true 的场三份账（deobf-report / key-bindings / js-collection.deobf 键）"
                 "齐才算采集完成；unresolved 面由运行态 hook-capture.js 对账补面，禁死磕静态也禁解不动装完成。",
    }
    (out_root / "deobf-report.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=1), encoding="utf-8")
    if keys:
        (out_root / "key-bindings.json").write_text(
            json.dumps({
                "schema_version": "1.0",
                "candidates": keys,
                "confirmed": [],
                "note": "candidates=程序扫出待核对；confirmed=模型核对后的条目"
                        "（{literal, 用途, file:line, static_or_runtime}）。"
                        "运行态 hook 抓到的真值与静态候选同值 = 交叉验证成立。",
            }, ensure_ascii=False, indent=1), encoding="utf-8")

    print(json.dumps({
        "status": "ok",
        "bundles": len(entries),
        "obfuscation_any": report["obfuscation_any"],
        "report": str(out_root / "deobf-report.json"),
        "key_candidates": len(keys),
    }, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
