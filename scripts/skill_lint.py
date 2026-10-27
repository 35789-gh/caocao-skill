#!/usr/bin/env python3
"""skill_lint：本包防膨胀看门狗（改进蓝图承诺项，2026-10-14 修复批三落地）。

用法：py scripts/skill_lint.py [--root <包根>]（默认脚本上级目录）

检查五查：
1. 单行宽度：正文 >250 字 warn、>400 字 fail（references/ 与 scripts/vis-tools/README 已进扫描域 2026-10-15 复核批；CHANGELOG/改进蓝图不扫——历史归宿不适用门闩）；批四十四起 >400 走包根 lint-baseline.json 机械基线：首跑快照存量、行内容一改即出基线须达标、新增照 fail——「存量不追溯、触碰即达标」从自觉变可判（基线只缩不涨；删基线文件=重新快照，偷懒可见于包 diff）
2. 改号字样：正文出现「N 改 / X十Y改」历史段（应只在 CHANGELOG；precedents 判例表与 CHANGELOG 同为历史归宿页豁免）
3. 悬空引用：正文引用的 protocol/references/scripts/templates 相对路径文件必须存在
4. 包卫生：__pycache__ / *.pyc 残留（fail）；vendored node_modules（vis-tools 实战依赖，2026-10-15 记档在案）列 warn 提示核对
5. 编号存在性：H-NN / RF-XXX-NN 引用必须有定义（悬空 fail、闲置计数）

退出码：有 fail 非零；只有 warn 时为零但逐条列出。
"""
from __future__ import annotations
import json
import re
import sys
from pathlib import Path

sys.dont_write_bytecode = True

ROOT = Path(__file__).resolve().parent.parent
SCAN_FILES = [
    "SKILL.md", "README.md", "CUT-LIST.md",
    "protocol/gates.md", "protocol/report.md", "protocol/report-format.md", "protocol/website.md",
    "references/php-methodology.md", "references/deterministic-regex-and-java.md",
    "scripts/vis-tools/README.md",
] + [f"roles/{n}.md" for n in (
    "于禁", "典韦", "刘晔", "司马懿", "曹仁", "曹冲", "曹操", "曹操分身", "郭嘉",
)]  # 2026-10-16 修复批：roles 统一带 .md 完整相对路径，与 glob 增量同形态去重；main 里另有 glob 收集兜新增文件

# 2026-10-16 修复批（第 5 条）：负向环境挡动词短语误报（「再三改进/一改往常」是改进不是改号计数），
# 「第X改/已三改/三改版」照拦；原第 2/3 分支（二十X改/十八改）被第一分支完全覆盖，系死代码删除。
REV_PAT = re.compile(r"(?<![再又重])[一二三四五六七八九十]{1,3}改(?![进造良动化好得往])")
REV_EXEMPT_FILES = {"CHANGELOG.md"}  # 历史归宿页：判例/沿革含改号是本职，不查改号
# 2026-10-16 修复批（第 4 条）：字符类补 \u4e00-\u9fff（中文名文件引用入账）、扩展名集补 docx
# ——此前 templates/芋道示范.docx、plain.docx 引用根本进不了检查，EXEMPT_REF 形同死代码；
# 现已可检查，真实存在的示范 docx 由 EXEMPT_REF 豁免（语义不变：真文件本就不悬空）。
REF_PAT = re.compile(r"`?((?:protocol|references|scripts|templates)/[A-Za-z0-9_\u4e00-\u9fff\-./]+\.(?:md|py|json|js|ps1|docx))`?")
EXEMPT_REF = re.compile(r"^templates/.*芋道.*$")  # 示范 docx 同名引用不做存在性判断

BASELINE_PATH_NAME = "lint-baseline.json"


def _long_key(rel: str, line: str) -> str:
    # 批四十四：机械基线键=文件+行内容哈希——行内容一改即出基线须达标（触碰即达标机械化），
    # 行位置移动不改内容仍算存量；基线只覆盖行宽一查，其余四查全量 fail 不豁免。
    # 2026-10-16 修复批：roles 扫描项统一为带 .md 完整路径后，键在此归一回批四十四快照的
    # 旧形态（roles/xxx.md → roles/xxx）——保既有基线兼容，不改写包根 lint-baseline.json。
    if rel.startswith("roles/") and rel.endswith(".md"):
        rel = rel[: -len(".md")]
    import hashlib
    return f"{rel}::{hashlib.sha256(line.strip().encode('utf-8')).hexdigest()[:16]}"

# 2026-10-14 修复批五（第五轮审查）：编号存在性检查——位置性规则 ID（H-NN / RF-XXX-NN）在序列
# 中间插入会让后续编号全漂、既有引用全断，此前只靠人工审查一轮、无机器闸。定义=表格行首格；
# 引用但未定义=悬空 fail；定义但从未被引用=闲置 warn（含定义行自身外零出现）。
ID_DEF_PAT = re.compile(r"^\|\s*(H-\d{2}|RF-[A-Z]{2,6}-\d{2})\s*\|", re.M)
ID_REF_PAT = re.compile(r"\b(H-\d{2}|RF-[A-Z]{2,6}-\d{2})\b")


def _usage() -> str:
    return "用法: py scripts/skill_lint.py [--root <包根>]（默认脚本上级目录；-h/--help 显示本说明不触发扫描）"


# 2026-10-16 修复批（第 1 条）：--root 此前只是 docstring 声称、实际被静默忽略照扫真包——
# 现手解析 sys.argv（保持零依赖），--help 只出用法；未知参数/缺参数/根不存在报错退出不扫描。
def _parse_root_argv(argv: list[str]) -> int | None:
    """解析 --root[-=x]/-h/--help；返回 None 放行、int 直接以该码退出（help=0、参数/根错误=2）。副作用：命中 --root 时改写全局 ROOT。"""
    global ROOT
    i = 0
    override: str | None = None
    while i < len(argv):
        a = argv[i]
        if a in ("-h", "--help"):
            print(_usage())
            return 0
        if a == "--root":
            if i + 1 >= len(argv):
                print(f"错误: --root 缺参数。{_usage()}", file=sys.stderr)
                return 2
            override = argv[i + 1]
            i += 2
            continue
        if a.startswith("--root="):
            override = a.split("=", 1)[1]
            i += 1
            continue
        print(f"错误: 未知参数 {a}。{_usage()}", file=sys.stderr)
        return 2
    if override is not None:
        ROOT = Path(override).resolve()
    if not ROOT.is_dir():
        print(f"错误: 包根不存在: {ROOT}", file=sys.stderr)
        return 2
    return None


def _collect_scan_files() -> list[str]:
    # 2026-10-16 修复批（第 6 条）：静态清单 + glob 增量（protocol/**\/*.md、roles\/*.md）——
    # 新增角色页/协议页此前零告警漏扫；豁免文件逻辑（REV_EXEMPT_FILES 等）按相对路径匹配不受影响。
    rels = list(SCAN_FILES)
    rels += [p.relative_to(ROOT).as_posix() for p in (ROOT / "protocol").rglob("*.md")]
    rels += [p.relative_to(ROOT).as_posix() for p in (ROOT / "roles").glob("*.md")]
    seen: set[str] = set()
    out: list[str] = []
    for r in rels:
        if r not in seen:
            seen.add(r)
            out.append(r)
    return out


def main() -> int:
    rc = _parse_root_argv(sys.argv[1:])
    if rc is not None:
        return rc
    scan_files = _collect_scan_files()
    fails: list[str] = []
    warns: list[str] = []
    texts: dict[str, str] = {}
    long_over: dict[str, str] = {}
    for rel in scan_files:
        p = ROOT / (rel if rel.endswith(".md") else rel + ".md")
        if not p.is_file():
            fails.append(f"缺文件: {rel}")
            continue
        text = p.read_text(encoding="utf-8")
        # 2026-10-15 批十二：CRLF 去污——本包全文 CRLF，路径捕获组尾部会粘 \r，
        # 导致悬空引用检查把「存在」判成「不存在」（探针实测：真悬空漏报、假悬空误报皆可能）。
        # 行宽/改号不受 \r 实质影响（\r 只加 1 字符），统一在读入后剥离。
        text = text.replace("\r\n", "\n")
        texts[rel] = text
        for i, line in enumerate(text.splitlines(), 1):
            if len(line) > 400:
                long_over[_long_key(rel, line)] = f"{rel}:{i} 单行 {len(line)} 字（>400 硬上限，拆子列表；存量行认 lint-baseline.json）"
            elif len(line) > 250:
                warns.append(f"{rel}:{i} 单行 {len(line)} 字（>250 软上限）")
            if REV_PAT.search(line) and rel not in REV_EXEMPT_FILES:
                fails.append(f"{rel}:{i} 正文含改号字样「{REV_PAT.search(line).group()}」——历史只许进 CHANGELOG")
        for m in REF_PAT.finditer(text):
            ref = m.group(1)
            if EXEMPT_REF.search(ref):
                continue
            if ref.startswith("scripts/") and not ref.endswith((".py", ".js", ".ps1")):
                continue
            if not (ROOT / ref).is_file():
                fails.append(f"{rel} 悬空引用: {ref}")
    # 批四十四：超宽行机械基线——首跑快照存量（祖父条款落盘），此后只 fail 新增/改写行；
    # 已修复/已改写的存量行自动出基线（基线只缩不涨，新增违规永不入基线）
    baseline_path = ROOT / BASELINE_PATH_NAME
    try:
        _bd = json.loads(baseline_path.read_text(encoding="utf-8")) if baseline_path.is_file() else None
    except Exception:
        _bd = None
    base_keys = set(_bd.get("keys") or []) if isinstance(_bd, dict) else None
    cur_keys = set(long_over)
    if base_keys is None:
        baseline_path.write_text(
            json.dumps({"_说明": "批四十四首跑快照：存量超宽行（祖父条款机械落盘）；只缩不涨，删本文件=重新快照", "keys": sorted(cur_keys)}, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        baseline_note = f"baseline_created({len(cur_keys)} 条存量入基线，此后新增/改写行照 fail)"
    else:
        new_keys = cur_keys - base_keys
        kept = base_keys & cur_keys
        shrunk = base_keys - cur_keys
        if shrunk:
            baseline_path.write_text(
                json.dumps({"_说明": "批四十四：存量超宽行基线（只缩不涨；每次运行自动收缩已达标行）", "keys": sorted(kept)}, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )
        for k in sorted(new_keys):
            fails.append(long_over[k])
        baseline_note = f"baseline(kept {len(kept)} / new {len(new_keys)} / shrunk {len(shrunk)})"
    # 编号存在性（第五查）：先收定义（表格行首格），再扫全部引用
    # 2026-10-16 修复批（第 2 条）：定义只认规则承载文件（SKILL/protocol/roles）——
    # README/templates 的「| H-NN |」示例表格不再算定义，堵住洗白悬空引用的口子
    def _is_def_carrier(rel: str) -> bool:
        return rel == "SKILL.md" or rel.startswith(("protocol/", "roles/"))

    id_defs: dict[str, int] = {}
    for rel, text in texts.items():
        if not _is_def_carrier(rel):
            continue
        for m in ID_DEF_PAT.finditer(text):
            id_defs[m.group(1)] = id_defs.get(m.group(1), 0) + 1
    id_refs: dict[str, list[str]] = {}
    for rel, text in texts.items():
        for i, line in enumerate(text.splitlines(), 1):
            # 2026-10-16 修复批（第 3 条）：定义行不再整行 continue——剥掉行首「| H-NN |」首格后
            # 对其余部分照收引用（定义行里引用的 H-77 不再被吞；自引用天然有定义不误报）
            dm = ID_DEF_PAT.match(line)
            body = line[dm.end():] if dm else line
            for m in ID_REF_PAT.finditer(body):
                id_refs.setdefault(m.group(1), []).append(f"{rel}:{i}")
    for rid, locs in sorted(id_refs.items()):
        if rid not in id_defs:
            fails.append(f"编号悬空: {rid}（被引用于 {locs[0]} 等 {len(locs)} 处，无定义——编号漂移或笔误）")
    idle_ids = [rid for rid in sorted(id_defs) if rid not in id_refs]
    # 批四十（红队六轮 P2-11）：条文↔机械件 parity 简版——正文行声称「机械拦/机械核/机械件已合入」
    # 时，同行命中的规则 ID（H-NN/RF-XXX-NN）或批次号（批三十…批四十）必须能在 scripts/*.py
    # 源码里找到锚（check 函数 docstring 均带批次锚）——防「正文承诺、实装缺失」
    # （批三十八 baseline_sent_at 就是现成事故：条文写了闸不查）
    mech_src = ""
    for sp in sorted((ROOT / "scripts").glob("*.py")):
        try:
            mech_src += sp.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
    MECH_CLAIM_PAT = re.compile(r"机械拦|机械核|机械件|闸机械|已合入闸|闸核")
    BATCH_PAT = re.compile(r"批(?:三十[一二三四五六七八九]?|四十)")
    for rel, text in texts.items():
        for i, line in enumerate(text.splitlines(), 1):
            claimed: set[str] = set()
            for mc in MECH_CLAIM_PAT.finditer(line):
                # 只核机械声称词前后 40 字窗口内的 ID/批次锚——整行收集会把同行的纯条文 ID 牵连误报
                window = line[max(0, mc.start() - 40): mc.end() + 40]
                claimed.update(ID_REF_PAT.findall(window))
                claimed.update(m.group() for m in BATCH_PAT.finditer(window))
            if not claimed:
                continue
            missing = [a for a in sorted(claimed) if a not in mech_src]
            if missing:
                fails.append(
                    f"{rel}:{i} parity：声称机械件（{','.join(missing)}）在 scripts/*.py 源码无锚"
                    "——正文承诺实装缺失或锚字样写错（批四十 P2-11；check docstring 须带批次/规则 ID 锚）"
                )
    junk = [str(p.relative_to(ROOT)) for p in ROOT.rglob("__pycache__")]
    junk += [str(p.relative_to(ROOT)) for p in ROOT.rglob("*.pyc")]
    if junk:
        fails.append(f"包卫生: {' '.join(junk)}")
    # 2026-10-15 二轮复核：vendored node_modules 记档在案（vis-tools 实战依赖，playwright-core）——
    # 列 warn 提示核对记档仍在，不 fail（移除会打断 hook-capture/drive 开箱即用）
    for nm in ROOT.rglob("node_modules"):
        warns.append(f"vendored node_modules（已记档，核对 CHANGELOG 复核批）: {nm.relative_to(ROOT)}")
    print(json.dumps({
        "status": "failed" if fails else "passed",
        "fails": fails,
        "warns": warns,
        "long_line_baseline": baseline_note,
        "idle_rule_ids": len(idle_ids),
        "idle_note": "定义未引用的规则 ID 计数（按需读页的正常态——整页通读用不上跳转；只在做废清扫时参考，不告警）",
        "checked_files": len(scan_files),
    }, ensure_ascii=False, indent=2))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
