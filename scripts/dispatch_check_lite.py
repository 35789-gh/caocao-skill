#!/usr/bin/env python3
"""Mini dispatch gate. Existence and fields only. No sha256 theatre."""
from __future__ import annotations
import sys
sys.dont_write_bytecode = True  # 2026-10-13 新6: 禁 pyc 落包目录（包卫生）

import argparse
import json
import re
import sys
from pathlib import Path

ROLE_DIRS = {
    "guo-jia": "01-guo-jia",
    "cao-cao": "02-cao-cao",
    "cao-cao-shadow": "02-cao-cao-shadow",
    "cao-chong": "03-cao-chong",
    "cao-ren": "04-cao-ren",
    "liu-ye": "05-liu-ye",
    "yu-jin": "06-yu-jin",
    "dian-wei": "08-dian-wei",
    "sima-yi": "09-si-ma-yi",
}

# 2026-10-13 C13 修：错号目录从枚举黑名单改为通用拦截——合法角色目录白名单（含无编号公共目录）之外，
# 任何 NN-拼音 形态的根目录都判错号（SKILL「错号=失败」是普适规则，黑名单只拦已见错法）
VALID_ROOT_DIRS = {
    "01-guo-jia", "02-cao-cao", "02-cao-cao-shadow", "03-cao-chong", "04-cao-ren",
    "05-liu-ye", "06-yu-jin", "08-dian-wei", "09-si-ma-yi",
    "run", "reports", "delivery", "materials", "env", "cors-audit", "docs", "assets",
}
import re as _re_c13
# 2026-10-16 修6：目录号拦截从黑名单式（只认 `^\d{2}-[a-z][a-z-]*$` 标准两位小写形态，
# 9-cao-cao/010-guo-jia/08-Dian-wei/01-guo-jia-2 全放行）改白名单式——
# 凡「数字-」开头的根目录都是角色目录形态，不在 VALID_ROOT_DIRS 白名单内一律判错号；
# run/reports 等无编号公共目录不以「数字-」开头，不受影响
ROLE_LIKE_ROOT_PAT = _re_c13.compile(r"^\d+-")

# 2026-10-16 修2：口令原文检测键名集扩 pwd|passwd|pass|密码|secret|token（大小写不敏感），
# 等号类补全角＝（U+FF1D；全角：原本就有）；ASCII 键加 \b 防 compass= 这类子串误伤
SECRET_KEY_NAMES = r"(?:\b(?:password|passwd|pwd|pass|secret|token)\b|密码|口令)"
SECRETISH = re.compile(
    r"(?:" + SECRET_KEY_NAMES + r"|encryptHex|SmImpl|万能密码)\s*[=/:：＝]\s*\S+",
    re.I,
)
# 「键出现但无赋值」（password 与值分写两步形态）→ 不硬拦，note 级告警人工核
SECRET_KEY_BARE = re.compile(SECRET_KEY_NAMES, re.I)
SIMA_LEAK = re.compile(
    r"encryptHex|SmImpl|CH-GJ-|候选索引|万能密码|Base64\.decode|b64decode|decodebase64",
    re.I,
)
# 2026-10-16 修5③：旧 `^agent_[0-9a-fA-F-]{8,}$` 放行 agent_--------/agent_00000000/agent_-abc-def0——
# 收紧为 UUID 形态（真实平台 id 形如 agent_65442a4d-eaf5-444c-a980-e29c53e3f97f）；
# 另兼容无连字符 16 位 hex 短 id 形态（现行契约 fixture 即此形态，见 D1）
AGENT_RE = re.compile(
    r"^agent_(?:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|[0-9a-f]{16})$",
    re.I,
)


def sima_leak_word(text: str) -> str | None:
    """2026-10-16 修4：对去空白副本匹配——`Base64 . decode`、`候选 索引` 插空格绕过不再放行。"""
    squeezed = re.sub(r"\s+", "", text)
    m = SIMA_LEAK.search(squeezed)
    return m.group(0) if m else None


def load_json(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        raise SystemExit(f"FAIL json {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise SystemExit(f"FAIL {path} is not an object")
    return data


def fail(msg: str) -> None:
    print(json.dumps({"status": "failed", "reason": msg}, ensure_ascii=False, indent=2))
    raise SystemExit(1)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-root", required=True)
    parser.add_argument("--role", required=True, choices=sorted(ROLE_DIRS))
    args = parser.parse_args()
    run_root = Path(args.run_root)
    role = args.role
    if not run_root.is_dir():
        fail(f"run_root missing: {run_root}")

    for name in sorted(d.name for d in run_root.iterdir() if d.is_dir()):
        # 2026-10-13 C13：通用错号拦截——NN-拼音 形态且不在合法白名单内的根目录全部判错
        # 2026-10-16 修6：黑名单式（只认标准两位小写形态）→白名单式，「数字-」开头即受检
        if ROLE_LIKE_ROOT_PAT.match(name) and name not in VALID_ROOT_DIRS:
            fail(f"wrong role dir on disk: {name}（合法角色目录见 VALID_ROOT_DIRS；错号=失败普适规则）")

    agents = run_root / "run" / "agents"
    dispatch_p = agents / f"{role}-dispatch.json"
    launch_p = agents / f"{role}-launch.json"
    ack_p = agents / f"{role}-read-ack.json"
    for p in (dispatch_p, launch_p, ack_p):
        if not p.is_file():
            fail(f"missing {p.relative_to(run_root)}")

    dispatch = load_json(dispatch_p)
    launch = load_json(launch_p)
    ack = load_json(ack_p)

    steps = dispatch.get("duty_steps")
    if not isinstance(steps, list) or not steps or not all(isinstance(x, str) and x.strip() for x in steps):
        fail("dispatch.duty_steps must be a non-empty string list")
    if role == "cao-cao-shadow":
        blob_steps = "\n".join(steps)
        banned = ("执行摘要", "三级 finding", "三级表", "BEC 台账", "闭环矩阵", "一、身份", "结案表")
        hits = []
        for step in steps:
            # 2026-10-13 新4 修：判决步只豁免「结案表」一词（判决段天然要描述封存/结案表流转）——
            # 2026-10-13 新8 修：旧版整步 continue 可被拼接利用（「出卷判决后再出一、身份结案表台账」整步放行）
            # 2026-10-14 修：新8 的整步 continue 没删干净（step 含任一禁止词仍跳过全部 banned 检查，
            # 「出一、身份结案表，不得外传」可绕过），且循环内的 step 级豁免同样过宽——两处统一降为
            # 短语级：禁止词出现在 banned 词紧邻窗口（前 6 字符）内才豁免该词，远处的「不得外传」不豁免任何词；
            # verdict 步对「结案表」的豁免照旧
            is_verdict_step = any(x in step for x in ("delivery-verdict", "出卷判决", "判决三段"))
            for k in banned:
                if k not in step:
                    continue
                # 2026-10-14 修复批三：any→all——同一违规词出现多次时，必须**每一次**出现都在紧邻否定窗口内
                # 才豁免；「禁止出结案表；随后照常生成结案表归档」这类一否定一正常的拼接不再放行。
                # 窗口保持 6 字的取舍：扩大窗口（如 12 字）会把「不要浪费时间，先出一、身份结案表」重新放开，
                # 误拦的代价只是改写措辞重派（fail-closed），漏放的代价是假检查过关——取 fail-closed。
                negated = all(
                    any(w in step[max(0, m.start() - 6):m.start()] for w in ("禁止", "不要", "不得", "不准"))
                    for m in re.finditer(re.escape(k), step)
                )
                if negated:
                    continue
                if is_verdict_step and k == "结案表":
                    continue
                hits.append(k)
        if hits:
            fail("cao-cao-shadow duty_steps 在派结案表/台账，必须派正式 8 块通报：" + ",".join(sorted(set(hits))))
        needed = ("目标网站URL", "漏洞描述", "漏洞危害", "涉及接口", "复现", "修复")
        # 2026-10-16 修1：any→all——旧版 6 个必点词只出现 1 个也放行，点名检查目的失效；
        # fail 文案列出缺失的块名
        missing = [k for k in needed if k not in blob_steps]
        if missing:
            fail(
                "cao-cao-shadow duty_steps 必须点名 8 块（目标网站URL/描述/危害/接口/复现/修复），缺块："
                + "、".join(missing)
            )
        # 2026-10-13 B4 修：九要素新标补查——任务书须含「软件与厂商信息」块
        if "厂商" not in blob_steps and "软件与厂商信息" not in blob_steps:
            fail("任务书缺「软件与厂商信息」块（2026-10-13 九要素：重写/新审计线任务书必备）")
        if "出卷判决" not in blob_steps and "delivery-verdict" not in blob_steps:
            fail("cao-cao-shadow duty_steps 必须点名出卷判决（先交 02-cao-cao-shadow/delivery-verdict.json 三段，曹操逐点回应后才排版）")

    # 2026-10-16 修5：agent_id 三缺口——①dispatch 与 launch 都有但不等 → fail（旧版 or 取先到者不查不一致）；
    # ②read-ack 缺 agent_id → fail（旧版 `if ack.get(...)` 把缺键当放行）；③正则收紧见 AGENT_RE
    dispatch_aid = dispatch.get("agent_id")
    launch_aid = launch.get("agent_id")
    if isinstance(dispatch_aid, str) and isinstance(launch_aid, str) and dispatch_aid != launch_aid:
        fail("dispatch.agent_id != launch.agent_id")
    agent_id = dispatch_aid or launch_aid
    if not isinstance(agent_id, str) or not AGENT_RE.match(agent_id):
        fail("agent_id must be platform-like agent_<uuid>")
    ack_aid = ack.get("agent_id")
    if not isinstance(ack_aid, str) or not ack_aid.strip():
        fail("read_ack.agent_id missing（read-ack 必须带回 agent_id）")
    if ack_aid != agent_id:
        fail("read_ack.agent_id != dispatch/launch agent_id")

    if dispatch.get("role") not in (None, role):
        fail("dispatch.role mismatch")

    # 2026-10-16 修3：口令原文与 SIMA_LEAK 检查从只扫 dispatch 扩到三件套（dispatch/launch/read-ack），
    # 复用同一检测函数，fail/note 注明出自哪个文件（旧版 launch.note / read-ack 里 password=admin123 照样 passed）
    warnings: list[str] = []
    for fname, obj in (("dispatch", dispatch), ("launch", launch), ("read-ack", ack)):
        fblob = json.dumps(obj, ensure_ascii=False)
        if SECRETISH.search(fblob):
            fail(f"{fname} looks like it contains a secret value; use credential_ref only")
        if SECRET_KEY_BARE.search(fblob):
            warnings.append(f"{fname}: 口令键出现未带值，人工核")
        if role == "sima-yi":
            leak = sima_leak_word(fblob)
            if leak:
                fail(f"sima-yi {fname} contains Guo Jia answers: {leak}")

    blob = json.dumps(dispatch, ensure_ascii=False)

    creds = re.findall(r"credential_ref:([^\s\"']+)", blob)
    for ref in creds:
        path = ref.split("#", 1)[0]
        if path.startswith("01-guo-jia/") and role == "sima-yi":
            fail("sima-yi credential_ref must not point at 01-guo-jia/")

    role_dir = run_root / ROLE_DIRS[role]
    # run roles should exist after dispatch; lite check only warns via stdout if missing
    out = {
        "status": "passed",
        "role": role,
        "agent_id": agent_id,
        "checked_agents": {role: {"agent_id": agent_id, "status": "passed"}},
        "role_dir": ROLE_DIRS[role],
        "role_dir_exists": role_dir.is_dir(),
        "hash_required": False,
        "note": "lite gate: no sha256 fields required",
    }
    # 2026-10-16 修2：note 级告警落账（口令键出现未带值——分写两步形态，人工核）
    if warnings:
        out["warnings"] = warnings
    stdout_path = agents / f"dispatch-check-{role}.json"
    stdout_path.write_text(json.dumps(out, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(out, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as exc:  # noqa: BLE001
        print(json.dumps({"status": "failed", "reason": str(exc)}, ensure_ascii=False, indent=2))
        sys.exit(1)
