# -*- coding: utf-8 -*-
"""make_canonical.py（批三十九）：生成/刷新 canonical 根 gates-canonical.json（默认包根，可用环境变量 CAOCAO_CANONICAL_ROOT 指到包外由用户保管）。

用途：闸与检查器的「闸外对照物」——开局外发值对「开局前改闸」自洽（外发的就是假闸哈希），
canonical 由用户保管在包外，hard_gate env/close 双相比对（era≥20261016），漂移即 fail。

何时跑：①本包任何 scripts/tools.json/v7 credential_scan 变更合入后（用户批的合规改闸）；
②canonical 丢失/损坏时重建。跑完在 CHANGELOG 记一行。

边界（如实记档，不假装能拦）：本文件与 canonical 同盘同权限，恶意模型可改闸+改 canonical 一次到位——
机械层真根止步于「便利对照+开局后防漂移」；绝对根 = 用户把生成后 canonical 文件的 sha256
抄录到聊天外（纸质/手机），对账时以抄录值为准（模型改不了已发出的消息与用户口袋）。

用法：py -3 scripts/make_canonical.py [--check]
  --check：不写文件，只比对现有 canonical 与当前哈希（CI 自检用，漂移 exit 1）
"""
import hashlib
import json
import sys
import os
import datetime
from pathlib import Path

BASE = Path(__file__).resolve().parent
CANON = Path(os.environ.get("CAOCAO_CANONICAL_ROOT") or str(BASE.parent / "gates-canonical.json"))
# 键集与 hard_gate._tool_baseline_now() 对齐（CHECKER_BASELINE_FILES + tools.json + credential_scan）
FILES = (
    "hard_gate.py",
    "dispatch_check_lite.py",
    "vision_gate.py",
    "vision_review.py",
    "check_finding.py",
    "auto_chain_scan.py",
    "hybrid_discovery.py",
    "js_unpack.py",
    "material_hash.py",
    "make_canonical.py",
    # 批六十一①：vis-tools 拍摄族与 CHECKER_BASELINE_FILES 同锚（开局前改 snapchrome 同样要炸）
    "vis-tools/cmdsend-any.ps1",
    "vis-tools/snapchrome.ps1",
    "vis-tools/snapwin.ps1",
    "vis-tools/snapdual.ps1",
    "vis-tools/shotlock.py",
    "vis-tools/who9222.py",
    "vis-tools/record-page.js",
    "vis-tools/drive.js",
    "vis-tools/send-shot-gate.sh",
)


def _now() -> dict:
    out: dict = {}
    for name in FILES:
        p = BASE / name
        if p.is_file():
            out[name] = hashlib.sha256(p.read_bytes()).hexdigest()
    tj = BASE.parent / "tools.json"
    if tj.is_file():
        out["tools.json"] = hashlib.sha256(tj.read_bytes()).hexdigest()
    pkgcred = BASE / "credential_scan.py"
    if pkgcred.is_file():
        out["credential_scan.py"] = hashlib.sha256(pkgcred.read_bytes()).hexdigest()
    return out


def main() -> int:
    cur = _now()
    if "--check" in sys.argv:
        if not CANON.is_file():
            print(json.dumps({"status": "missing", "path": str(CANON)}, ensure_ascii=False))
            return 1
        old = json.loads(CANON.read_text(encoding="utf-8")).get("files") or {}
        drift = sorted(k for k in set(old) | set(cur) if str(old.get(k) or "") != str(cur.get(k) or ""))
        print(json.dumps({"status": "drift" if drift else "ok", "drift": drift}, ensure_ascii=False))
        return 1 if drift else 0
    body = {
        "generated_at": datetime.datetime.now().astimezone().isoformat(timespec="seconds"),
        "package": str(BASE.parent),
        "files": cur,
        "self_note": "批三十九 canonical 根：hard_gate env/close 比对本件；模型禁写本文件（信任根纪律见 README）。"
        "用户保管义务：生成后把本文件 sha256 抄录到聊天外（纸质/手机）——同盘同权限可被改，"
        "抄录值才是绝对根。",
    }
    CANON.parent.mkdir(parents=True, exist_ok=True)
    CANON.write_text(json.dumps(body, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    digest = hashlib.sha256(CANON.read_bytes()).hexdigest()
    print(
        json.dumps(
            {"status": "written", "path": str(CANON), "files": len(cur), "canonical_sha256": digest},
            ensure_ascii=False,
            indent=2,
        )
    )
    print(">>> 把 canonical_sha256 抄到聊天外保存（纸质/手机）：", digest)
    return 0


if __name__ == "__main__":
    sys.exit(main())
