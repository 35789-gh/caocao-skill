#!/usr/bin/env python3
"""写时自检：角色落盘 finding / 签字件后当场跑，写完 10 秒内发现字段问题，不等 close 挨批。

用法：
    py scripts/check_finding.py <json路径> [--run-root <场根>]

键名速查（三个语境三套键，别混用——2026-10-08 手续改良）：
    finding/签字件结论键 → status（闸也认 finding_status/final_status；verdict/verdict_now/result 都不认）
    验证计划行的结果键 → result / verdict（verdict_now 只是排期初判，不算）
    分身出卷判决      → 文件名 02-cao-cao-shadow/delivery-verdict.json（认文件不认键）

词表不自带——直接 import hard_gate（同一出处，闸改了自检自动跟着变）。
对应闸检查：hard_gate.check_verified_evidence（结论键、evidence 路径、类型配套证据）。

⚠ 免责（2026-10-15 批十一）：本工具只查 finding JSON 的字段与证据路径，
**不覆盖录屏/视频义务、复杂链录像、确认件哈希绑定**——那些在 hard_gate
verify/close 全闸里（check_complex_video / check_recording_integrity /
check_vision_report_images）。过了本工具 ≠ 过闸，收口必须跑 hard_gate close。
"""
import argparse
import json
import sys
from pathlib import Path

sys.dont_write_bytecode = True  # 2026-10-13 新6: 禁 pyc 落包目录（包卫生）
sys.path.insert(0, str(Path(__file__).parent))
import hard_gate as hg  # noqa: E402

# 闸黑名单同款：这些键不当作结论键（hard_gate.py 顶部 verdict.json / verdict_now 条目）
WRONG_KEYS = ("verdict", "verdict_now", "result", "final_result")


def status_of(cur: dict) -> str:
    return str(cur.get("status") or cur.get("finding_status") or cur.get("final_status") or "").lower()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("json_path")
    parser.add_argument("--run-root", default=None, help="场根（evidence 相对路径的基准）")
    args = parser.parse_args()

    path = Path(args.json_path)
    run_root = Path(args.run_root).resolve() if args.run_root else path.parent
    problems: list[str] = []

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        print(json.dumps({"status": "failed", "problems": [f"不是合法 JSON: {exc}"]}, ensure_ascii=False, indent=2))
        return 1

    dicts = list(hg.walk_dicts(data)) if data else []
    if not dicts:
        problems.append("没有任何对象节点——照 templates/finding.json 的结构写")

    for cur in dicts:
        # 闸黑名单同款：这些键不当作结论键（hard_gate.py 顶部 verdict.json / verdict_now 条目）。
        # 只在「该 dict 没有正经结论键、且错误键的值本身就是结论词」时报——嵌套验证块里
        # {'result': '200 OK'} 这类步骤值合法（闸不看无 status 的嵌套 dict），不报。
        CONCLUSION_WORDS = {"verified", "suspected", "eliminated", "disproved"}
        has_proper = any(k in cur for k in ("status", "finding_status", "final_status"))
        if not has_proper:
            for wk in WRONG_KEYS:
                v = cur.get(wk)
                if isinstance(v, str) and v.strip().lower() in CONCLUSION_WORDS:
                    problems.append(f"该对象没有 status/finding_status/final_status，结论写在了闸不认的 '{wk}' 里——结论键只用 status")
                    break
        if status_of(cur) != "verified":
            continue
        ftype = hg.finding_type(cur)
        if "cors" in ftype:
            problems.append("verified 类型是 CORS，不得进正式结论（CORS 只进 cors-audit/）")
        evid = cur.get("evidence") or cur.get("evidence_paths") or cur.get("evidence_dir")
        files = [x for x in (evid if isinstance(evid, list) else [evid]) if isinstance(x, str)] if evid else []
        if not files:
            problems.append("status=verified 但没有 evidence 路径")
            continue
        has_image = has_text = False
        for item in files:
            f = hg.resolve_inside(run_root, item, "verified.evidence")
            if not f.exists():
                problems.append(f"evidence 不存在: {item}")
                continue
            if f.is_dir():
                kids = [k for k in f.rglob("*") if k.is_file()]
                if not kids:
                    problems.append(f"evidence 目录为空: {item}")
                for k in kids:
                    # 2026-10-16 修12：目录分支旧版跳过 png magic 检查（假图混进目录漏检）——
                    # 目录内 *.png 逐个过与单文件分支同款的图像头检查；非 png 文件不要求
                    if k.suffix.lower() in hg.IMAGE_EXT:
                        if hg.is_real_image(k):
                            has_image = True
                        else:
                            problems.append(f"evidence 图没有图像文件头: {item}/{k.relative_to(f).as_posix()}")
                    if k.suffix.lower() not in hg.IMAGE_EXT | hg.VIDEO_EXT and k.stat().st_size >= 40:
                        has_text = True
            elif f.is_file():
                if f.suffix.lower() in hg.IMAGE_EXT:
                    if hg.is_real_image(f):
                        has_image = True
                    else:
                        problems.append(f"evidence 图没有图像文件头: {item}")
                elif f.stat().st_size >= 40:
                    has_text = True
        if "xss" in ftype and not has_image:
            problems.append("XSS verified 必须有弹窗/渲染原图")
        if any(x in ftype for x in ("rce", "command", "ssti", "deserialize")) and not has_text:
            problems.append("RCE verified 必须有命令/文件执行落盘，不能只靠截图")
        if any(x in ftype for x in ("idor", "越权", "broken access")) and not has_text:
            problems.append("越权 verified 必须有他者数据回包")
        # SQL 库侧真值比对（2026-10-09 判例）：与 hard_gate.check_verified_evidence 同源同拦
        # 模板/SpEL/XSS/XXE/命令类「注入」属别行，排除防误伤
        GT_EXCLUDE = ("xss", "模板", "spel", "ssti", "xxe", "命令", "command", "rce", "代码")
        if not any(x in ftype for x in GT_EXCLUDE) and any(x in ftype for x in ("sql", "sqli", "注入", "盲注")):
            gt = cur.get("db_ground_truth")
            if not isinstance(gt, dict):
                problems.append("SQL verified 缺 db_ground_truth 块——db_direct（含直查原件）或 waiver（原因+次级真值来源）二选一")
            else:
                gmode = str(gt.get("mode") or gt.get("source") or "").lower()
                if gmode in ("db_direct", "db", "direct"):
                    gt_evid = gt.get("evidence")
                    gt_files = (
                        [x for x in (gt_evid if isinstance(gt_evid, list) else [gt_evid]) if isinstance(x, str)]
                        if gt_evid
                        else []
                    )
                    if not gt_files:
                        problems.append("db_ground_truth.mode=db_direct 但没有直查原件路径")
                    for item in gt_files:
                        gf = hg.resolve_inside(run_root, item, "db_ground_truth.evidence")
                        if not gf.exists():
                            problems.append(f"db_ground_truth 直查原件不存在: {item}")
                        elif gf.stat().st_size < 40:
                            problems.append(f"db_ground_truth 直查原件过小(<40B): {item}")
                elif gmode in ("waiver", "not_available", "n/a"):
                    if len(str(gt.get("reason") or "")) < 10:
                        problems.append("db_ground_truth.mode=waiver 但 reason 太短（须写明库通道为何不可达）")
                    if not str(gt.get("secondary_source") or "").strip():
                        problems.append("waiver 须写 secondary_source（出厂种子SQL/凭据账种子/第二接口回读/未拖具体值仅证机制）")
                else:
                    problems.append("db_ground_truth.mode 须为 db_direct 或 waiver")

    out = {"status": "failed" if problems else "ok", "checked": str(path), "problems": problems}
    print(json.dumps(out, ensure_ascii=False, indent=2))
    return 1 if problems else 0


if __name__ == "__main__":
    # 2026-10-16 修11：evidence 路径逃出 run_root 时 resolve_inside 抛 hard_gate.GateFailure——
    # 旧版裸 traceback，违背「写完 10 秒内出 JSON 回执」的约定（按 JSON 解析的调用方会挂）。
    # 兜住出结构化回执（含 reason）+ 非零退出，方向仍 fail-closed
    try:
        sys.exit(main())
    except hg.GateFailure as exc:
        print(json.dumps({"status": "failed", "reason": str(exc)}, ensure_ascii=False, indent=2))
        sys.exit(1)
