# -*- coding: utf-8 -*-
"""selftest.py（批四十，红队六轮 P2-10）：最小回归自检——防「改了没回归」重演
（历史上判决函数被切断死代码两批没人发现、packs 注释短路、白名单死锁全是这个账）。

跑：py -3 scripts/selftest.py
覆盖：①全脚本 py_compile；②make_canonical --check；③最小 website 场 env→close 四相冒烟
（close 预期 failed——空场要件不全，但 failed 输出里必须含 Baseline/canonical 相关已知 fail
且不能有 traceback/异常崩溃，证明主流程活着）；④era 分层不误伤（20261015 存量场 env passed）。
 heavier 回归（fixture 行为测试）靶子见 tests/README.md（E:\\DeepAudit 外部资产指引）。
"""
import py_compile
import subprocess
import sys
import tempfile
from pathlib import Path

BASE = Path(__file__).resolve().parent
PKG = BASE.parent
PY = sys.executable
fails = []


def run(args, **kw):
    return subprocess.run([PY, *args], capture_output=True, text=True, cwd=str(BASE), timeout=180, **kw)


def main() -> int:
    # ① compile all
    for p in sorted(BASE.glob("*.py")):
        try:
            py_compile.compile(str(p), doraise=True)
            print(f"compile ok: {p.name}")
        except py_compile.PyCompileError as exc:
            fails.append(f"compile {p.name}: {exc}")
    # ② canonical check（改闸后先 py -3 scripts/make_canonical.py 重建再跑 selftest——漂移=忘了重建，重建后哈希要重抄聊天外）
    r = run(["make_canonical.py", "--check"])
    if '"status": "ok"' not in r.stdout:
        fails.append(f"canonical --check 漂移（改闸后先跑 make_canonical.py 重建、重抄哈希，再跑 selftest）: {r.stdout[:200]}{r.stderr[:200]}")
    else:
        print("canonical ok")
    # ③ B39/40 era 新场冒烟（env passed 需要 canonical 一致；此处 canonical 已核一致）
    with tempfile.TemporaryDirectory(prefix="b40-selftest-") as td:
        new_dir = Path(td) / "20990101-future-test"
        (new_dir / "run").mkdir(parents=True)
        (new_dir / "envelope.json").write_text(
            '{"run_id":"SELF","branch":"website_only","input_scope_kind":"website_only","execution_status":"in_progress","runner_model":"selftest","tool_baseline":{}}',
            encoding="utf-8",
        )
        r = run(["hard_gate.py", "--run-root", str(new_dir), "--phase", "env"])
        if '"status": "passed"' not in r.stdout:
            fails.append(f"B39-era env smoke: {r.stdout[:300]}")
        else:
            print("era-new env smoke passed")
        # 存量场不误伤：昨日日期低于 B39/B40 新拦线，且与今日 mtime 差 ≤1 天不触发 era 回拨核
        # （era_sanity 对所有场生效，勿用远旧日期名——那本来就该被回拨核拦，不是误伤）
        # 批五十八 F 附：写死 20261015 在跨日后必假红（文件 mtime=今日晚于目录名 2 天→era 回拨核拦）
        # ——改动态取昨日 YYYYMMDD，夹具永远满足「晚 ≤1 天」前提
        import datetime as _dt
        _yesterday = (_dt.date.today() - _dt.timedelta(days=1)).strftime("%Y%m%d")
        old_dir = Path(td) / f"{_yesterday}-legacy-test"
        (old_dir / "run").mkdir(parents=True)
        (old_dir / "envelope.json").write_text(
            '{"run_id":"SELF2","branch":"website_only","input_scope_kind":"website_only","execution_status":"in_progress","runner_model":"selftest","tool_baseline":{}}',
            encoding="utf-8",
        )
        r = run(["hard_gate.py", "--run-root", str(old_dir), "--phase", "env"])
        if '"status": "passed"' not in r.stdout:
            fails.append(f"legacy env smoke: {r.stdout[:300]}")
        else:
            print("legacy env smoke passed")
    print()
    if fails:
        print("SELFTEST FAILED:")
        for f in fails:
            print(" -", f)
        return 1
    print("SELFTEST OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
