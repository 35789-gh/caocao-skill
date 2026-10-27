#!/usr/bin/env python3
"""Mini hard gates. Disk facts, real files. Fill-in JSON alone is not enough.

Phases:
  env     — 三枪回包原件、captures 真图+两套端口、in_run、撞过滤必须有曹冲、sink 模块必起、第三方版本必须查 CVE、自动链扫描账（candidate_only，不顶关键字/JS/sink/CVE）；召回层 hybrid-discovery.jsonl（Deep 分桶：PHP/JS/Ruby 先正则，Java/Python/Go/C#/Kotlin/Scala/Swift 先向量，混栈 mixed；不能顶 walker）；禁止「没有专文所以不挖」停工（缺口账可选，不强制）；部署型 web 面已在则司马懿目录不得空、不得假 not-needed「无网站」
  verify  — 复杂链对号录像/5 次失败、前端清单非空、混淆须扫过、verified 类型证据
  close   — env+verify；正位 8 块 finding；曹冲撞过滤不得假 not-needed；第三方 hits 时曹仁/刘晔禁止假 not-needed；CVE in_range 每条须有代码层结论（实测/否证 file:line/blocked，收编不算）；计划行写了 test 须有结果键（verdict_now 不算）、纯读探测禁捆绑延后；正式卷禁内部角色名/账指针（总览/总报告豁免）；cors 实测；网站 JS 清单；曹操签字 verified；credential_scan 必须有账且无外泄；司马懿两段（禁止只打 native 未登录就收口）；欠图 pending/incomplete 不得 close；信封仍写 not_started 但已作业不得 close；验证计划 pending/queued 不得 close；点名的 iot/pay/jmreport 必须入账；关键字账不得用 swagger/链审 grep 顶；JS 清单不得用 api-docs/菜单顶；自动链扫描不得用 swagger/菜单/链审顶、不得写成 verified、也不能免关键字/JS/sink/CVE；召回层必须跟 Deep 分桶（PHP/JS/Ruby regex_first，Java 等 vector_first，混栈 mixed；禁止全语言同一套），有召回也不能免 walker；禁止用「没有专文所以不挖」停工（methodology-gap 可选）；回执落盘 run/hard-gate-<phase>.json
"""
from __future__ import annotations
import sys
sys.dont_write_bytecode = True  # 2026-10-13 新6: 禁 pyc 落包目录（包卫生）

# 批三十七（红队三轮 P0-1）：闸进程代理清洗——close 内嵌 faker 复检（_vision_random_recheck
# import vision_review 发请求）与 subprocess（credential_scan）都继承本进程环境；
# 操作者设 http_proxy 指向本地假神谕即可零文件改动劫持全部视觉防伪（H-25 抓不到）
import os as _os37
for _k37 in [k for k in list(_os37.environ) if k.lower() in ("http_proxy", "https_proxy", "all_proxy")]:
    _os37.environ.pop(_k37, None)

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlparse

IMAGE_EXT = {".png", ".jpg", ".jpeg", ".webp"}
VIDEO_EXT = {".mp4", ".webm", ".mkv", ".mov"}
FILTER_HINTS = (
    "onceperrequestfilter",
    "handlerinterceptor",
    "tokenauthenticationfilter",
    "datapermission",
    "filter_review_required",
    "xssfilter",
    "sqlfilter",
    "captchafilter",
    "拦截器",
    "过滤器",
    "数据权限",
    "waf",
    "验证码防护",
)
SIMA_LEAK = re.compile(
    r"encryptHex|SmImpl|CH-GJ-|候选索引|万能密码|Base64\.decode|01-guo-jia/",
    re.I,
)
def _pkg_script(name: str) -> Path:
    """包内 scripts/ 工具单一出处（无外部包依赖）。"""
    return Path(__file__).resolve().parent / name


CREDENTIAL_SCAN = _pkg_script("credential_scan.py")
URL_RE = re.compile(r"^https?://\S+$", re.I)
FOUR_STEP_KEYS = ("readme", "official_repo", "local_package", "public_repo")
SOURCE_ROSTER = (
    ("01-guo-jia", False),
    ("02-cao-cao", False),
    ("02-cao-cao-shadow", False),
    ("03-cao-chong", True),
    ("04-cao-ren", True),
    ("05-liu-ye", True),
    ("06-yu-jin", True),
    ("08-dian-wei", True),
    ("09-si-ma-yi", True),
)
SKIP_WALK = {"snapshot", "runtime", "node_modules", ".git", "__pycache__", "workspace"}
CAO_CHONG_FAKE_NN = (
    "吸收",
    "已由曹操",
    "无独立",
    "链审吸收",
    "曹操首轮",
    "已被链审",
    "不需要独立",
)
LEDGER_DOCX = ("一、身份", "二、finding", "BEC 台账", "闭环矩阵", "证据链与目录", "收口定性")
# 内部角色名 / 内部账指针不得出现在正式 finding 卷（对用户交代见曹操卡「说人话」）
INTERNAL_TRACE_DOCX = (
    "司马懿",
    "于禁",
    "郭嘉",
    "刘晔",
    "曹冲",
    "曹仁",
    "典韦",
    "分身",
    "曹操",
    "02-cao-cao",
    "06-yu-jin",
    "09-si-ma-yi",
    "01-guo-jia",
    "05-liu-ye",
    "04-cao-ren",
    "03-cao-chong",
    "verification.json",
    "verdict.json",
    "观察册",
    "verdict_now",
    # 2026-10-15 批二十六：RF-DOC-09 三禁词 + 补漏目录字符串（全文禁）。
    # 「机器复核」/「glm」从全文词表挪出 → IMG_CAPTION_TRACE 只扫图注行（批二十五放全文超条文授权：
    # RF-DOC-09 三禁词无 glm，RF-IMG-13 只禁图注标模型名/复核字样——AI 应用类目标正文与请求包实值
    # 合法含 "model":"glm-4" 类内容，全文拦=误伤）
    "run_id",
    "target_identity",
    "snapshot_id",
    "08-dian-wei",
)
IMG_CAPTION_TRACE = (
    # 2026-10-15 批二十六：RF-IMG-13 图注禁词（判例 24）——只扫含「实测截图」特征词的图注行，不扫全文
    "机器复核",
    "glm",
    "gpt",
    "gemini",
    "claude",
    "qwen",
    "via faker",
)
SINK_SCAN_KEYS = (
    "mybatis_dollar",
    "class_for_name",
    "exec",
    "expression",
    "fastjson_user_entry",
)
SINK_FAKE_BLOCK = (
    "只起了",
    "登录已经",
    "本场只测",
    "只测 admin",
    "只起 system",
    "只起了登录",
    "考场没起",
    "没起所以打不了",
    "admin壳",
    "聚合注释",
    "模块注释",
    "pom 注释",
    "pom注释",
    "只启用 system",
    "只启用了 system",
    "只编译了 system",
    "只编译部署了",
    "其余模块注释",
    "不值一个",
    "不值当",
    "report-server 未部署",
    "iot 没起",
    "iot没起",
)
CVE_SCAN_KEYS = (
    "maven",
    "npm",
    "gradle",
    "python",
    "go_mod",
)
CVE_QUERY_OK = {"queried", "first_party", "no_public_db"}
CVE_EVIDENCE_RE = re.compile(
    r"cve-\d{4}-\d+|nvd|ghsa-|advisory|keywordsearch|无条目|0 条目|0 hits",
    re.I,
)
# 批三十五 P1-3（深挖 27）：era≥20261015 的 queried 证据须含真实 HTTP 响应特征——
# 「无条目/0 条目」中文手记不再当查询原件（手写一个 41 字节 txt 即过闸的摸鱼手法）
CVE_EVIDENCE_STRICT_RE = re.compile(
    r"HTTP/1\.|https?://(nvd\.nist\.gov|cve\.circl\.lu|osv\.dev|github\.com/advisories|avd\.aquasec\.com|cvefeed\.io|www\.cvedetails\.com)"
    r"|\"(results|totalResults|vulns|cves|totalCount)\"\s*:",
    re.I,
)
CVE_FAKE_NN = CAO_CHONG_FAKE_NN + (
    "本地源码",
    "无外部情报",
    "情报无到期",
    "无独立组件",
    "组件画像",
    "coverage_gap",
)
SIMA_FAKE_NN = (
    "无待测网站",
    "无网站黑盒",
    "无网站",
    "无 web",
    "无web",
    "local_source",
    "本地源码",
    "zip 无前端",
    "zip无前端",
    "无前端所以无黑盒",
    "website_work_required",
    "无待测 url",
    "无待测url",
    "无待测 URL",
)
SIMA_PHASE2_FAKE = (
    "等第一段",
    "回执未齐",
    "闸没齐",
    "等画面",
    "等主会话截",
    "pending_visual",
    "还没轮到",
    "排队",
    "lock-q-002",
    "第二段等",
    "等曹操调度",
    "等审批完毕后",
)
NOT_STARTED_STATUSES = (
    "not_started",
    "session_initialized_before_audit_execution",
)
OPEN_PLAN_STATUSES = {
    "pending",
    "queued",
    "waiting",
    "not_started",
    "todo",
    "ready",
    "待测",
    "未测",
    "等窗口",
    "待打",
    "待发起",
    "待复测",
}
KEYWORD_SCAN_KEYS = (
    "permit_all",
    "login_user_header",
    "mock_secret",
    "notify_url",
    "mybatis_dollar",
    "class_for_name",
    "exec",
    "expression",
    "upload_ext",
    "third_party_coord",
)
KEYWORD_FAKE_SOURCE = (
    "swagger",
    "api-docs",
    "apidocs",
    "knife4j",
    "doc.html",
    "menu/list",
    "get-permission-info",
    "对象图",
    "链审 grep",
    "链审grep",
    "chains/",
    "verification-plan",
    "v3/api-docs",
)
JS_FAKE_SOURCE = (
    "swagger",
    "api-docs",
    "apidocs",
    "knife4j",
    "doc.html",
    "v3/api-docs",
    "对象图",
    "menu/list 抽出",
    "从菜单",
)
CHAIN_SCAN_KEYS = (
    "php_request",
    "php_include",
    "php_sql",
    "php_eval",
    "php_unserialize",
    "java_request",
    "java_exec",
    "mybatis_dollar",
)
JS_IN_OK = ("query", "body", "path", "header")
CHAIN_FAKE_SOURCE = KEYWORD_FAKE_SOURCE
CHAIN_ENGINE_FAKE = (
    "keyword-scan.json",
    "js-collection.json",
    "sink-runtime-modules.json",
    "component-cve-ledger.json",
)
CHAIN_FORBIDDEN_STATUS = (
    "verified",
    "confirmed",
    "true_positive",
    "finding",
    "exploited",
)
HYBRID_STRATEGY_OK = ("regex_first", "vector_first", "mixed")
HYBRID_UNIFIED_FAKE = ("regex_after_no_vector",)
HYBRID_REGEX_FIRST_LANGS = ("php", "javascript", "ruby")
HYBRID_VECTOR_FIRST_LANGS = (
    "java",
    "python",
    "go",
    "csharp",
    "kotlin",
    "scala",
    "swift",
)
METHODOLOGY_STALL = (
    "没有方法论所以不挖",
    "缺方法论所以不挖",
    "等方法论文件",
    "停工等文再挖",
    "没有专文所以不挖",
    "没有 php/java 所以不挖",
    "没有php/java所以不挖",
    "没有 php 方法论所以",
    "没有 java 方法论所以",
    "没有php方法论所以",
    "没有java方法论所以",
    "等专文再挖",
    "装箱没有所以不挖",
)
PACKED_METHODOLOGY_OK = {"none", "php", "java", "mixed", "self"}
PHASE = ""
RUN_ROOT: Path | None = None


def load_json(path: Path) -> dict | None:
    # 批四十五 B-13：utf-8 → utf-8-sig（BOM 兼容——PowerShell Out-File 产物常带 BOM，旧版把
    # 合法 BOM JSON 判成坏档静默当缺失）；dict 根行为不变
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
    except Exception:
        return None
    return data if isinstance(data, dict) else None


def load_json_tree(path: Path, consumer: str):
    """批四十五 B-1：全树遍历型消费方（any_verified/check_verified_evidence/
    check_verified_disposition）专用——文件存在就必须解析出内容（数组根/标量根原样返回
    交给 walk_dicts 遍历），坏 JSON 明确 fail。旧 load_json 对非 dict 根返回 None，
    手写数组根 finding（[{chain_id,status:verified,evidence:[不存在]}]）让全部
    verified 系检查整体失明。「文件存在但读不出」绝不等于「无 finding 文件」。"""
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8-sig"))
    except Exception as exc:
        fail(
            f"{consumer}: {path} 存在但不是合法 JSON（malformed: {type(exc).__name__}）——"
            "不再静默当无 finding 文件（批四十五 B-1）；GBK/二进制内容须转 UTF-8 后落盘"
        )


def load_finding_json(path: Path, consumer: str) -> dict | None:
    """批四十五 B-1：reports/json 的 finding 消费方专用——finding 文件必须是对象根，
    数组根/标量根明确 fail（注明 array-root/malformed）；文件不存在返回 None（等同旧语义）。"""
    data = load_json_tree(path, consumer)
    if data is not None and not isinstance(data, dict):
        kind = "array-root" if isinstance(data, list) else f"{type(data).__name__}-root"
        fail(
            f"{consumer}: {path.name} 根不是 JSON 对象（{kind}）——finding 文件必须对象根"
            "（批四十五 B-1：旧 load_json 对非 dict 根返回 None，数组根 finding 逃过全部证据配套检查）"
        )
    return data


def _finding_status(f: dict) -> str:
    """批四十五 M31：finding 终态键统一读取——status/finding_status/final_status 三键
    一致优先级。旧版 check_verified_evidence/any_verified 只读前两键，finding 只写
    final_status=verified 即逃过证据配套检查、却在读三键的处置/下限检查里计为 verified。"""
    return str(f.get("status") or f.get("finding_status") or f.get("final_status") or "").strip().lower()


def write_receipt(status: str, payload: dict) -> None:
    if RUN_ROOT is None or not PHASE:
        return
    out_dir = RUN_ROOT / "run"
    out_dir.mkdir(parents=True, exist_ok=True)
    body = {"status": status, "phase": PHASE, "hash_required": False}
    # 批四十九（r18 R3-L 锚①）：回执落「实跑当日日期」——close/verify 用它与目录名双对账，
    # 目录名起昨天骗 era ±1 天容差的降级链在此暴露（改 env 回执日期则撞 scene_digest v4 指纹）
    import datetime as _dt49

    body["run_date"] = _dt49.datetime.now().strftime("%Y%m%d")
    body.update(payload)
    if PHASE == "close":
        # 2026-10-15 批三十四（draft batch30 §2 合入，H-23 机械件）：close 回执防伪三件——
        # 闸自身哈希 + 场景指纹（reports/** 与两份前置回执的 relpath:size:mtime_ns 总哈希，
        # 不含回执自身防自引用；os.utime 改回 mtime 也须同时伪造 size 且重跑即刷新）+
        # 检查器基线快照。--verify-close 重验比对，缺字段/不符 = 手写或场后改动（伪造论处）。
        body["gate_sha256"] = _gate_sha256()
        body["scene_digest"] = _scene_digest(RUN_ROOT)
        body["scene_digest_version"] = 4  # 批四十五：v4 全量口径（run_root 全部文件哈希，B-2/B-4）；旧口径回执 verify-close 按升级重跑处理
        body["tool_baseline_at_close"] = _tool_baseline_now()
        # 批四十（红队六轮 P0-2）：env 回执指纹进 close 回执——「中段洗白链」（env 后塞洞→重算清单
        # →改写 env 回执锚值→跑真 close 首次 scene_digest 把脏状态记成合法）靠外部对账抓：
        # 深挖 29③ 开局外发 env 指纹，收口外发带本键，两点不一致 = env 回执被中段改写，用户对账即露。
        _envrc = RUN_ROOT / "run" / "hard-gate-env.json"
        if _envrc.is_file():
            import hashlib as _hl40b

            body["env_receipt_sha256"] = _hl40b.sha256(_envrc.read_bytes()).hexdigest()
    elif PHASE == "env":
        # 批三十五（H-22 清单锚）：env 回执记开局清单哈希，close 的 check_finding_source_refs
        # 比对——收口前重写一份与毒化材料自洽的 material-manifest 在此被拦（换清单=换锚必露）
        _mp = RUN_ROOT / "run" / "material-manifest.json"
        if _mp.is_file():
            import hashlib as _hl35

            body["material_manifest_sha256"] = _hl35.sha256(_mp.read_bytes()).hexdigest()
        # 批六十二①（摸鱼洞「收口前重锚」）：信封是可写文件——env 过后整体改写信封
        # tool_baseline 使其与收口实况自洽，close 的「信封锚 vs 实况」两头都可控。env 回执
        # 锚住信封 tool_baseline 的序列化哈希，close 三方对账（回执锚 vs 现信封）——开局锚
        # 被中段改写在此暴露（与批四十 env_receipt_sha256 同哲学：闸写的回执锚信封）
        _env62 = envelope(RUN_ROOT)
        if isinstance(_env62.get("tool_baseline"), dict) and _env62["tool_baseline"]:
            import hashlib as _hl62

            body["envelope_tool_baseline_sha256"] = _hl62.sha256(
                json.dumps(_env62["tool_baseline"], sort_keys=True, ensure_ascii=False).encode("utf-8")
            ).hexdigest()
    path = out_dir / f"hard-gate-{PHASE}.json"
    path.write_text(json.dumps(body, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


class GateFailure(Exception):
    """单个检查项不过（2026-10-08 collect-all 改良：一轮收全所有毛病，不再挤牙膏式返工）"""


FAILURES: list[dict] = []


def collect_errors(fn):
    # 包一层：顶层检查失败先记账、继续跑后面的检查；由 ok()/收尾统一出一整张账。
    import functools

    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except GateFailure:
            return None

    return wrapper


def emit_failures() -> None:
    first = str(FAILURES[0].get("reason", ""))
    more = len(FAILURES) - 1
    reason = first if more <= 0 else f"{first}（另有 {more} 条，逐条见 failures）"
    out = {"status": "failed", "reason": reason, "failures": FAILURES}
    write_receipt("failed", out)
    print(json.dumps(out, ensure_ascii=False, indent=2))
    raise SystemExit(1)


def fail(msg: str, extra: dict | None = None) -> None:
    entry = {"reason": msg}
    if extra:
        entry.update(extra)
    FAILURES.append(entry)
    raise GateFailure(msg)


def ok(phase: str, notes: list[str]) -> None:
    if FAILURES:
        emit_failures()
    payload = {"notes": notes}
    write_receipt("passed", payload)
    print(
        json.dumps(
            {"status": "passed", "phase": phase, "notes": notes, "hash_required": False},
            ensure_ascii=False,
            indent=2,
        )
    )


def envelope(run_root: Path) -> dict:
    for cand in (
        run_root / "run" / "envelope.json",
        run_root / "envelope.json",
        run_root / "test-session.json",
        run_root / "run" / "test-session.json",
    ):
        data = load_json(cand)
        if data:
            return data
    return {}


def is_website(env: dict) -> bool:
    kind = str(env.get("input_scope_kind") or env.get("branch") or "").lower()
    return "website_only" in kind or kind == "website"


def _declared_proxy_opener(env: dict):
    """批四十四（声明式代理豁免）：官方源探针 / CVE 重放两类公网取数可走信封登记的
    declared_proxy（开局外发账必含，用户可对）——环境变量暗代理仍剥（批三十七防劫持不变）、
    faker 视觉通道与打本场本地服务的回包重放永不走代理。返回 None = 直连照旧。"""
    p = str((env or {}).get("declared_proxy") or "").strip()
    if not p:
        return None
    import urllib.request as _urp44
    return _urp44.build_opener(_urp44.ProxyHandler({"http": p, "https": p}))


def is_static_only(env: dict) -> bool:
    mode = str(
        env.get("review_mode")
        or env.get("mode")
        or env.get("declared_mode")
        or ""
    ).lower()
    return mode in {"static_only", "semantic_only"}


def blob_text(path: Path, limit: int = 400_000) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")[:limit]
    except OSError:
        return ""


def has_deployed_web_surface(run_root: Path) -> bool:
    """Native/API/login/swagger already in this run — blackbox surface exists."""
    env = envelope(run_root)
    if is_website(env):
        return True
    if is_static_only(env):
        return False
    shots = load_json(run_root / "01-guo-jia" / "captcha-removed-three-shots.json") or {}
    if any(str(shots.get(k) or "").lower() == "pass" for k in ("login_without_captcha", "challenge_no_image", "page_no_widget")):
        return True
    idx = load_json(run_root / "run" / "captures-index.json") or {}
    if str(idx.get("ui") or "").lower() == "required":
        return True
    urls = idx.get("address_bar_urls")
    if isinstance(urls, dict) and any(isinstance(v, str) and v.startswith("http") for v in urls.values()):
        return True
    markers = (
        "swagger",
        "knife4j",
        "doc.html",
        "/login",
        "api-docs",
        "getcaptcha",
        "v3/api-docs",
        "127.0.0.1:",
        "localhost:",
    )
    for folder in ("01-guo-jia", "02-cao-cao", "06-yu-jin", "09-si-ma-yi", "run"):
        root = run_root / folder
        if not root.is_dir():
            continue
        for p in root.rglob("*"):
            if not p.is_file() or p.suffix.lower() not in {".json", ".md", ".txt", ".yaml", ".yml"}:
                continue
            if p.stat().st_size > 2_000_000:
                continue
            text = blob_text(p).lower()
            if any(m in text for m in markers):
                # 2026-10-13 C9 修：localhost:3306/redis://127.0.0.1 等非 web 连接串不算部署面——
                # 端口负向排除常见 DB/中间件口，另认 http:// 与 host 头形态
                import re as _re9
                # 2026-10-13 M6 修（v2）：裸词 marker（swagger/knife4j/doc.html——CVE 描述/文档常裸提及）
                # 须以路径形态命中（后跟 /?# 引号，防「swagger 文档」空格语境误报）；
                # 自带斜杠的 marker（/login、/api-docs、v3/api-docs、getcaptcha）本身就是路径片段，子串命中即算
                _BARE_WORD_MARKERS = ("swagger", "knife4j", "doc.html")
                # 2026-10-13 新7 修：[/?#] 只认后跟路径符号——「/doc.html 开放」「swagger」句尾全漏。
                # 终版口径：负向 (?![a-z0-9]) 只排英文正文粘连（如 swagger-ui 组件名 / swaggerui）；
                # 中文/空格语境一律放行——误报代价=多查司马懿两段+CORS（安全侧），漏拦代价=整段检查静默跳过
                _hits = [m for m in markers
                         if (m in _BARE_WORD_MARKERS and _re9.search(_re9.escape(m) + r'(?![a-z0-9])(?![-_.][a-z])', text))
                         or (m not in _BARE_WORD_MARKERS and m in text)]
                web_hits = _re9.findall(r'(?:127\.0\.0\.1|localhost):(?!3306\b|6379\b|5432\b|27017\b|9092\b|2181\b|33060\b)[0-9]+', text)
                http_hits = _re9.findall(r'https?://(?:127\.0\.0\.1|localhost)', text)
                # 2026-10-13 C9 真修：旧 host 判定 'host:' in text 被 localhost:6379 子串击穿（修了个寂寞）——
                # 现只认 host 作为键出现（JSON/YAML/表单形态），子串形态不算
                host_hdr = bool(_re9.search(r'["\']host["\']\s*[:=]', text)) or "\nhost:" in text or text.startswith("host:")
                other = bool(_hits)
                if web_hits or http_hits or host_hdr or other:
                    return True
                continue
    return False


def iter_files(run_root: Path, suffix: str | None = None):
    for dirpath, dirnames, filenames in os.walk(run_root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_WALK]
        for name in filenames:
            if suffix and not name.lower().endswith(suffix):
                continue
            yield Path(dirpath) / name


def iter_json_files(run_root: Path):
    yield from iter_files(run_root, ".json")


def walk_dicts(data):
    stack = [data]
    while stack:
        cur = stack.pop()
        if isinstance(cur, dict):
            yield cur
            stack.extend(cur.values())
        elif isinstance(cur, list):
            stack.extend(cur)


def any_verified(run_root: Path) -> bool:
    for p in iter_json_files(run_root):
        # 批四十五 B-1/M31：数组根原样进 walk_dicts（verified 不因根形态逃检）；终态键统一
        data = load_json_tree(p, "any_verified")
        if not data:
            continue
        for cur in walk_dicts(data):
            if _finding_status(cur) == "verified":
                return True
    return False


def file_head(path: Path, n: int = 64) -> bytes:
    try:
        with path.open("rb") as fh:
            return fh.read(n)
    except OSError:
        return b""


def is_real_image(path: Path) -> bool:
    head = file_head(path)
    if head.startswith(b"\x89PNG\r\n\x1a\n"):
        return True
    if head.startswith(b"\xff\xd8\xff"):
        return True
    if head.startswith(b"RIFF") and b"WEBP" in head[:16]:
        return True
    return False


def is_real_video(path: Path) -> bool:
    head = file_head(path, 32)
    if b"ftyp" in head[:16]:
        return True
    if head.startswith(b"\x1a\x45\xdf\xa3"):
        return True
    return False


def resolve_inside(run_root: Path, rel: str, label: str) -> Path:
    f = (run_root / rel).resolve()
    try:
        f.relative_to(run_root.resolve())
    except ValueError:
        fail(f"{label} escapes run_root: {rel}")
    return f


def url_host_port(url: str) -> tuple[str, int]:
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    if not host:
        fail(f"URL 没有 host: {url}")
    # 批四十五 B-14：urlparse().port 对越界端口（:99999）抛 ValueError 穿透 collect_errors
    # 裸崩——视为非法 URL 结构化 fail
    try:
        port = parsed.port
    except ValueError:
        fail(f"URL 端口非法（越界/非数字）: {url}（批四十五 B-14）")
    if not port:
        port = 443 if parsed.scheme == "https" else 80
    return host, port


def text_has_filter(run_root: Path) -> bool:
    roots = [
        run_root / "01-guo-jia",
        run_root / "02-cao-cao",
        run_root / "06-yu-jin",
        run_root / "09-si-ma-yi",
    ]
    for root in roots:
        if not root.is_dir():
            continue
        for p in root.rglob("*"):
            if not p.is_file():
                continue
            if p.suffix.lower() in {".png", ".jpg", ".jpeg", ".webp", ".mp4", ".zip", ".jar"}:
                continue
            try:
                if p.stat().st_size > 2_000_000:
                    continue
                text = p.read_text(encoding="utf-8", errors="ignore").lower()
            except OSError:
                continue
            if any(h in text for h in FILTER_HINTS):
                return True
    for marker_p in (
        run_root / "02-cao-cao" / "filter-signal.json",
        run_root / "01-guo-jia" / "filter-signal.json",
    ):
        marker = load_json(marker_p)
        if marker and marker.get("hit") is True:
            return True
    return False


def capability_files(run_root: Path) -> list[Path]:
    out = []
    for p in iter_json_files(run_root):
        if "capability" not in p.name.lower():
            continue
        data = load_json(p)
        if data and "screenshot_capture_in_run" in data:
            out.append(p)
    return out


@collect_errors
def check_three_shots(run_root: Path, notes: list[str]) -> None:
    path = run_root / "01-guo-jia" / "captcha-removed-three-shots.json"
    if not path.is_file():
        fail("missing 01-guo-jia/captcha-removed-three-shots.json (去干净三枪回执)")
    data = load_json(path)
    if not data:
        fail("captcha-removed-three-shots.json is not a JSON object")
    required = ("login_without_captcha", "challenge_no_image", "page_no_widget")
    for key in required:
        val = str(data.get(key) or "").lower()
        if val not in {"pass", "fail", "not_applicable"}:
            fail(f"three-shots.{key} must be pass|fail|not_applicable")
        if val == "fail":
            fail(f"three-shots.{key}=fail；去干净未过，不得报 removed 小跑通过")
    if data.get("no_captcha_product") is True:
        # 2026-10-15 二轮复核：无验证码产品三枪客观不存在（native 本免码/无挑战接口/无控件），
        # SKILL 双拓扑明文「第二套记未改对照，不假造差分」——闸认未改对照形态，禁假造差分凑三枪
        for key in required:
            if str(data.get(key) or "").lower() in {"pass", "fail"}:
                fail(f"no_captcha_product=true 时 {key} 应为 not_applicable（产品无验证码，无此枪可打）")
        if len(str(data.get("product_basis") or "").strip()) < 10:
            fail("no_captcha_product=true 必须写 product_basis（≥10 字：源码/配置里无验证码模块的依据）")
        if not isinstance(data.get("evidence"), list) or len(data.get("evidence") or []) < 1:
            fail("no_captcha_product 至少 1 份未改对照回包原件（removed 登录成功回包）")
        for rel in data.get("evidence") or []:
            # 修复批十九：豁免免的是「假差分」，不免证据——原件校验与常规分支同标
            if not isinstance(rel, str) or not rel.strip():
                fail("no_captcha_product evidence 项必须是路径字符串")
                continue
            f = resolve_inside(run_root, rel, "no_captcha evidence")
            if not f.is_file() or f.stat().st_size < 40:
                fail(f"no_captcha_product evidence missing or too small: {rel}")
        notes.append("three_shots_no_captcha_product")
        return
    if str(data.get("challenge_no_image")).lower() == "not_applicable" and str(
        data.get("login_without_captcha")
    ).lower() == "pass":
        fail("登录免码却把挑战接口标 not_applicable：第②枪必须打")
    if str(data.get("challenge_no_image")).lower() == "pass":
        cpath = str(data.get("challenge_path") or "").strip()
        if not cpath.startswith("/"):
            fail("第②枪 pass 必须写 challenge_path（以 / 开头的真实 path）")
    evidence = data.get("evidence")
    if not isinstance(evidence, list) or len(evidence) < 2:
        fail("three-shots.evidence 至少两份落盘回包（登录差分 + 挑战接口）")
    # 批四十五 B-16：同一路径重复充两份不算——登录差分与挑战接口必须是两份不同原件
    _evid_uniq = {str(r) for r in evidence if isinstance(r, str)}
    if len(_evid_uniq) < 2:
        fail("three-shots.evidence 是同一路径重复充数（批四十五 B-16）——登录差分与挑战接口须各留一份独立原件")
    bodies = []
    for rel in evidence:
        if not isinstance(rel, str) or not rel.strip():
            fail("three-shots.evidence 项必须是路径字符串")
        f = resolve_inside(run_root, rel, "three-shots.evidence")
        if not f.is_file() or f.stat().st_size < 40:
            fail(f"three-shots evidence missing or too small: {rel}")
        try:
            bodies.append(f.read_text(encoding="utf-8", errors="ignore"))
        except OSError:
            fail(f"three-shots evidence unreadable: {rel}")
    blob = "\n".join(bodies).lower()
    if str(data.get("challenge_no_image")).lower() == "pass":
        if "http" not in blob and "status" not in blob and "{" not in blob:
            fail("第②枪 evidence 不像 HTTP/JSON 回包")
        if re.search(r'"code"\s*:\s*(0|200)\s*,[\s\S]{0,400}(image|base64|captchaEnabled"\s*:\s*true)', blob, re.I):  # 批五十九 B-3：blob 已 lower()，大小写敏感的 captchaEnabled 恒失配（死代码）——加 re.I
            fail("第②枪 evidence 仍像成功吐图/出题，不得标 pass")
    notes.append("three_shots_present")


def check_four_step(gap: object) -> None:
    if not isinstance(gap, dict) or not gap:
        fail("UI not_applicable 必须带 four_step_frontend_search 对象，四步各有结果")
    for key in FOUR_STEP_KEYS:
        val = gap.get(key)
        if not isinstance(val, dict):
            fail(f"four_step_frontend_search.{key} 必须是对象")
        searched = str(val.get("searched") or "").strip()
        result = str(val.get("result") or "").strip().lower()
        if len(searched) < 8:
            fail(f"four_step_frontend_search.{key}.searched 太短，必须写搜了什么")
        if result not in {"hit", "miss"}:
            fail(f"four_step_frontend_search.{key}.result 必须是 hit|miss")


@collect_errors
def check_captures(run_root: Path, notes: list[str]) -> None:
    idx_p = run_root / "run" / "captures-index.json"
    if not idx_p.is_file():
        fail("missing run/captures-index.json")
    idx = load_json(idx_p)
    if not idx:
        fail("captures-index.json is not a JSON object")
    ui = str(idx.get("ui") or "required").lower()
    if ui == "not_applicable":
        check_four_step(idx.get("four_step_frontend_search"))
        notes.append("captures_ui_na")
        return
    if ui != "required":
        fail("captures-index.ui 必须是 required 或 not_applicable")
    urls = idx.get("address_bar_urls")
    if not isinstance(urls, dict):
        fail("captures-index.address_bar_urls 必须按张给 URL，禁止只写 address_bar=true")
    if idx.get("address_bar") is not True:
        fail("captures-index.address_bar must be true（地址栏原图）")
    ports = {}
    shots: dict[str, Path] = {}
    for key in ("native_login", "removed_login", "removed_admin"):
        rel = idx.get(key)
        if not isinstance(rel, str) or not rel.strip():
            fail(f"captures-index missing {key} path")
        f = resolve_inside(run_root, rel, f"captures-index.{key}")
        if not f.is_file() or f.suffix.lower() not in IMAGE_EXT:
            fail(f"captures-index.{key} file missing or not an image: {rel}")
        if f.stat().st_size < 8_000:
            fail(f"captures-index.{key} too small to be a real window shot: {rel}")
        if not is_real_image(f):
            fail(f"captures-index.{key} 不是 PNG/JPEG/WEBP 文件头，禁止用一堆 x 充原图: {rel}")
        url = urls.get(key)
        if not isinstance(url, str) or not URL_RE.match(url.strip()):
            fail(f"captures-index.address_bar_urls.{key} 必须是 http(s) URL")
        ports[key] = url_host_port(url.strip())
        shots[key] = f
    native_hp = ports["native_login"]
    removed_hp = ports["removed_login"]
    admin_hp = ports["removed_admin"]
    if native_hp == removed_hp:
        fail("native_login 与 removed_login 的 host:port 相同；双拓扑必须两套端口")
    if removed_hp[0] != admin_hp[0] or removed_hp[1] != admin_hp[1]:
        fail("removed_login 与 removed_admin 必须是同一套 removed 实例（同 host:port）")
    _check_capture_duplicates(shots, notes)
    notes.append("captures_index_ok")


def _check_capture_duplicates(shots: dict[str, Path], notes: list[str]) -> None:
    """批三十六（红队二轮 P1-5）：三张双拓扑截图两两查重——同图复制配三个 URL 字符串的
    造假在此被拦（此前只验魔数+大小+URL 字符串，画面内容零比对）。
    ① sha256 字节级相同必拦；② dhash 感知哈希（PIL 可用时）距离 ≤6 判近重复——
    同屏微裁/重压缩也拦；PIL 不可用只记 note（字节级查重仍生效）。"""
    import hashlib as _hl

    keys = [k for k in ("native_login", "removed_login", "removed_admin") if k in shots]
    shas = {k: _hl.sha256(shots[k].read_bytes()).hexdigest() for k in keys}
    for i in range(len(keys)):
        for j in range(i + 1, len(keys)):
            if shas[keys[i]] == shas[keys[j]]:
                fail(
                    f"双拓扑截图查重：{keys[i]} 与 {keys[j]} 字节级相同（sha256 一致）——"
                    "同一张图复制三份配不同 URL 冒充两套实例（批三十六），必须分别实拍"
                )
    try:
        from PIL import Image as _PILImage
    except Exception:
        notes.append("capture_dhash_unavailable(PIL 未装，字节级查重已生效)")
        return

    def _dhash(p: Path) -> int:
        img = _PILImage.open(p).convert("L").resize((9, 8))
        px = list(img.getdata())
        bits = 0
        for row in range(8):
            for col in range(8):
                bits = (bits << 1) | (1 if px[row * 9 + col] > px[row * 9 + col + 1] else 0)
        return bits

    try:
        hashes = {k: _dhash(shots[k]) for k in keys}
    except Exception:
        notes.append("capture_dhash_unavailable(解码失败，字节级查重已生效)")
        return
    for i in range(len(keys)):
        for j in range(i + 1, len(keys)):
            d = bin(hashes[keys[i]] ^ hashes[keys[j]]).count("1")
            # 批五十九 B-1（r38 实测）：native×removed 双拓扑对按语义豁免 ≤6 阈值——双拓扑=同产品
            # 两套实例，登录页唯一差异常是验证码控件（实测距离 4），dhash 抓不住这种局部差异属
            # 误杀（本来就是分别实拍）；字节级查重仍对全对生效（同图复制照拦），removed×removed
            # 侧保持 ≤6 严判。native×removed 改 >2 字节级豁免外全放（sha 已拦同图）。
            _pair59 = {keys[i], keys[j]}
            _topo59 = ("native_login" in _pair59) and ("removed_login" in _pair59 or "removed_admin" in _pair59)
            if d <= 6 and not (_topo59 and d > 1):
                fail(
                    f"双拓扑截图查重：{keys[i]} 与 {keys[j]} 感知哈希距离 {d}（≤6 判近重复）——"
                    "同屏微裁/重压缩冒充另一套实例（批三十六），必须分别实拍；"
                    "双拓扑对（native×removed）仅拦距离 ≤2 的近全同（局部差异如验证码控件属正常拓扑差，批五十九 B-1）"
                )
    notes.append("capture_duplicates_ok")


@collect_errors
def check_in_run(run_root: Path, notes: list[str]) -> None:
    caps = capability_files(run_root)
    if not caps:
        if (run_root / "01-guo-jia").is_dir() or (run_root / "09-si-ma-yi").is_dir():
            fail("郭嘉或司马懿目录已在，但没有任何 capability JSON 含 screenshot_capture_in_run")
        notes.append("no_capability_json")
        return
    captures_exist = False
    cap_dir = run_root / "captures"
    if cap_dir.is_dir() and any(
        p.suffix.lower() in IMAGE_EXT and p.is_file() for p in cap_dir.rglob("*")
    ):
        captures_exist = True
    idx = load_json(run_root / "run" / "captures-index.json") or {}
    ui_required = str(idx.get("ui") or "").lower() == "required"
    pending = False
    wrong = []
    for p in caps:
        data = load_json(p) or {}
        items = data.get("pending_visual_capture_items")
        if isinstance(items, list) and items:
            pending = True
        if str(data.get("screenshot_capture_in_run") or "").lower() == "unavailable":
            wrong.append(str(p.relative_to(run_root)).replace("\\", "/"))
        if str(data.get("ui_completeness") or "").lower() == "passed" and not captures_exist:
            fail("ui_completeness=passed 但 captures/ 没有图")
    if (captures_exist or pending or ui_required) and wrong:
        fail(
            "screenshot_capture_in_run=unavailable but this run can capture（有图/欠项/captures-index.ui=required）；本场能截不得填 unavailable",
            {"files": wrong},
        )
    notes.append("in_run_ok")
    check_pending_visual_not_empty(run_root, notes, phase_close=False)


def pending_capture_open(run_root: Path) -> list[str]:
    hits: list[str] = []
    for p in capability_files(run_root):
        data = load_json(p) or {}
        items = data.get("pending_visual_capture_items")
        if isinstance(items, list) and items:
            hits.append(str(p.relative_to(run_root)).replace("\\", "/") + ":pending_visual_capture_items")
        for key in ("pending_visual_review", "visual_items_handed_to_main_session"):
            val = data.get(key)
            if val in (True, "true", "pending") or (isinstance(val, list) and val):
                hits.append(str(p.relative_to(run_root)).replace("\\", "/") + f":{key}")
    tickets = []
    for folder in ("06-yu-jin", "09-si-ma-yi", "02-cao-cao", "08-dian-wei"):
        d = run_root / folder
        if not d.is_dir():
            continue
        for p in d.rglob("*"):
            if not p.is_file():
                continue
            name = p.name.lower()
            if "workorder" in name or "ticket" in name or "capture-ticket" in name:
                tickets.append(p)
    for p in tickets:
        text = blob_text(p).lower()
        if any(
            k in text
            for k in (
                "pending",
                "incomplete",
                "待补",
                "待截",
                "等待主会话",
                "交主会话",
                "closed_loop_status=incomplete",
                "\"incomplete\"",
            )
        ) and not re.search(r"closed_loop_status[\"'\s:=]+(?:complete[d]?|done|ok|closed)\b", text[:800]) and '"closed": true' not in text[:800]:
            # 批五十九 B-4（r38）：旧版 "closed" 裸子串短路——字段名 closed_loop_status 自带 closed，
            # =incomplete 的未关 md 工单 100% 漏拦；改结构化字段值判定（键名+闭合值才算关）
            hits.append(str(p.relative_to(run_root)).replace("\\", "/"))
    for p in iter_json_files(run_root):
        rel = str(p.relative_to(run_root)).replace("\\", "/")
        if rel.startswith("reports/") or "/discarded/" in rel:
            continue
        data = load_json(p)
        if not data:
            continue
        for cur in walk_dicts(data):
            st = str(cur.get("closed_loop_status") or cur.get("visual_status") or "").lower()
            if st in {"incomplete", "pending_visual_capture", "pending_visual_review"}:
                hits.append(rel)
                break
    return hits


@collect_errors
def check_pending_visual_not_empty(run_root: Path, notes: list[str], phase_close: bool) -> None:
    caps = capability_files(run_root)
    for p in caps:
        data = load_json(p) or {}
        in_run = str(data.get("screenshot_capture_in_run") or "").lower()
        items = data.get("pending_visual_capture_items")
        if in_run == "available" and items == []:
            # empty is only legal when no remaining visual duty; close will still fail on tickets
            continue
        if in_run == "available" and not isinstance(items, list):
            fail(f"{p.name} 本场能截时 pending_visual_capture_items 必须是数组")
    if not phase_close:
        notes.append("pending_visual_shape_ok")
        return
    open_hits = pending_capture_open(run_root)
    if open_hits:
        fail(
            "本场仍有欠图/弹窗工单/closed_loop_status=incomplete；禁止写工单散场后 close。主会话必须自己截完再收口",
            {"open": open_hits[:16]},
        )
    notes.append("pending_visual_closed")


def cao_chong_has_work(d: Path) -> bool:
    for p in d.rglob("*"):
        if not p.is_file():
            continue
        if p.name.lower() in {"not-needed.json", "capability.json"}:
            continue
        if p.suffix.lower() in {".json", ".md", ".txt"} and p.stat().st_size >= 40:
            return True
    return False


@collect_errors
def check_cao_chong(run_root: Path, notes: list[str]) -> None:
    if is_website(envelope(run_root)):
        notes.append("website_no_cao_chong")
        return
    if not text_has_filter(run_root):
        notes.append("no_filter_hint")
        return
    d = run_root / "03-cao-chong"
    if not d.is_dir():
        fail("filter/拦截器信号已出现，但没有 03-cao-chong/")
    nn = d / "not-needed.json"
    if cao_chong_has_work(d):
        notes.append("cao_chong_present")
        return
    if nn.is_file():
        data = load_json(nn) or {}
        reason = str(data.get("reason") or "")
        if any(k in reason for k in CAO_CHONG_FAKE_NN):
            fail("曹冲 not-needed 写成『被曹操吸收/无独立增量』；撞到过滤必须交过滤账，禁止假 not-needed")
        fail("源码撞到过滤，曹冲不得只交 not-needed.json，必须交过滤账（能不能解开、怎么测）")
    fail("源码撞到过滤，03-cao-chong/ 没有过滤账")


@collect_errors
def check_sink_runtime(run_root: Path, notes: list[str]) -> None:
    if is_website(envelope(run_root)):
        notes.append("website_skip_sink_runtime")
        return
    path = run_root / "01-guo-jia" / "sink-runtime-modules.json"
    if not path.is_file():
        fail("missing 01-guo-jia/sink-runtime-modules.json（危险 sink 模块扫描/拉起回执）")
    data = load_json(path)
    if not data:
        fail("sink-runtime-modules.json is not a JSON object")
    scans = data.get("scans")
    if not isinstance(scans, dict):
        fail("sink-runtime-modules.scans 必须是对象")
    for key in SINK_SCAN_KEYS:
        row = scans.get(key)
        if not isinstance(row, dict):
            fail(f"sink-runtime-modules.scans.{key} 必须是对象")
        searched = str(row.get("searched") or "").strip()
        if len(searched) < 8:
            fail(f"sink-runtime-modules.scans.{key}.searched 太短")
        hits = row.get("hits")
        if not isinstance(hits, int) or hits < 0:
            fail(f"sink-runtime-modules.scans.{key}.hits 必须是 >=0 的整数")
    items = data.get("items")
    if not isinstance(items, list):
        fail("sink-runtime-modules.items 必须是数组")
    declared = sum(int(scans[k]["hits"]) for k in SINK_SCAN_KEYS)
    if declared > 0 and len(items) < 1:
        fail("scans.hits>=1 但 items 为空；每条危险 sink 必须入账并尝试拉起")
    for i, item in enumerate(items):
        if not isinstance(item, dict):
            fail(f"sink-runtime-modules.items[{i}] 必须是对象")
        sink = str(item.get("sink") or "").strip()
        module = str(item.get("module") or "").strip()
        runtime = str(item.get("runtime") or "").strip().lower()
        if len(sink) < 4 or len(module) < 2:
            fail(f"items[{i}] 必须写 sink 和 module")
        if runtime not in {"started", "blocked"}:
            fail(f"items[{i}].runtime 必须是 started|blocked")
        evidence = item.get("evidence")
        if not isinstance(evidence, list) or len(evidence) < 1:
            fail(f"items[{i}].evidence 至少一份听口或启动失败原件")
        for rel in evidence:
            if not isinstance(rel, str) or not rel.strip():
                fail(f"items[{i}].evidence 项必须是路径字符串")
            f = resolve_inside(run_root, rel, f"sink-runtime.items[{i}].evidence")
            if not f.is_file() or f.stat().st_size < 40:
                fail(f"sink-runtime evidence missing or too small: {rel}")
        if runtime == "blocked":
            reason = str(item.get("reason") or "")
            if any(k.lower() in reason.lower() for k in SINK_FAKE_BLOCK):
                fail(
                    "sink blocked 写成『只起了登录壳/聚合注释/不值当/本场只测 admin』；"
                    "pom 注释掉 iot/pay/report ≠ 没这面，必须尝试拉起，客观失败才 blocked"
                )
            gap = str(item.get("coverage_gap") or "").strip()
            if any(k.lower() in gap.lower() for k in SINK_FAKE_BLOCK):
                fail(
                    "sink coverage_gap 写成『聚合注释/不值当/只起登录壳』；"
                    "注释掉模块不是启动失败原件"
                )
            if len(gap) < 8:
                fail(f"items[{i}] blocked 必须写 coverage_gap")
    notes.append("sink_runtime_ok")


@collect_errors
def check_material_provenance(run_root: Path, notes: list[str]) -> None:
    """批三十七（红队三轮 P0-3）：材料来源双账——H-22 只防「中途改材料」，两个残留口：
    ①开局投毒（解压后、算哈希前塞后门——清单自洽）；②清单缩水（manifest 是操作者落盘的，
    手写只含引用文件的假清单，闸不核覆盖面）。
    修：a) 覆盖面机械核——闸按 manifest.path 重走计数 vs file_count，随机抽 10 件重算 sha；
    b) 原档账——信封登记 material_source_path 的场，run/material-manifest-src.json 必落
    （material_hash.py 对原 ZIP 现在输出 zip_entries 逐成员账），白盒 verified 的 source_refs
    出处必须同时命中解压树账与原档账（sha 一致）——出处文件不在原档 = 开局投毒。
    era≥20261015 生效；未登记原档路径的场记 waiver 提示（材料非 ZIP/目录原档不适用）。"""
    import hashlib as _hl
    import random as _rd

    m = effective_run_date(run_root)
    new_era = bool(m and m.group(0) >= H22_STRICT_ERA)
    manifest = load_json(run_root / "run" / "material-manifest.json")
    if not manifest or not isinstance(manifest.get("files"), list):
        notes.append("provenance_skip(no manifest)")
        return
    root = str(manifest.get("path") or "").strip()
    files = manifest["files"]
    if new_era:
        # ① 覆盖面重走
        if not root or not Path(root).is_dir():
            if new_era:
                fail("H-22：material-manifest.path 指不到目录——覆盖面核无法执行（批三十七），清单须带真实材料根")
        else:
            walked = [
                p for p in Path(root).rglob("*")
                if p.is_file() and not any(part in {"node_modules", ".git", "__pycache__"} for part in p.parts)
            ]
            fc = manifest.get("file_count")
            if isinstance(fc, int) and fc > 0:
                if abs(len(walked) - fc) > max(3, fc // 20):
                    fail(
                        f"material-manifest.file_count={fc} 但闸重走 {root} 实数 {len(walked)}——清单缩水/膨胀（批三十七覆盖面核）；"
                        "重跑 material_hash.py 刷新清单"
                    )
                else:
                    notes.append(f"provenance_filecount_ok({fc})")
            # 抽 10 重算 sha（清单哈希是对的、文件被换的「账实分离」防不了 H-22 比对——这里堵）
            sample = _rd.sample(files, min(10, len(files)))
            bad = []
            non_dict = 0
            for it in sample:
                if not isinstance(it, dict):
                    # 批四十五 B-17：非 dict 条目计入——旧版 continue 让全字符串形态清单
                    # 抽样核零执行仍记 provenance_sample_ok(10)
                    non_dict += 1
                    continue
                rel = str(it.get("path") or "").replace("\\", "/").lstrip("/")
                want = str(it.get("sha256") or "").lower()
                p = Path(root) / rel
                if not p.is_file():
                    bad.append(rel + "(missing)")
                    continue
                if _hl.sha256(p.read_bytes()).hexdigest() != want:
                    bad.append(rel + "(sha)")
            if bad:
                fail("material-manifest 抽样重算不一致（清单与盘上文件账实分离，批三十七）：" + "；".join(bad[:6]))
            elif non_dict:
                fail(
                    f"material-manifest.files 抽样 {non_dict}/{len(sample)} 条不是对象"
                    f"（旧版全字符串清单形态）——抽样核零执行（批四十五 B-17）；"
                    "重跑 material_hash.py 生成 [{'path':…,'sha256':…}] 对象条目清单后重跑 close"
                )
            else:
                notes.append(f"provenance_sample_ok({len(sample)})")
    # ② 原档账双查
    env = envelope(run_root)
    src_path = str(env.get("material_source_path") or "").strip()
    if not src_path:
        if new_era and not is_website(env):
            notes.append("material_source_path_missing(开局投毒盲区 waiver：登记原档路径+落 src 账可关死；无原档材料如实记)")
        return
    src_manifest = load_json(run_root / "run" / "material-manifest-src.json")
    if not src_manifest:
        if new_era:
            fail(
                f"信封登记 material_source_path={src_path} 但缺 run/material-manifest-src.json——"
                "原档账未落（material_hash.py --file <原档> 输出重定向落盘，批三十七）；开局投毒无原档账不可检出"
            )
        return
    src_index: dict[str, str] = {}
    if isinstance(src_manifest.get("zip_entries"), list):
        for e in src_manifest["zip_entries"]:
            if isinstance(e, dict) and e.get("path"):
                src_index[str(e["path"]).replace("\\", "/").lower()] = str(e.get("sha256") or "").lower()
    for e in src_manifest.get("files") or []:
        if isinstance(e, dict) and e.get("path"):
            src_index.setdefault(str(e["path"]).replace("\\", "/").lstrip("/").lower(), str(e.get("sha256") or "").lower())
    if not src_index:
        notes.append("provenance_src_index_empty(原档账无条目——单文件原档非 ZIP，双账不适用)")
        return
    # 批五十八 A（摸鱼洞② 原档账手编）：此前只信账不重开——原档账可以对着毒化副本算到自洽。
    # 收口重开 material_source_path 实档：整档 sha256/size + 成员数 + 确定性抽样成员哈希逐项比对。
    if new_era and str(src_manifest.get("kind") or "").lower() == "zip":
        import hashlib as _hl58
        import zipfile as _zf58

        sp58 = Path(src_path)
        if not sp58.is_file():
            notes.append("provenance_src_reopen_skip(原档已不在盘上，重开比对跳过——换机/清理场景如实)")
        else:
            _bad58: list[str] = []
            _h58 = _hl58.sha256()
            with open(sp58, "rb") as _fh58:
                for _ch in iter(lambda: _fh58.read(1 << 20), b""):
                    _h58.update(_ch)
            _arc58 = _h58.hexdigest()
            _m_arc58 = str(src_manifest.get("sha256") or "").lower()
            _m_size58 = src_manifest.get("size_bytes")
            if _m_arc58 and _arc58 != _m_arc58:
                _bad58.append(f"整档 sha256 账 {_m_arc58[:12]}… vs 实档 {_arc58[:12]}…")
            if isinstance(_m_size58, int) and _m_size58 != sp58.stat().st_size:
                _bad58.append(f"size 账 {_m_size58} vs 实档 {sp58.stat().st_size}")
            try:
                with _zf58.ZipFile(sp58) as _z58:
                    _names58 = {i.filename.replace("\\", "/"): i for i in _z58.infolist() if not i.is_dir()}
                    _m_entries58 = [e for e in (src_manifest.get("zip_entries") or []) if isinstance(e, dict) and e.get("path")]
                    if _m_entries58 and len(_names58) != len(_m_entries58):
                        _bad58.append(f"成员数账 {len(_m_entries58)} vs 实档 {len(_names58)}")
                    _idx58 = {str(e.get("path")).replace("\\", "/"): e for e in _m_entries58}
                    _sorted58 = sorted(_names58)
                    if len(_sorted58) <= 12:
                        _pick58 = _sorted58
                    else:
                        _pick58 = [_sorted58[int(round(i * (len(_sorted58) - 1) / 11))] for i in range(12)]
                    for _pn58 in _pick58:
                        _me58 = _idx58.get(_pn58)
                        if _me58 is None:
                            _bad58.append(f"成员 {_pn58} 不在账内")
                            continue
                        _hm58 = _hl58.sha256(_z58.read(_names58[_pn58])).hexdigest()
                        if str(_me58.get("sha256") or "").lower() != _hm58:
                            _bad58.append(f"成员 {_pn58} sha 账实不符")
            except Exception as _exc58:  # noqa: BLE001
                _bad58.append(f"重开 ZIP 失败：{_exc58}")
            if _bad58:
                fail(
                    "原档账与实档重开比对不符（批五十八 A，摸鱼洞②：原档账可对毒化副本自洽手编）——"
                    + "；".join(_bad58[:5])
                    + f"（账=run/material-manifest-src.json，实档={src_path}）；属官方包演进/换件如实登记 waiver 并重算账，手编账按 H-21 论处"
                )
            else:
                notes.append("provenance_src_reopen_ok(整档+成员抽样与实档一致)")
    jdir = run_root / "reports" / "json"
    checked = 0
    for jf in sorted(jdir.glob("*.json")) if jdir.is_dir() else []:
        data = load_json(jf)
        if not data:
            continue
        for ref in data.get("source_refs") or []:
            if not isinstance(ref, dict):
                continue
            fp = str(ref.get("file") or "").replace("\\", "/").strip().lstrip("/").lower()
            want = str(ref.get("sha256") or "").strip().lower()
            if not fp or not want:
                continue
            hit = None
            if fp in src_index:
                hit = src_index[fp]
            else:
                tail = "/" + fp
                for k, v in src_index.items():
                    if k.endswith(tail):
                        hit = v
                        break
            if hit is None:
                fail(
                    f"{jf.name}.source_refs 出处 {fp} 不在原档账（material-manifest-src.json）——"
                    "文件是解压后新增 = 开局投毒（批三十七），该链作废"
                )
                continue
            if hit != want:
                fail(
                    f"{jf.name}.source_refs 出处 {fp} 与原档账 sha 不一致——解压树文件被改过再算清单"
                    "（开局投毒变体，批三十七），该链作废"
                )
                continue
            checked += 1
    if checked:
        notes.append(f"provenance_src_ok({checked})")


def _fake_source(text: str, needles: tuple[str, ...]) -> str | None:
    low = text.lower()
    for k in needles:
        if k.lower() in low:
            return k
    return None


LEDGER_STRICT_ERA = "20261015"  # 批三十五 P1-3 生效线（深挖 27 的机械落地；存量场不追溯）


def _ledger_material_roots(run_root: Path, data: dict) -> list[Path]:
    """账本指向的可验基准（批三十五 P1-3）：source_root 优先，回退开局清单根与场内快照。

    多基准任一命中即算可解析——keyword 账可能扫的是快照而清单根指材料原处，宁可多基准防误伤。"""
    roots: list[Path] = []
    sr = str(data.get("source_root") or "").strip()
    if sr and Path(sr).is_dir():
        roots.append(Path(sr))
    manifest = load_json(run_root / "run" / "material-manifest.json") or {}
    mp = str(manifest.get("path") or "").strip()
    if mp and Path(mp).is_dir():
        roots.append(Path(mp))
    snap = run_root / "snapshot"
    if snap.is_dir():
        roots.append(snap)
    return roots


def _resolve_ledger_file(run_root: Path, roots: list[Path], loc: str) -> bool:
    """剥离行号后按基准解析（批三十五 P1-3：编造 file:line 的手写账拦截）。

    无可验基准（材料不在本机/存量场）返回 True 不拦——有基准才拦，防误伤。
    批四十五 B-8：绝对路径不再「存在即算解析到」——resolve 后必须落在 run_root/材料基准内，
    C:/Windows/win.ini 类场外系统文件不算账本命中，否则 fail。"""
    p = Path(loc)
    if p.is_absolute():
        rp = p.resolve()
        if not rp.is_file():
            return False
        for base in [run_root.resolve()] + [r.resolve() for r in roots]:
            try:
                rp.relative_to(base)
                return True
            except ValueError:
                continue
        fail(
            f"账本 file 指针绝对路径越界（{loc}）——必须落在 run_root/材料根内"
            "（批四十五 B-8：场外系统文件不算账本命中）；指回材料相对路径或场内绝对路径"
        )
    if not roots:
        return True
    return any((r / loc).is_file() for r in roots)


def _check_ledger_items_resolved(run_root: Path, data: dict, items: list, ledger: str, notes: list[str]) -> None:
    """批三十五 P1-3（深挖 27 机械件）：账本 items 的 file 指向必须真实存在于材料基准。"""
    m = effective_run_date(run_root)
    if not m or m.group(0) < LEDGER_STRICT_ERA:
        return
    roots = _ledger_material_roots(run_root, data)
    if not roots:
        # 批三十六（红队二轮 P0-3）：基准全空从 note 升 fail——自报 source_root 指谎+清单缺 path
        # = 指向解析整体逃逸；era≥20261015 有命中的账不许「无可验基准」
        _m_lr = effective_run_date(run_root)
        if items and _m_lr and _m_lr.group(0) >= H22_STRICT_ERA:
            fail(
                f"{ledger} 有命中但材料基准全空（source_root 指不到目录且清单缺 path）——"
                "指向解析被整体跳过（批三十六硬拦）；补 source_root 为材料根绝对路径或补清单 path"
            )
        notes.append(f"{ledger}_material_root_unknown(深挖 27：source_root/清单根/快照均不可知，指向解析未执行)")
        return
    bad = []
    for i, item in enumerate(items):
        if not isinstance(item, dict):
            continue
        loc = str(item.get("file") or item.get("path") or "").strip()
        if not loc:
            continue
        clean = re.split(r":\d+$", loc)[0]
        if not _resolve_ledger_file(run_root, roots, clean):
            bad.append(f"items[{i}] {loc}")
    if bad:
        fail(
            f"{ledger} 命中指向在材料基准解析不到（深挖 27 / 批三十五）："
            + "；".join(bad[:6])
            + "——手写/编造 file:line 的垃圾账；重跑 walker 或补 source_root"
        )
    notes.append(f"{ledger}_items_resolved({len(items)})")


@collect_errors
def check_keyword_scan(run_root: Path, notes: list[str]) -> None:
    if is_website(envelope(run_root)):
        notes.append("website_skip_keyword_scan")
        return
    path = run_root / "01-guo-jia" / "keyword-scan.json"
    if not path.is_file():
        fail(
            "missing 01-guo-jia/keyword-scan.json（关键字定位是郭嘉开局源码账）；"
            "禁止用曹操链审 grep / swagger / 菜单顶"
        )
    data = load_json(path)
    if not data:
        fail("keyword-scan.json is not a JSON object")
    scans = data.get("scans")
    if not isinstance(scans, dict):
        fail("keyword-scan.scans 必须是对象")
    for key in KEYWORD_SCAN_KEYS:
        row = scans.get(key)
        if not isinstance(row, dict):
            fail(f"keyword-scan.scans.{key} 必须是对象")
        searched = str(row.get("searched") or "").strip()
        if len(searched) < 8:
            fail(f"keyword-scan.scans.{key}.searched 太短")
        fake = _fake_source(searched, KEYWORD_FAKE_SOURCE)
        if fake:
            fail(
                f"keyword-scan.scans.{key}.searched 写成『{fake}』；"
                "关键字定位必须扫源码，禁止 swagger/api-docs/菜单/链审 grep 顶"
            )
        hits = row.get("hits")
        if not isinstance(hits, int) or hits < 0:
            fail(f"keyword-scan.scans.{key}.hits 必须是 >=0 的整数")
    items = data.get("items")
    if not isinstance(items, list):
        fail("keyword-scan.items 必须是数组")
    declared = sum(int(scans[k]["hits"]) for k in KEYWORD_SCAN_KEYS)
    if declared > 0 and len(items) < 1:
        fail("keyword-scan scans.hits>=1 但 items 为空；命中必须写 file:line")
    for i, item in enumerate(items):
        if not isinstance(item, dict):
            fail(f"keyword-scan.items[{i}] 必须是对象")
        loc = str(item.get("file") or item.get("path") or "").strip()
        if len(loc) < 8:
            fail(f"keyword-scan.items[{i}] 必须写源码 file/path")
        fake = _fake_source(loc + " " + str(item.get("note") or ""), KEYWORD_FAKE_SOURCE)
        if fake:
            fail(
                f"keyword-scan.items[{i}] 来源是『{fake}』；"
                "命中必须是源码路径，不能是 swagger/菜单/链审"
            )
    _check_ledger_items_resolved(run_root, data, items, "keyword-scan", notes)
    notes.append("keyword_scan_ok")


ENTRY_LANG_KEYS = (
    ("php", "php_request"),
    ("java", "java_request"),
    ("js", "js_request"),
    ("py", "py_request"),
    ("go", "go_request"),
    ("rb", "rb_request"),
    ("rs", "rs_request"),
    ("c", "c_request"),
    ("cs", "cs_request"),
)


def _check_entry_zero_self_check(data: dict, scans: dict, notes: list[str]) -> None:
    """入口键零命中且该语言有文件 → 必须留自查痕迹（工具异常先排查，不许默默绕开）。"""
    coverage = data.get("coverage")
    files_by_lang = (coverage.get("files_by_lang") or {}) if isinstance(coverage, dict) else {}
    zero_langs = []
    for lang, key in ENTRY_LANG_KEYS:
        if files_by_lang.get(lang, 0) > 0:
            row = scans.get(key)
            if isinstance(row, dict) and row.get("hits") == 0:
                zero_langs.append(key)
    if not zero_langs:
        return
    if isinstance(coverage, dict) and "entry_zero_cross_check" in coverage:
        notes.append("entry_zero_cross_check_ok")
        return
    blob = json.dumps(data, ensure_ascii=False)
    for mark in ("复核", "cross_check", "规则盲区"):
        if mark in blob:
            notes.append("entry_zero_manual_note_ok")
            return
    fail(
        f"auto-chain-scan 入口键零命中但对应语言文件非零（{('、'.join(zero_langs))}）："
        "工具异常先排查再绕开——重跑新版 walker 会自动记 coverage.entry_zero_cross_check"
        "（mismatch=疑似规则盲区，grep 复核后记 coverage_gap）；旧账手写复核注记也认。"
        "入口面可以改走 keyword-scan/js-collection，但必须留排查痕迹"
    )


@collect_errors
def check_auto_chain_scan(run_root: Path, notes: list[str]) -> None:
    if is_website(envelope(run_root)):
        notes.append("website_skip_auto_chain_scan")
        return
    path = run_root / "01-guo-jia" / "auto-chain-scan.json"
    if not path.is_file():
        fail(
            "missing 01-guo-jia/auto-chain-scan.json（自动链扫描是郭嘉开局 walker 账）；"
            "禁止用关键字 grep / JS 清单 / swagger / 菜单 / 曹操链审顶；"
            "有自动链也不能免 keyword-scan / sink-runtime / CVE；JS 仅有前端或网站才必须"
        )
    data = load_json(path)
    if not data:
        fail("auto-chain-scan.json is not a JSON object")
    if data.get("candidate_only") is not True:
        fail("auto-chain-scan.candidate_only 必须是 true；walker 命中不是洞")
    engine = str(data.get("engine") or "")
    root = str(data.get("source_root") or "")
    fake = _fake_source(engine + " " + root, CHAIN_FAKE_SOURCE)
    if fake:
        fail(
            f"auto-chain-scan 来源写成『{fake}』；"
            "必须跑 scripts/auto_chain_scan.py 走源码（.inc 当 PHP，include/ 仍读），"
            "禁止 swagger/菜单/链审顶"
        )
    eng_low = engine.lower().replace("\\", "/")
    for needle in CHAIN_ENGINE_FAKE:
        if needle in eng_low:
            fail(
                f"auto-chain-scan.engine 写成『{needle}』；"
                "自动链是独立 walker，不能拿关键字/JS/sink/CVE 账顶"
            )
    if "auto_chain_scan" not in eng_low and "auto-chain-scan" not in eng_low:
        # 批四十五 B-18：engine 必须指名 walker（auto_chain_scan/auto-chain-scan）——
        # 旧版任意 ≥8 字符串即过，伪 walker 名手写账无差别放行
        fail(
            "auto-chain-scan.engine 必须写 walker 脚本（scripts/auto_chain_scan.py，批四十五 B-18）"
            "——engine 名不含 auto_chain_scan/auto-chain-scan 的账按手写论处"
        )
    # 批四十九（r18 A-R2-01）：walker 的跳过警告必须被消费——「跳过含真洞文件→账面干净→闸全绿」
    # 两条通道（RecursionError 记账 / py3.14 SyntaxError 静默）此前都无人读；现在未处置警告=必须补扫或交曹操
    _warns = data.get("scan_warnings")
    if isinstance(_warns, list) and _warns:
        _unresolved = [
            w for w in _warns
            if not (isinstance(w, dict) and str(w.get("resolution", "")).strip())
        ]
        if _unresolved:
            fail(
                f"auto-chain-scan.scan_warnings 有 {len(_unresolved)} 条未处置跳过警告（首条：{str(_unresolved[0])[:80]}…）"
                "——被跳过文件可能是藏洞面（r18 A-R2-01）：补扫该文件入账，或在警告条目里补 resolution 键"
                "（file+reviewed_by+人工复核结论）后重跑"
            )
        notes.append(f"scan_warnings_resolved({len(_warns)} 条已带 resolution)")
    scanned = data.get("files_scanned")
    if not isinstance(scanned, int) or scanned < 0:
        fail("auto-chain-scan.files_scanned 必须是 >=0 的整数")
    scans = data.get("scans")
    if not isinstance(scans, dict):
        fail("auto-chain-scan.scans 必须是对象")
    for key in CHAIN_SCAN_KEYS:
        row = scans.get(key)
        if not isinstance(row, dict):
            fail(f"auto-chain-scan.scans.{key} 必须是对象")
        searched = str(row.get("searched") or "").strip()
        if len(searched) < 8:
            fail(f"auto-chain-scan.scans.{key}.searched 太短")
        fake = _fake_source(searched, CHAIN_FAKE_SOURCE)
        if fake:
            fail(
                f"auto-chain-scan.scans.{key}.searched 写成『{fake}』；"
                "必须扫源码 source/sink，禁止 swagger/菜单/链审顶"
            )
        hits = row.get("hits")
        if not isinstance(hits, int) or hits < 0:
            fail(f"auto-chain-scan.scans.{key}.hits 必须是 >=0 的整数")
    _check_entry_zero_self_check(data, scans, notes)
    items = data.get("items")
    if not isinstance(items, list):
        fail("auto-chain-scan.items 必须是数组")
    declared = sum(int(scans[k]["hits"]) for k in CHAIN_SCAN_KEYS)
    if declared > 0 and len(items) < 1:
        fail("auto-chain-scan scans.hits>=1 但 items 为空；钉到的 sink 必须入账")
    for i, item in enumerate(items):
        if not isinstance(item, dict):
            fail(f"auto-chain-scan.items[{i}] 必须是对象")
        if item.get("candidate_only") is not True:
            fail(f"auto-chain-scan.items[{i}].candidate_only 必须是 true")
        st = str(item.get("status") or "candidate").strip().lower()
        if st in CHAIN_FORBIDDEN_STATUS:
            fail(
                f"auto-chain-scan.items[{i}].status={st}；"
                "自动链只许 candidate，禁止写成 verified/finding"
            )
        loc = str(item.get("file") or item.get("path") or "").strip()
        sink = item.get("sink") if isinstance(item.get("sink"), dict) else {}
        if len(loc) < 4:
            loc = str(sink.get("file") or "").strip()
        if len(loc) < 4:
            fail(f"auto-chain-scan.items[{i}] 必须写源码 file（可在 include/*.inc）")
        fake = _fake_source(loc + " " + str(item.get("note") or ""), CHAIN_FAKE_SOURCE)
        if fake:
            fail(
                f"auto-chain-scan.items[{i}] 来源是『{fake}』；"
                "命中必须是源码路径，不能是 swagger/菜单/链审"
            )
    _check_ledger_items_resolved(run_root, data, items, "auto-chain-scan", notes)
    # 批三十五 P1-3：files_scanned 与开局清单文件数同数量级对账（闸自己数，不认自报——键齐量少的手写账）
    _m35 = effective_run_date(run_root)
    if _m35 and _m35.group(0) >= LEDGER_STRICT_ERA and isinstance(scanned, int) and scanned > 0:
        _manifest35 = load_json(run_root / "run" / "material-manifest.json") or {}
        _files35 = _manifest35.get("files")
        if isinstance(_files35, list) and _files35:
            _n35 = len(_files35)
            if max(_n35, scanned) / min(_n35, scanned) >= 10:
                fail(
                    f"auto-chain-scan.files_scanned={scanned} 与开局清单 {_n35} 个文件差一个数量级"
                    "——手写垃圾账（深挖 27：files_scanned 须与闸实数同数量级）"
                )
            notes.append(f"auto_chain_files_scanned_magnitude_ok({scanned}/{_n35})")
    notes.append("auto_chain_scan_ok")


def load_jsonl_objects(path: Path) -> list[dict]:
    try:
        # 批四十五 B-13：utf-8-sig（BOM 兼容）+ UnicodeDecodeError 捕获——0xff 头/GBK 文本
        # 旧版裸崩丢已收集 failures 无回执，现走结构化 fail
        text = path.read_text(encoding="utf-8-sig")
    except OSError:
        return []
    except UnicodeDecodeError as exc:
        fail(
            f"{path} 不是 UTF-8 文本（{exc}）——jsonl 原件须 UTF-8 落盘"
            "（批四十五 B-13：GBK/二进制内容转码后再进账，不裸崩）"
        )
    records: list[dict] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(item, dict):
            records.append(item)
    return records


@collect_errors
def check_hybrid_discovery(run_root: Path, notes: list[str]) -> None:
    if is_website(envelope(run_root)):
        notes.append("website_skip_hybrid_discovery")
        return
    path = run_root / "01-guo-jia" / "hybrid-discovery.jsonl"
    if not path.is_file():
        fail(
            "missing 01-guo-jia/hybrid-discovery.jsonl（召回层跟 Deep：PHP/JS/Ruby 先正则，Java 等先向量，混栈 mixed）；"
            "跑 scripts/hybrid_discovery.py；不能顶 auto-chain-scan / 关键字 / JS / sink / CVE"
        )
    records = load_jsonl_objects(path)
    if not records:
        fail("hybrid-discovery.jsonl 必须是 JSONL，至少一行 hybrid_manifest")
    manifest = next((r for r in records if r.get("record_type") == "hybrid_manifest"), records[0])
    if manifest.get("candidate_only") is not True:
        fail("hybrid-discovery.candidate_only 必须是 true；向量/正则命中不是洞")
    blob = json.dumps(manifest, ensure_ascii=False)
    fake = _fake_source(blob, CHAIN_FAKE_SOURCE)
    if fake:
        fail(f"hybrid-discovery 来源写成『{fake}』；必须走源码召回，禁止 swagger/菜单/链审顶")
    strategy = str(manifest.get("strategy") or "").strip()
    if strategy in HYBRID_UNIFIED_FAKE or strategy not in HYBRID_STRATEGY_OK:
        fail(
            f"hybrid-discovery.strategy={strategy or '空'}；"
            "必须跟 Deep：PHP/JS/Ruby regex_first，Java/Python/Go/C#/Kotlin/Scala/Swift vector_first，"
            "混栈 mixed。禁止全语言同一套 regex_after_no_vector"
        )
    if manifest.get("mini_unified") is True:
        fail("hybrid-discovery.mini_unified=true；禁止把 Deep 分桶抹成全语言同一套")
    if manifest.get("vector_success") is not True and "vector_key_check" not in manifest:
        fail(
            "hybrid-discovery 向量没命中/失败但 manifest 缺 vector_key_check："
            "先查密钥再下结论——重跑 scripts/hybrid_discovery.py 会自动带上"
            "（key_missing 先补 secrets/embedding.env 重跑；key_present 属网络/服务端，重试一次再落 lexical）；"
            "不得直接当『向量不可用』收场"
        )
    by_lang = manifest.get("strategy_by_language")
    if isinstance(by_lang, dict) and by_lang:
        for lang, order in by_lang.items():
            lang_l = str(lang).strip().lower()
            order_s = str(order).strip()
            if lang_l in HYBRID_REGEX_FIRST_LANGS and order_s != "regex_first":
                fail(
                    f"hybrid-discovery.strategy_by_language.{lang}={order_s}；"
                    "PHP/JS/Ruby 必须 regex_first（Deep）"
                )
            if lang_l in HYBRID_VECTOR_FIRST_LANGS and order_s != "vector_first":
                fail(
                    f"hybrid-discovery.strategy_by_language.{lang}={order_s}；"
                    "Java/Python/Go/C#/Kotlin/Scala/Swift 必须 vector_first（Deep）"
                )
        has_regex = any(str(k).lower() in HYBRID_REGEX_FIRST_LANGS for k in by_lang)
        has_vector = any(str(k).lower() in HYBRID_VECTOR_FIRST_LANGS for k in by_lang)
        if has_regex and has_vector and strategy != "mixed":
            fail("混栈必须 strategy=mixed（Deep）；不能全语言同一套")
        if has_regex and not has_vector and strategy != "regex_first":
            fail("只有 PHP/JS/Ruby 时 strategy 必须 regex_first")
        if has_vector and not has_regex and strategy != "vector_first":
            fail("只有 Java/Python/Go 等时 strategy 必须 vector_first")
    for i, rec in enumerate(records):
        if rec.get("candidate_only") is not True:
            fail(f"hybrid-discovery.jsonl[{i}].candidate_only 必须是 true")
        st = str(rec.get("status") or "").strip().lower()
        if st in CHAIN_FORBIDDEN_STATUS:
            fail(f"hybrid-discovery.jsonl[{i}].status={st}；召回只许 candidate")
    notes.append("hybrid_discovery_ok")


def _guo_jia_text_blob(run_root: Path) -> str:
    d = run_root / "01-guo-jia"
    if not d.is_dir():
        return ""
    parts = []
    env = envelope(run_root)
    parts.append(json.dumps(env, ensure_ascii=False) if env else "")
    for name in (
        "methodology-gap.json",
        "not-needed.json",
        "identity.json",
        "collection-notes.md",
        "stack.json",
    ):
        p = d / name
        if p.is_file():
            parts.append(blob_text(p, 80_000))
    return "\n".join(parts).lower()


def _has_token(blob: str, tokens: tuple[str, ...]) -> bool:
    return any(t.lower() in blob for t in tokens)


@collect_errors
def check_methodology_gap(run_root: Path, notes: list[str]) -> None:
    if is_website(envelope(run_root)):
        notes.append("website_skip_methodology_gap")
        return
    blob = _guo_jia_text_blob(run_root)
    stall = _fake_source(blob, METHODOLOGY_STALL)
    if stall:
        fail(
            f"郭嘉用『{stall}』停工；本包长文只装箱 PHP/Java，"
            "其它栈必须 walker 短规则继续扫、按入口/链路/反证/覆盖继续追，禁止等文"
        )
    path = run_root / "01-guo-jia" / "methodology-gap.json"
    if not path.is_file():
        notes.append("methodology_gap_optional_ok")
        return
    data = load_json(path)
    if not data:
        fail("methodology-gap.json is not a JSON object")
    if data.get("candidate_only") is not True:
        fail("methodology-gap.candidate_only 必须是 true；自建方法不是洞")
    packed_m = str(data.get("packed_methodology") or "").strip().lower()
    if packed_m not in PACKED_METHODOLOGY_OK:
        fail("methodology-gap.packed_methodology 必须是 none|php|java|mixed|self")
    lang = str(data.get("language") or "").strip()
    if len(lang) < 2:
        fail("methodology-gap.language 必须写本栈语言")
    searched = str(data.get("searched") or "").strip()
    reasoned = str(data.get("reasoned") or "").strip()
    if len(searched) < 8:
        fail("methodology-gap.searched 必须写搜了什么（公开资料/自身检索），不能空等")
    if len(reasoned) < 8:
        fail("methodology-gap.reasoned 必须写自己怎么追入口/链路，不能空等")
    fake = _fake_source(searched + " " + reasoned, CHAIN_FAKE_SOURCE)
    if fake:
        fail(f"methodology-gap 写成『{fake}』；自建方法也要追源码，禁止 swagger/菜单顶")
    stall2 = _fake_source(searched + " " + reasoned + " " + str(data.get("notes") or ""), METHODOLOGY_STALL)
    if stall2:
        fail(f"methodology-gap 仍写『{stall2}』停工；缺口账是搜/想的记录，不是免挖")
    st = str(data.get("status") or "").strip().lower()
    if st in CHAIN_FORBIDDEN_STATUS:
        fail("methodology-gap.status 禁止写成 verified/finding")
    notes.append("methodology_gap_ok")


def role_has_work(d: Path) -> bool:
    for p in d.rglob("*"):
        if not p.is_file():
            continue
        if p.name.lower() in {"not-needed.json", "capability.json"}:
            continue
        if p.suffix.lower() in {".json", ".md", ".txt"} and p.stat().st_size >= 40:
            return True
    return False


def _find_material_file(run_root: Path, rel_or_name: str) -> Path | None:
    """批三十六：在材料基准（清单根/source_root/快照）定位账本 source 坐标指的文件——
    精确相对路径优先，basename 尾匹配兜底（防「pom.xml」写法与实际「server/pom.xml」层级差）。"""
    manifest = load_json(run_root / "run" / "material-manifest.json") or {}
    mp = str(manifest.get("path") or "").strip()
    files = manifest.get("files") if isinstance(manifest.get("files"), list) else []
    norm = rel_or_name.replace("\\", "/").strip().strip("/")
    if not norm:
        return None
    if mp:
        p = Path(mp) / norm
        if p.is_file():
            return p
    for f in files:
        if not isinstance(f, dict):
            continue
        fp = str(f.get("path") or "").replace("\\", "/").lstrip("/")
        if fp == norm or fp.endswith("/" + norm):
            cand = (Path(mp) / fp) if mp else Path(fp)
            if cand.is_file():
                return cand
    snap = run_root / "snapshot" / norm
    if snap.is_file():
        return snap
    return None


@collect_errors
def check_component_cve(run_root: Path, notes: list[str]) -> None:
    if is_website(envelope(run_root)):
        notes.append("website_skip_component_cve")
        return
    path = run_root / "01-guo-jia" / "component-cve-ledger.json"
    if not path.is_file():
        fail("missing 01-guo-jia/component-cve-ledger.json（第三方版本 CVE 查询账）")
    data = load_json(path)
    if not data:
        fail("component-cve-ledger.json is not a JSON object")
    scans = data.get("scans")
    if not isinstance(scans, dict):
        fail("component-cve-ledger.scans 必须是对象")
    for key in CVE_SCAN_KEYS:
        row = scans.get(key)
        if not isinstance(row, dict):
            fail(f"component-cve-ledger.scans.{key} 必须是对象")
        searched = str(row.get("searched") or "").strip()
        if len(searched) < 8:
            fail(f"component-cve-ledger.scans.{key}.searched 太短")
        hits = row.get("hits")
        if not isinstance(hits, int) or hits < 0:
            fail(f"component-cve-ledger.scans.{key}.hits 必须是 >=0 的整数")
    items = data.get("items")
    if not isinstance(items, list):
        fail("component-cve-ledger.items 必须是数组")
    declared = sum(int(scans[k]["hits"]) for k in CVE_SCAN_KEYS)
    if declared > 0 and len(items) < 1:
        fail("scans.hits>=1 但 items 为空；带版本的第三方必须入账并查 CVE")
    third_party = 0
    for i, item in enumerate(items):
        if not isinstance(item, dict):
            fail(f"component-cve-ledger.items[{i}] 必须是对象")
        comp = str(item.get("component") or "").strip()
        ver = str(item.get("version") or "").strip()
        source = str(item.get("source") or "").strip()
        query = str(item.get("cve_query") or "").strip().lower()
        if len(comp) < 2 or len(ver) < 1 or len(source) < 4:
            fail(f"items[{i}] 必须写 component、version、source")
        if query not in CVE_QUERY_OK:
            fail(f"items[{i}].cve_query 必须是 queried|first_party|no_public_db")
        if query == "first_party":
            continue
        third_party += 1
        evidence = item.get("query_evidence")
        if not isinstance(evidence, list) or len(evidence) < 1:
            fail(f"items[{i}] 第三方必须有 query_evidence（NVD/GHSA 查询落盘）")
        blobs = []
        for rel in evidence:
            if not isinstance(rel, str) or not rel.strip():
                fail(f"items[{i}].query_evidence 项必须是路径字符串")
            f = resolve_inside(run_root, rel, f"component-cve.items[{i}].query_evidence")
            if not f.is_file() or f.stat().st_size < 40:
                fail(f"component-cve query_evidence missing or too small: {rel}")
            try:
                blobs.append(f.read_text(encoding="utf-8", errors="ignore"))
            except OSError:
                fail(f"component-cve query_evidence unreadable: {rel}")
        blob = "\n".join(blobs)
        if query == "queried":
            # 批三十五 P1-3：新场认真实响应特征（HTTP/1. 行、公开库 URL、JSON results 键）；存量场旧词表不追溯
            _m36 = effective_run_date(run_root)
            _pat36 = CVE_EVIDENCE_STRICT_RE if (_m36 and _m36.group(0) >= LEDGER_STRICT_ERA) else CVE_EVIDENCE_RE
            if not _pat36.search(blob):
                fail(
                    f"items[{i}] queried 的 evidence 缺真实查询痕迹"
                    + ("（须含 HTTP/1. 响应行、公开库 URL 或 JSON results 键——纯『无条目』手记不算原件，深挖 27）" if _pat36 is CVE_EVIDENCE_STRICT_RE else "，禁止空说明顶查询")
                )
        cao_ren_rel = str(item.get("cao_ren_artifact") or "").strip()
        if not cao_ren_rel:
            fail(f"items[{i}] 第三方必须写 cao_ren_artifact")
        cr = resolve_inside(run_root, cao_ren_rel, f"component-cve.items[{i}].cao_ren_artifact")
        if not cr.is_file() or cr.stat().st_size < 40:
            fail(f"cao_ren_artifact missing or too small: {cao_ren_rel}")
        if "04-cao-ren" not in cao_ren_rel.replace("\\", "/"):
            fail(f"items[{i}].cao_ren_artifact 必须落在 04-cao-ren/")
        # 批三十六（红队二轮 P1-7）曹仁核对摘录锚：核对件须引用 source 文件 ≥15 字连续原文——
        # 「曹操核对/曹仁作业」环节此前全是自证，摘录锚保证至少真的打开过被核对文件
        _m_ca = effective_run_date(run_root)
        if _m_ca and _m_ca.group(0) >= H22_STRICT_ERA:
            _src_path = _find_material_file(run_root, source)
            if _src_path is None:
                fail(
                    f"items[{i}].source『{source}』在材料基准解析不到——曹仁核对无原文可锚（批三十六摘录锚）；"
                    "source 须写材料内真实相对路径"
                )
            else:
                _art_text = cr.read_text(encoding="utf-8", errors="ignore")
                _src_text = _src_path.read_text(encoding="utf-8", errors="ignore")
                if not _excerpt_in_file(_art_text, _src_text):
                    fail(
                        f"items[{i}] cao_ren_artifact 无摘录锚：须引用 source 文件（{source}）≥15 字连续原文"
                        "（批三十六）——核对件不得只写结论不引原文"
                    )
                # 批六十二③（摸鱼洞「摘录纯抄录」时序链）：核对件落盘须晚于被核 source 文件——
                # 先有账后有核对；source mtime 晚于核对件=「核对后现造账再抄摘录」倒挂（era≥20261017）
                _m62 = effective_run_date(run_root)
                if _m62 and _m62.group(0) >= "20261017":
                    try:
                        if _src_path.stat().st_mtime > cr.stat().st_mtime + 60:
                            fail(
                                f"items[{i}] 摘录锚时序倒挂：source『{source}』mtime 晚于核对件 {cr.name}"
                                "——先核对后改账的左手核右手（批六十二③）；确属文件整理搬动，曹操登记说明后重跑"
                            )
                    except OSError:
                        pass
    if third_party > 0:
        for dirname, label in (("04-cao-ren", "曹仁"), ("05-liu-ye", "刘晔")):
            d = run_root / dirname
            if not d.is_dir():
                fail(f"第三方版本已入账，但没有 {dirname}/")
            nn = d / "not-needed.json"
            if role_has_work(d):
                continue
            if nn.is_file():
                reason = str((load_json(nn) or {}).get("reason") or "")
                if any(k in reason for k in CVE_FAKE_NN):
                    fail(
                        f"{label} not-needed 写成『曹操收编/本地源码无情报/coverage_gap』；"
                        "带版本的第三方必须查 CVE，禁止假 not-needed"
                    )
                fail(f"第三方版本已入账，{label} 不得只交 not-needed.json，必须交版本/情报作业")
            fail(f"第三方版本已入账，{dirname}/ 没有 CVE/情报作业")
        notes.append("component_cve_third_party_ok")
    else:
        notes.append("component_cve_no_third_party")


CVE_IN_RANGE_RE = re.compile(r"in[_\s-]*range", re.IGNORECASE)
CVE_NOT_IN_RANGE_RE = re.compile(r"(not|out)[_\s-]*(of[_\s-]*)?in[_\s-]*range", re.IGNORECASE)
# in_range 区间命中的合法结论文案（写进账本 conclusion/disposition/verdict/status/note 任一字段即可）
CVE_CONCLUSION_RE = re.compile(
    r"实测闭环|实测通过|实测不成立|代码否证|blocked|coverage_gap|suspected"
    r"|file:\s*line|\.java:\d+|\.py:\d+|\.php:\d+|\.js:\d+|\.ts:\d+|\.xml:\d+|\.yml:\d+|\.properties:\d+"
    r"|回包|复测|disproved|verified",
    re.IGNORECASE,
)


@collect_errors
def check_cve_in_range_conclusion(run_root: Path, notes: list[str]) -> None:
    """close 门：刘晔查询账里 relation=in_range 的坐标每条必须有代码层/实测结论。

    pig 场教训：10 条 in_range、0 条实测，「曹操收编」记账就散场。收编只算分流，
    不算结论。结论认三类：实测闭环（回包原件）、代码否证（触发条件对不上源码，
    file:line）、blocked（带原件）。机械闸只能卡「结论字段存在且有内容」，
    结论真伪仍由曹操链审与复审负责。
    """
    liu_ye = run_root / "05-liu-ye"
    if not liu_ye.is_dir():
        return
    pending: list[str] = []
    total_in_range = 0
    for p in sorted(liu_ye.rglob("*.json*")):
        if p.name.lower() == "capability.json" or p.name.lower() == "not-needed.json":
            continue
        records: list[dict] = []
        if p.suffix.lower() == ".jsonl":
            records = load_jsonl_objects(p)
        elif p.suffix.lower() == ".json":
            data = load_json(p)
            if isinstance(data, list):
                records = [r for r in data if isinstance(r, dict)]
            elif isinstance(data, dict):
                for key in ("items", "queries", "results", "records"):
                    rows = data.get(key)
                    if isinstance(rows, list):
                        records.extend(r for r in rows if isinstance(r, dict))
        for i, rec in enumerate(records):
            rel = str(rec.get("relation") or rec.get("range_relation") or "")
            if not CVE_IN_RANGE_RE.search(rel) or CVE_NOT_IN_RANGE_RE.search(rel):
                continue
            coord = str(rec.get("coord") or rec.get("component") or f"{p.name}[{i}]")
            blob = " ".join(
                str(rec.get(k) or "")
                for k in ("conclusion", "disposition", "verdict", "status", "code_conclusion", "note", "notes")
            )
            total_in_range += 1
            if not CVE_CONCLUSION_RE.search(blob):
                pending.append(f"{coord}({p.name}:{i + 1})")
    if total_in_range == 0:
        notes.append("cve_in_range_none")
        return
    if pending:
        fail(
            "CVE in_range 区间命中缺代码层结论（收编/待办不算）："
            + "; ".join(pending[:10])
            + ("；等" if len(pending) > 10 else "")
            + f" 共 {len(pending)} 条未结。每条须：实测闭环（回包原件）/ 代码否证（file:line）/ blocked（原件）"
        )
    notes.append(f"cve_in_range_all_concluded({total_in_range})")


def claimed_frontend(run_root: Path) -> bool:
    env = envelope(run_root)
    if is_website(env):
        return False
    shots = load_json(run_root / "01-guo-jia" / "captcha-removed-three-shots.json") or {}
    if str(shots.get("page_no_widget") or "").lower() == "pass":
        return True
    idx = load_json(run_root / "run" / "captures-index.json") or {}
    return str(idx.get("ui") or "").lower() == "required"


@collect_errors
def check_obfuscation(run_root: Path, notes: list[str]) -> None:
    website = is_website(envelope(run_root))
    path = run_root / "01-guo-jia" / "js-collection.json"
    if website:
        site_p = run_root / "09-si-ma-yi" / "js-collection.json"
        if site_p.is_file():
            path = site_p
        elif not path.is_file():
            fail("网站必须有 09-si-ma-yi/js-collection.json（接口清单+混淆三件）；禁止跳过采集")
    if not path.is_file():
        if claimed_frontend(run_root):
            fail("有前端但缺少 01-guo-jia/js-collection.json")
        notes.append("no_js_collection")
        return
    data = load_json(path)
    if not data:
        fail("js-collection.json is not a JSON object")
    scanned = data.get("files_scanned")
    if not isinstance(scanned, int) or scanned < 1:
        fail("js-collection.files_scanned 必须 >=1；禁止随手写 obfuscation=false")
    source_blob = " ".join(
        [
            str(data.get("notes") or ""),
            str(data.get("source") or ""),
            str(data.get("origin") or ""),
        ]
    )
    fake_js = _fake_source(source_blob, JS_FAKE_SOURCE)
    if fake_js and not re.search(
        # 批四十五 B-19：免检白名单只认可解析 URL/host 形态（http(s)://… 或 host[:port]/path）
        # ——「自称 swagger + 含 .js 字样」的裸文字不再免检
        r'https?://[^\s"\']+|(?:^|[\s"\'（(、])[A-Za-z0-9][A-Za-z0-9.-]*\.[A-Za-z]{2,}(?::\d{2,5})?/[\w./-]+',
        source_blob,
    ):
        fail(
            f"js-collection 来源写成『{fake_js}』；"
            "JS 路径必须抽前端包（src/api / vue-router / bundle），"
            "禁止 swagger / v3/api-docs / menu/list 顶 js-collection"
            "（批四十五 B-19：source 须带可解析 URL/host 形态——http(s)://… 或 host[:port]/path——裸文字不免检）"
        )
    if claimed_frontend(run_root) or website:
        n = data.get("interface_count")
        if not isinstance(n, int) or n < 1:
            fail("有前端/网站但 interface_count < 1；空清单不算采集完成")
        ledger = data.get("ledger") or data.get("interfaces")
        if not isinstance(ledger, list) or len(ledger) < 1:
            fail("有前端/网站必须在 js-collection.ledger 或 interfaces 列出至少一条接口")
    ledger = data.get("ledger") or data.get("interfaces")
    if isinstance(ledger, list):
        # in=query|body|path|header：可选；写了就校验值，老账缺字段不 fail。
        for i, entry in enumerate(ledger):
            if not isinstance(entry, dict):
                continue
            ins: list[str] = []
            if entry.get("in") is not None:
                ins.append(str(entry["in"]).strip().lower())
            params = entry.get("params")
            if isinstance(params, list):
                for p in params:
                    if isinstance(p, dict):
                        if not str(p.get("name") or "").strip():
                            fail(f"js-collection.ledger[{i}].params 用 dict 就必须写 name")
                        if p.get("in") is not None:
                            ins.append(str(p["in"]).strip().lower())
            for v in ins:
                if v not in JS_IN_OK:
                    fail(f"js-collection in 只能是 query|body|path|header（ledger[{i}] 写了 '{v}'）")
    obf = data.get("obfuscation")
    if obf is True or str(obf).lower() in {"true", "yes", "present"}:
        for key in ("deobfuscated", "key_binding", "controllable_ledger"):
            if data.get(key) is not True:
                fail(f"有混淆但 js-collection.{key} 不是 true；采集未完成")
        notes.append("obfuscation_complete")
    elif obf is False:
        notes.append("no_obfuscation_claimed")
    else:
        fail("js-collection.obfuscation 必须是 JSON true 或 false")


@collect_errors
def check_complex_video(run_root: Path, notes: list[str]) -> None:
    # 2026-10-12 十改㉖（用户令修订 10-10 废止令）：复杂漏洞可录视频，录前周围必须干净。
    # 闸职责：①不强制录（判型归人工）②若 run/recordings/ 存在视频件，则要求对应关键帧确认件
    # （vision-reviews 里有 *frame* 或 *rec* 命名的 evidence_ok 件），画面干净与否归 faker/主会话复核。
    # 2026-10-15 批二十六：RF-VID-01 视觉前提同步——条文「必录条件（本场有视觉时）」批二十五已补，
    # 闸此前不读信封 review_mode，无视觉场（static_only/semantic_only）出高危 verified 会被误拦成
    # 条文许可、闸禁止的死锁。现开场即豁免：无视觉场不录（完整 CLI 链承载证据），整套录像检查跳过。
    # 2026-10-15 批二十七：豁免锚点扩 visual_available——「降级纯 API」黑盒场（SKILL 前端 JS 节：
    # 四步找不到前端、双拓扑照起、review_mode 仍 blackbox_review）整场无浏览器，不在 static_only
    # 语义内（血统词表：static_only=不起运行态），此前仍落死锁区。开场即确认没有浏览器时信封落
    # "visual_available": false（缺键/true/其它值=默认有视觉不豁免，fail-safe 方向保持）。
    env = envelope(run_root)
    if is_static_only(env):
        notes.append("complex_video_skip(static_only)")
        return
    if env.get("visual_available") is False:
        # 批五十七 W2：无视觉声明须凭环境失败账（≥6 次真实尝试）——口头自报不再免视频义务
        _ok, _det = _visual_env_attempts_ok(run_root)
        if _ok:
            notes.append("complex_video_skip(no visual，环境失败账在场：" + _det + ")")
            return
        fail(
            "信封宣称 visual_available=false 但" + _det + "——电脑默认有浏览器，无视觉豁免须凭 "
            "run/visual-env-attempts.json ≥6 次真实环境搭建失败尝试（when/tool/error，批五十七 W2）；"
            "缺账=声明无效，视频义务按有视觉照担"
        )
    rec_dir = run_root / "run" / "recordings"
    videos = [p for ext in ("*.mp4", "*.webm", "*.mkv", "*.mov") for p in rec_dir.glob(ext)] if rec_dir.is_dir() else []
    # 十一改㉗（2026-10-12）：高危/严重级 finding 录视频必交——reports/json 里 severity 命中即无视频拦
    high_sev = False
    rj = run_root / "reports" / "json"
    if rj.is_dir():
        for jf in rj.glob("*.json"):
            try:
                # 2026-10-13 A5 修：旧版只读前 600 字符找 severity——字段位置靠后漏拦、
                # 其它 JSON 出现 "priority":"high" 误拦。现改为全文 json 解析取 severity/level 键，
                # 解析失败再退文本扫描（范围扩到 4000）
                # 批四十五 B-13：utf-8-sig + UnicodeDecodeError 结构化 fail（GBK json 旧版裸崩）
                raw = jf.read_text(encoding="utf-8-sig")
            except OSError:
                continue
            except UnicodeDecodeError as exc:
                fail(
                    f"reports/json/{jf.name} 不是 UTF-8 文本（{exc}）——GBK/二进制 JSON"
                    "须转 UTF-8 落盘（批四十五 B-13，不裸崩丢回执）"
                )
            sev = ""
            try:
                _j = json.loads(raw)
                if isinstance(_j, dict):
                    sev = str(_j.get("severity") or _j.get("level") or "")
            except Exception:
                pass
            if not sev:
                _low = raw[:4000].lower()
                if '"severity"' in _low:
                    i = _low.find('"severity"')
                    sev = _low[i:i + 80]
            sl = (sev or "").lower()
            if any(k in sl for k in ("high", "critical", "严重", "高危")):
                high_sev = True
                break
    if not videos:
        if high_sev:
            # 批五十七 W1：目标不可达同样录不了视频——此前视频条只认「无视觉场」出口
            # （visual_available=false），真不可达场（浏览器在场、目标摸不到）被硬拦死锁。
            # 与截图豁免同源同标准：有效 no-screenshot-waiver.json（reason≥20 字且异字≥6）放行
            _vwa_p = run_root / "run" / "no-screenshot-waiver.json"
            _vwa_j = load_json(_vwa_p) if _vwa_p.is_file() else {}
            _vwa_r = str((_vwa_j or {}).get("reason", "")).strip()
            if len(_vwa_r) >= 20 and len(set(_vwa_r)) >= 6:
                notes.append("complex_video_waiver(目标不可达，复用截图豁免件：" + _vwa_r[:40] + "…)")
            else:
                fail(
                    "十一改㉗：本场含高危/严重级 finding（reports/json severity 命中）但 run/recordings/ 无视频"
                    "——高级别录视频必交，无视频=卷不完整退回补录（录屏按㉖三查：前端在/同步变化/图2形态干净）；"
                    "目标真不可达录不了：落 run/no-screenshot-waiver.json（与截图豁免同件，reason ≥20 字"
                    "且不同字符 ≥6 + 证据指针），有效豁免件不再拦视频（批五十七 W1）"
                )
        notes.append("complex_video_none(no videos, not required)")
        return
    if high_sev:
        notes.append("complex_video_high_sev(has video)")
    vr_dir = run_root / "run" / "vision-reviews"
    frame_ok = 0
    if vr_dir.is_dir():
        for rv in vr_dir.glob("*.review.md"):
            name = rv.stem.lower()
            if "frame" not in name and "rec" not in name and "录屏" not in name:
                continue
            try:
                head = rv.read_text(encoding="utf-8")[:400]
            except OSError:
                continue
            if verdict_ok_in(head):
                frame_ok += 1
    if frame_ok < 1:
        fail(
            f"十改㉖：run/recordings/ 有 {len(videos)} 个视频但无关键帧确认件——"
            "录屏须抽 2-3 关键帧过模型确认（vision-reviews/ 带 frame/rec/录屏 命名的 evidence_ok 件，"
            "帧图注标「录屏@mm:ss」）；录前周围必须干净（画面只含目标窗，杂项/IDE=废件重录）"
        )
    # 批六十 G-06/G-07（r37：录屏 PoC 收尾段+前后对比、最大攻击效果画面零核）——
    # 帧确认件族内容词轻核：全套帧件须含「收尾/PoC/前后对比/对比」之一（RF-VID-16）与
    # 「最大/落库/直出/数据/效果」之一（RF-VID-19⑧ 停在过程态拦截）。era≥20261017。
    _m60v = effective_run_date(run_root)
    if _m60v and _m60v.group(0) >= "20261017" and high_sev and frame_ok:
        _all_frames = ""
        if vr_dir.is_dir():
            for rv in vr_dir.glob("*.review.md"):
                if any(k in rv.stem.lower() for k in ("frame", "rec", "录屏")):
                    _all_frames += rv.read_text(encoding="utf-8", errors="ignore")[:600]
        if not re.search(r"收尾|PoC|poc|前后对比|对比", _all_frames):
            fail("录屏帧确认族缺 PoC 收尾段/前后对比证据词（RF-VID-16：收尾段必含运行前后对比，帧件须体现——批六十 G-06）")
        if not re.search(r"最大|落库|直出|数据|效果|弹窗", _all_frames):
            fail("录屏帧确认族缺最大攻击效果画面词（RF-VID-19⑧：停在 200/success 过程态=不合格，帧件须呈现效果——批六十 G-07）")
        notes.append("video_frame_content_ok")
    notes.append(f"complex_video_ok({len(videos)} videos, {frame_ok} frame reviews)")
    complex_hits: list[tuple[Path, dict]] = []
    for p in iter_json_files(run_root):
        data = load_json(p)
        if not data:
            continue
        for cur in walk_dicts(data):
            if str(cur.get("complexity") or "").lower() == "complex":
                complex_hits.append((p, cur))
    if not complex_hits:
        notes.append("no_complex_chain")
        return
    rec_p = run_root / "run" / "recording-index.json"
    rec = load_json(rec_p) if rec_p.is_file() else None
    if not isinstance(rec, dict):
        rec = {}
    items = rec.get("items") if isinstance(rec.get("items"), list) else []
    by_chain: dict[str, dict] = {}
    for item in items:
        if isinstance(item, dict) and item.get("chain_id"):
            by_chain[str(item["chain_id"])] = item
    att_p = run_root / "run" / "recording-attempts.json"
    att = load_json(att_p) if att_p.is_file() else None
    att_by_chain: dict[str, list] = {}
    if isinstance(att, dict):
        if isinstance(att.get("by_chain"), dict):
            for cid, rows in att["by_chain"].items():
                if isinstance(rows, list):
                    att_by_chain[str(cid)] = rows
        raw_att = att.get("attempts")
        if isinstance(raw_att, list):
            for row in raw_att:
                if not isinstance(row, dict):
                    continue
                cid = str(row.get("chain_id") or att.get("chain_id") or "")
                if cid:
                    att_by_chain.setdefault(cid, []).append(row)
    missing = []
    seen: set[str] = set()
    for p, obj in complex_hits:
        cid = str(obj.get("chain_id") or "")
        if not cid:
            missing.append(f"{p.relative_to(run_root).as_posix()} 标了 complex 但缺 chain_id")
            continue
        if cid in seen:
            continue
        seen.add(cid)
        item = by_chain.get(cid)
        if item:
            rel = item.get("video")
            if item.get("full_span") is not True:
                missing.append(f"{cid} full_span 必须是 JSON true（从头录到效果确认）")
                continue
            if not isinstance(rel, str) or not rel.strip():
                missing.append(f"{cid} recording-index 无 video 路径")
                continue
            f = resolve_inside(run_root, rel, f"{cid} video")
            if not f.is_file() or f.suffix.lower() not in VIDEO_EXT or f.stat().st_size <= 50_000:
                missing.append(f"{cid} video 文件无效或太小（<50KB）: {rel}")
                continue
            if not is_real_video(f):
                missing.append(f"{cid} video 不是 mp4/mkv/mov/webm（ftyp/EBML）文件头，禁止用一堆 x 充录像: {rel}")
                continue
            continue
        rows = att_by_chain.get(cid) or []
        # 2026-10-15 批二十六：5 次失败账退路交叉查 severity——RF-VID-01「高危/严重无此退路，
        # 必须换工具/路线录成」此前停留在条文层，场内有任一其他视频时高危 complex 链写满 5 次账即可零视频过闸
        csev = str(obj.get("severity") or obj.get("level") or "").lower()
        if any(k in csev for k in ("high", "critical", "严重", "高危")):
            # 批五十八 C（SKILL 体检 r36 P1-1）：W1 豁免出口此前只落在 check_complex_video 的
            # 「整场零视频」分支——场内有他链视频时本逐链检查仍对真不可达的高危链硬拦（豁免件被无视）。
            # 同件同标：有效 no-screenshot-waiver（reason≥20 字且异字≥6）在此同样放行。
            _wc_p = run_root / "run" / "no-screenshot-waiver.json"
            _wc_j = load_json(_wc_p) if _wc_p.is_file() else {}
            _wc_r = str((_wc_j or {}).get("reason", "")).strip()
            if len(_wc_r) >= 20 and len(set(_wc_r)) >= 6:
                notes.append(f"chain_video_waiver({cid}: 目标不可达，复用截图豁免件放行必录)")
                continue
            missing.append(f"{cid} 高危/严重 complex 链无「5 次失败账」免录退路（RF-VID-01），必须换工具/路线录成；目标真不可达：有效 run/no-screenshot-waiver.json 同样放行（批五十八 C）")
            continue
        if len(rows) < 5:
            missing.append(f"{cid} 无对应录像且失败记录不足 5 次")
            continue
        bad = False
        for row in rows[:5]:
            if (
                not str(row.get("when") or "").strip()
                or not str(row.get("tool") or "").strip()
                or not str(row.get("error") or "").strip()
            ):
                bad = True
                break
        if bad:
            missing.append(f"{cid} 5 次失败记录缺 when/tool/error")
    if missing:
        fail(
            "complex 链必须有对应该 chain_id 的真录像（recording-index + full_span=true + 文件头）或满 5 次失败账",
            {"missing": missing[:12]},
        )
    notes.append("complex_video_or_five_ok")


def finding_type(obj: dict) -> str:
    for key in ("finding_type", "vuln_type", "type", "category"):
        val = obj.get(key)
        if isinstance(val, str) and val.strip():
            return val.lower()
    return ""


@collect_errors
def check_verified_evidence(run_root: Path, notes: list[str]) -> None:
    problems = []
    found = False
    for p in iter_json_files(run_root):
        rel = str(p.relative_to(run_root)).replace("\\", "/")
        if rel.startswith("reports/") and "cors" in p.name.lower():
            problems.append(f"正式报告里出现 CORS 文件: {rel}")
            continue
        if rel.startswith("cors-audit/"):
            continue
        data = load_json_tree(p, "check_verified_evidence")
        if not data:
            continue
        for cur in walk_dicts(data):
            if _finding_status(cur) != "verified":
                continue
            found = True
            # 批六十 G-16（r37：不写 complexity 键则 no_complex_chain 直接放行——复杂链逃必录全靠曹操自觉）：
            # era≥20261017 verified finding 必带 complexity=simple|complex（缺键/垃圾值都拦，与 H-26 缺 severity 同款）
            if _b39_era(run_root) and effective_run_date(run_root).group(0) >= "20261017":
                _cx60 = str(cur.get("complexity") or "").strip().lower()
                if _cx60 not in ("simple", "complex"):
                    problems.append(f"{rel} verified finding 缺/坏 complexity 键（须 simple|complex——不写=复杂链逃必录，RF-VID-01 判型依据，批六十 G-16）")
            ftype = finding_type(cur)
            if "cors" in ftype:
                problems.append(f"{rel} verified 类型是 CORS，不得进正式结论")
            evid = cur.get("evidence") or cur.get("evidence_paths") or cur.get("evidence_dir")
            files: list[str] = []
            if isinstance(evid, list):
                files = [x for x in evid if isinstance(x, str)]
            elif isinstance(evid, str):
                files = [evid]
            if not files:
                problems.append(f"{rel} verified 没有 evidence 路径")
                continue
            has_image = False
            has_text = False
            for item in files:
                f = resolve_inside(run_root, item, "verified.evidence")
                if not f.exists():
                    problems.append(f"{rel} evidence missing: {item}")
                    continue
                if f.is_dir():
                    kids = [k for k in f.rglob("*") if k.is_file()]
                    if not kids:
                        problems.append(f"{rel} evidence dir empty: {item}")
                    for k in kids:
                        if k.suffix.lower() in IMAGE_EXT and is_real_image(k):
                            has_image = True
                        if k.suffix.lower() not in IMAGE_EXT | VIDEO_EXT and k.stat().st_size >= 40:
                            has_text = True
                elif f.is_file():
                    if f.suffix.lower() in IMAGE_EXT:
                        if is_real_image(f):
                            has_image = True
                        else:
                            problems.append(f"{rel} evidence 图没有图像文件头: {item}")
                    elif f.stat().st_size >= 40:
                        has_text = True
            if "xss" in ftype and not has_image:
                problems.append(f"{rel} XSS verified 必须有弹窗/渲染原图")
            if any(x in ftype for x in ("rce", "command", "ssti", "deserialize")) and not has_text:
                problems.append(f"{rel} RCE verified 必须有命令/文件执行落盘，不能只靠截图")
            if any(x in ftype for x in ("idor", "越权", "broken access")) and not has_text:
                problems.append(f"{rel} 越权 verified 必须有他者数据回包")
            # SQL 库侧真值比对契约（2026-10-09 判例：Snowy 161 枪拖全哈希只对种子文件，
            # 库通道在场 30 秒可做的直查没做 → 校准不闭环）。db_direct / waiver 二选一，缺块即拦。
            # 类型匹配：sql/sqli/注入/盲注 归本行；模板/SpEL/XSS/XXE/命令类「注入」属别行，排除防误伤。
            GT_EXCLUDE = ("xss", "模板", "spel", "ssti", "xxe", "命令", "command", "rce", "代码")
            if not any(x in ftype for x in GT_EXCLUDE) and any(x in ftype for x in ("sql", "sqli", "注入", "盲注")):
                gt = cur.get("db_ground_truth")
                if not isinstance(gt, dict):
                    problems.append(
                        f"{rel} SQL verified 缺 db_ground_truth 块——db_direct（含库侧只读直查原件）"
                        "或 waiver（写库通道不可达原因+次级真值来源）二选一，只对种子/凭据文件比对且库通道在场不得 verified"
                    )
                else:
                    gmode = str(gt.get("mode") or gt.get("source") or "").lower()
                    gt_evid = gt.get("evidence")
                    gt_files = (
                        [x for x in (gt_evid if isinstance(gt_evid, list) else [gt_evid]) if isinstance(x, str)]
                        if gt_evid
                        else []
                    )
                    if gmode in ("db_direct", "db", "direct"):
                        if not gt_files:
                            problems.append(f"{rel} db_ground_truth.mode=db_direct 但没有直查原件路径")
                        for item in gt_files:
                            gf = resolve_inside(run_root, item, "db_ground_truth.evidence")
                            if not gf.exists():
                                problems.append(f"{rel} db_ground_truth 直查原件不存在: {item}")
                            elif gf.stat().st_size < 40:
                                problems.append(f"{rel} db_ground_truth 直查原件过小(<40B): {item}")
                    elif gmode in ("waiver", "not_available", "n/a"):
                        if len(str(gt.get("reason") or "")) < 10:
                            problems.append(f"{rel} db_ground_truth.mode=waiver 但 reason 太短（须写明库通道为何不可达）")
                        if not str(gt.get("secondary_source") or "").strip():
                            problems.append(f"{rel} waiver 须写 secondary_source（出厂种子SQL/凭据账种子/第二接口回读/未拖具体值仅证机制）")
                    else:
                        problems.append(f"{rel} db_ground_truth.mode 须为 db_direct 或 waiver")
    if problems:
        fail("verified 证据不足或 CORS 进了正式结论", {"missing": problems[:16]})
    if found:
        notes.append("verified_evidence_ok")
        signed = False
        signed_file: Path | None = None
        cao = run_root / "02-cao-cao"
        if cao.is_dir():
            for p in cao.rglob("*.json"):
                data = load_json(p)
                if not data:
                    continue
                for cur in walk_dicts(data):
                    st = _finding_status(cur)  # 批四十五 M31：终态键统一三键
                    if st == "verified":
                        signed = True
                        signed_file = p
                        break
                if signed:
                    break
        if not signed:
            fail("已有 verified，但 02-cao-cao/ 没有曹操签字收口件（status/final_status=verified）")
        # 批三十七（红队三轮 P1-12）：签字摘录锚——空壳一句「同意 verified」也过的口收紧；
        # era≥20261015 签字件须引用 findings/证据原文 ≥15 字（至少真的打开过被签的账）
        _m_sg = effective_run_date(run_root)
        if _m_sg and _m_sg.group(0) >= H22_STRICT_ERA and signed_file is not None:
            # target 只收 ≥20 字的文本值（结论/描述类）——路径/键名不构成「读过账本」的锚
            _target = ""
            rj = run_root / "reports" / "json"
            for jf in sorted(rj.glob("*.json")) if rj.is_dir() else []:
                _jd = load_json(jf)
                for _cur in walk_dicts(_jd) if _jd else []:
                    for _v in _cur.values():
                        if isinstance(_v, str) and len(_v.strip()) >= 20:
                            _target += _v + chr(10)
            if _target and not _excerpt_in_file(signed_file.read_text(encoding="utf-8", errors="ignore"), _target):
                fail(
                    f"曹操签字件 {signed_file.name} 无摘录锚：未引用任何 finding 结论/证据原文 ≥15 字"
                    "（批三十七）——签字必须建立在读过账本之上，空壳签字按未签论处"
                )
        notes.append("verified_cao_cao_signed")
    else:
        notes.append("no_verified_objects")


def sima_reason_blob(d: Path) -> str:
    parts = []
    nn = d / "not-needed.json"
    if nn.is_file():
        data = load_json(nn) or {}
        parts.append(str(data.get("reason") or ""))
        parts.append(str(data.get("applicability_predicate") or ""))
        parts.append(str(data.get("basis") or ""))
    for name in ("blackbox-phases.json", "sima-yi-book.md"):
        p = d / name
        if p.is_file():
            parts.append(blob_text(p, 80_000))
    return "\n".join(parts)


def removed_instance_ready(run_root: Path) -> bool:
    shots = load_json(run_root / "01-guo-jia" / "captcha-removed-three-shots.json") or {}
    if str(shots.get("login_without_captcha") or "").lower() == "pass":
        return True
    idx = load_json(run_root / "run" / "captures-index.json") or {}
    urls = idx.get("address_bar_urls") if isinstance(idx.get("address_bar_urls"), dict) else {}
    for key in ("removed_login", "removed_admin"):
        if isinstance(urls.get(key), str) and urls[key].startswith("http"):
            return True
    yujin = run_root / "06-yu-jin"
    if yujin.is_dir() and role_has_work(yujin):
        return True
    return False


@collect_errors
def check_sima_web_duty(run_root: Path, notes: list[str], phase_close: bool) -> None:
    env = envelope(run_root)
    if is_website(env):
        d = run_root / "09-si-ma-yi"
        if not d.is_dir() or not role_has_work(d):
            fail("网站场必须有 09-si-ma-yi/ 黑盒作业，禁止空目录收口")
        notes.append("website_sima_work_ok")
        check_sima_phases(run_root, notes, website=True)
        return
    if is_static_only(env):
        notes.append("static_only_skip_sima_web")
        return
    surface = has_deployed_web_surface(run_root)
    d = run_root / "09-si-ma-yi"
    if not surface and not d.is_dir():
        notes.append("no_web_surface_yet")
        return
    if not d.is_dir():
        fail("部署型 web 面已在（登录/API/swagger/本场端口），必须有 09-si-ma-yi/；禁止空目录等到收口")
    nn = d / "not-needed.json"
    blob = sima_reason_blob(d).lower()
    if nn.is_file() and not role_has_work(d):
        if any(k.lower() in blob for k in SIMA_FAKE_NN):
            fail(
                "司马懿 not-needed 写成『local_source / 无待测网站 / ZIP 无前端』；"
                "本场部署实例的登录页/API/swagger 就是黑盒面，禁止假 not-needed"
            )
        fail("部署型 web 面已在，司马懿不得只交 not-needed.json，必须打 native 第一段")
    if not role_has_work(d):
        fail("09-si-ma-yi/ 空目录或只有 capability；native 入口可达必须派第一段并留下观察")
    notes.append("sima_web_surface_ok")
    check_sima_phases(run_root, notes, website=False)


def check_sima_phases(run_root: Path, notes: list[str], website: bool) -> None:
    d = run_root / "09-si-ma-yi"
    path = d / "blackbox-phases.json"
    if not path.is_file():
        fail("收口必须有 09-si-ma-yi/blackbox-phases.json（第一段 native / 第二段 captcha_removed）")
    data = load_json(path)
    if not data:
        fail("blackbox-phases.json is not a JSON object")
    p1 = str(data.get("phase1_native") or "").strip().lower()
    p2 = str(data.get("phase2_captcha_removed") or "").strip().lower()
    if p1 not in {"done", "blocked"}:
        fail("blackbox-phases.phase1_native 必须是 done|blocked")
    evid1 = data.get("phase1_evidence")
    if not isinstance(evid1, list) or len(evid1) < 1:
        fail("phase1_native 必须有 phase1_evidence（观察册/请求原件）")
    for rel in evid1:
        f = resolve_inside(run_root, str(rel), "phase1_evidence")
        if not f.is_file() or f.stat().st_size < 40:
            fail(f"phase1_evidence missing or too small: {rel}")
    if p1 == "blocked":
        gap = str(data.get("phase1_coverage_gap") or "").strip()
        if len(gap) < 8:
            fail("phase1 blocked 必须写 phase1_coverage_gap")
        if any(k.lower() in gap.lower() for k in SIMA_PHASE2_FAKE):
            fail("phase1 blocked 写成『闸没齐/等画面』；入口可达就必须打第一段")
    if website:
        if p2 not in {"done", "blocked", "not_applicable"}:
            fail("网站 blackbox-phases.phase2_captcha_removed 必须是 done|blocked|not_applicable")
        notes.append("sima_phases_website_ok")
        return
    if p2 not in {"done", "blocked", "not_applicable"}:
        fail("blackbox-phases.phase2_captcha_removed 必须是 done|blocked|not_applicable")
    if removed_instance_ready(run_root) and p2 == "not_applicable":
        fail(
            "captcha_removed 已在（三枪/截图/于禁已打），第二段不得 not_applicable；"
            "禁止只打 native 未登录就收口"
        )
    if p2 == "done":
        evid2 = data.get("phase2_evidence")
        if not isinstance(evid2, list) or len(evid2) < 1:
            fail("phase2 done 必须有 phase2_evidence（removed 上的观察/请求原件）")
        for rel in evid2:
            f = resolve_inside(run_root, str(rel), "phase2_evidence")
            if not f.is_file() or f.stat().st_size < 40:
                fail(f"phase2_evidence missing or too small: {rel}")
    if p2 == "blocked":
        gap = str(data.get("phase2_coverage_gap") or "").strip()
        if len(gap) < 8:
            fail("phase2 blocked 必须写 phase2_coverage_gap")
        if any(k.lower() in gap.lower() for k in SIMA_PHASE2_FAKE):
            fail(
                "phase2 blocked 写成『等第一段/回执未齐/等画面/排队 LOCK-Q-002』；"
                "removed 已在就必须打第二段，禁止排队到死"
            )
    book = d / "sima-yi-book.md"
    if book.is_file():
        text = blob_text(book).lower()
        if any(
            k in text
            for k in (
                "本段未进",
                "未进第二段",
                "本段未访问",
                "captcha_removed 本段未",
            )
        ) and p2 == "done":
            fail("司马懿册子仍写『未进第二段』，与 blackbox-phases.phase2=done 矛盾")
    notes.append("sima_two_phases_ok")


def _plan_blob_files(run_root: Path) -> list[Path]:
    out: list[Path] = []
    cao = run_root / "02-cao-cao"
    if cao.is_dir():
        for p in cao.rglob("*"):
            if not p.is_file():
                continue
            if p.suffix.lower() not in {".md", ".json"}:
                continue
            if p.stat().st_size > 200_000:
                continue
            name = p.name.lower()
            parent = p.parent.name.lower()
            if not any(k in name or k in parent for k in ("plan", "alignment", "chain", "matrix", "verification")):
                continue
            out.append(p)
    return out


# 2026-10-15 二轮复核：纯读探测禁捆绑延后——pig 判例原话「随 XX 批次一并跑」形态，markdown 与 JSON 计划行同拦
BUNDLE_NEEDLES = (
    (re.compile(r"随.{0,16}批次一并"), "纯读探测捆绑延后"),
    (re.compile(r"捆绑.{0,8}(?:延后|一并)"), "计划行捆绑延后"),  # 修复批十九：去掉 跑|打|测——「两链捆绑打同一入口」类正常表述误伤
)


@collect_errors
def check_open_plan(run_root: Path, notes: list[str]) -> None:
    if is_website(envelope(run_root)):
        notes.append("website_skip_open_plan")
        return
    if is_static_only(envelope(run_root)):
        notes.append("static_skip_open_plan")
        return
    open_rows: list[str] = []
    for p in _plan_blob_files(run_root):
        rel = p.relative_to(run_root).as_posix()
        if p.suffix.lower() == ".json":
            data = load_json(p)
            if not data:
                continue
            for cur in walk_dicts(data):
                st = str(cur.get("status") or cur.get("state") or cur.get("进度") or "").strip().lower()
                token = re.split(r"[；;，,\s]", st, maxsplit=1)[0]
                if token in OPEN_PLAN_STATUSES or st.startswith("pending") or st.startswith("ready"):
                    cid = cur.get("id") or cur.get("chain_id") or cur.get("chain") or cur.get("#") or "?"
                    open_rows.append(f"{rel}:{cid}:{st[:80]}")
                # 计划行定义了 test 却没有任何结果键 = 隐形 pending（pig 场教训：VP-P2
                # 三行 verdict_now=suspected 词表对不上，close 放行后一发未打）
                if str(cur.get("test") or "").strip():
                    has_result = any(
                        str(cur.get(k) or "").strip()
                        for k in ("result", "verdict_final", "outcome", "closed_as", "final_verdict", "verdict")
                    )
                    if not has_result:
                        rid = cur.get("id") or cur.get("chain_id") or cur.get("chain") or cur.get("#") or "?"
                        open_rows.append(f"{rel}:{rid}:有 test 无结果（verdict_now 只算初判不算结果）")
                # 2026-10-15 二轮复核：纯读探测禁捆绑延后——JSON 计划行同拦（pig 判例原话形态）
                sv = " ".join(str(v) for v in cur.values() if v)
                for _pat, _label in BUNDLE_NEEDLES:
                    _m = _pat.search(sv)
                    if _m:
                        rid = cur.get("id") or cur.get("chain_id") or "?"
                        open_rows.append(f"{rel}:{rid}:{_label}「{_m.group()}」")
            continue
        try:
            text = p.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for line in text.splitlines():
            raw = line.strip()
            if raw.count("|") < 2:
                continue
            cells = [c.strip() for c in raw.strip("|").split("|")]
            if not cells:
                continue
            # 2026-10-13 C5 修：状态列不再假设末列——任一列命中状态词即判（状态不在末列的表旧版整表漏检）
            # 批三十七（红队三轮 P1-11）：era≥20261015 场白名单化——黑名单词表永远追不完
            # （「第二批/待安排/Phase2」都漏）；状态词不落在闭合集 = open（fail-closed，同 era 无日期哲学）
            _m_pl = effective_run_date(run_root)
            _whitelist = bool(_m_pl and _m_pl.group(0) >= H22_STRICT_ERA)
            CLOSED_PLAN_STATUSES = {
                "verified", "suspected", "coverage_gap", "eliminated", "disproved",
                "not_applicable", "blocked", "done", "closed", "passed", "skipped",
                "已测", "已闭环", "已否证", "已封存", "已否决",
            }
            row_hit = False
            # 白名单只查末列（状态列惯例位；等级/说明列不禁——防「高危/复杂」被当开放态误拦），
            # 黑名单照旧全列兜底
            _last_cell = cells[-1].strip().lower() if cells else ""
            _last_token = re.split(r"[；;，,\s/]", _last_cell, maxsplit=1)[0] if _last_cell else ""
            if _whitelist and _last_cell not in {"状态", "status", "---", ":---", "---|", "结果", "结论"} and not re.fullmatch(r":?-{2,}:?", _last_cell):
                # 批四十五 B-9：状态列留空=按 open 处理（fail-closed）——旧版空 token 让
                # 白名单黑名单双跳过，「| CHAIN-A | rce 待打 |  |」当已闭合
                if not _last_token or (_last_token not in CLOSED_PLAN_STATUSES and not _last_token.startswith(("coverage", "not_app"))):
                    row_hit = True
            if not row_hit:
                for ci, cell in enumerate(cells):
                    status_cell = cell.lower()
                    if status_cell in {"状态", "status", "---", ":---", "---|", "结果", "结论"}:
                        continue
                    token = re.split(r"[；;，,\s/]", status_cell, maxsplit=1)[0]
                    if not token:
                        continue
                    if token in OPEN_PLAN_STATUSES or status_cell.startswith("pending") or status_cell.startswith("ready"):
                        row_hit = True
                        break
            if row_hit:
                open_rows.append(f"{rel}: {raw[:100]}")
        low = text.lower()
        for needle in ("仍按原计划 pending", "当前不可跑", "仍等 report-server", "等窗口后再"):
            if needle in low:
                open_rows.append(f"{rel}: {needle}")
        # 2026-10-15 二轮复核：pig 判例原话形态「随 XX 批次一并跑」此前不拦——纯读探测禁捆绑延后补 needle
        for _pat, _label in BUNDLE_NEEDLES:
            _m = _pat.search(text)
            if _m:
                open_rows.append(f"{rel}: {_label}「{_m.group()}」")
    if open_rows:
        fail(
            "验证计划仍有 pending/queued/等窗口 链就 close；第一条 verified 可以出报告，"
            "本场结束必须把表打完或改成 verified/suspected/coverage_gap（有据），禁止高优先链停在 pending",
            {"open": open_rows[:16]},
        )
    notes.append("plan_closed_ok")


@collect_errors
def check_named_surfaces(run_root: Path, notes: list[str]) -> None:
    if is_website(envelope(run_root)) or is_static_only(envelope(run_root)):
        notes.append("skip_named_surfaces")
        return
    blobs: list[str] = []
    for rel in (
        "01-guo-jia/deploy-plan.md",
        "01-guo-jia/candidates.jsonl",
        "01-guo-jia/collection-brief.md",
        "01-guo-jia/receipts.md",
        "02-cao-cao/verification-plan.md",
        "02-cao-cao/plan-alignment.md",
    ):
        p = run_root / rel
        if p.is_file() and p.stat().st_size < 500_000:
            try:
                blobs.append(p.read_text(encoding="utf-8", errors="ignore"))
            except OSError:
                pass
    chains = run_root / "02-cao-cao" / "chains"
    if chains.is_dir():
        for p in chains.glob("*.md"):
            if p.stat().st_size < 200_000:
                try:
                    blobs.append(p.read_text(encoding="utf-8", errors="ignore"))
                except OSError:
                    pass
    blob = "\n".join(blobs).lower()
    if not blob.strip():
        notes.append("no_named_surface_docs")
        return
    ledger = load_json(run_root / "01-guo-jia" / "component-cve-ledger.json") or {}
    ledger_txt = json.dumps(ledger, ensure_ascii=False).lower()
    sink = load_json(run_root / "01-guo-jia" / "sink-runtime-modules.json") or {}
    sink_txt = json.dumps(sink, ensure_ascii=False).lower()
    if any(k in blob for k in ("jimureport", "jmreport", "积木报表")):
        if "jimureport" not in ledger_txt and "jmreport" not in ledger_txt:
            fail(
                "计划/链审已点名 jimureport/积木报表，component-cve-ledger 必须入账并查 CVE；"
                "禁止只写 coverage_gap 或曹仁假 not-needed"
            )
    if any(k in blob for k in ("tdengine", "device_message_${", "product_property_${", "module-iot", "iot-module")):
        if "iot" not in sink_txt and "tdengine" not in sink_txt:
            fail(
                "计划/链审已点名 IoT/TDengine ${}，sink-runtime-modules 必须入账并尝试拉起；"
                "禁止聚合只起 system+infra 当没这面"
            )
    if any(k in blob for k in ("notifyurl", "paynotify", "module-pay", "pay-module", "transfer_notify_url")):
        if "pay" not in sink_txt and "notify" not in sink_txt:
            fail(
                "计划/链审已点名 pay notifyUrl SSRF，sink-runtime-modules 必须入账并尝试拉起 pay 模块；"
                "缺列/注释聚合不是『没有 SSRF』"
            )
    notes.append("named_surfaces_ok")


def verdict_ok_in(head: str) -> bool:
    """2026-10-13 A1 修：判定行匹配容错——归一全角冒号/全角空格后再匹配三态，
    兼容 faker 通道历史件「判定： 判定： evidence_ok」双写形态
    批六十一⑧（r38 C-4 四口径归一）：ok 收集口径与 normalize_verdict/parse_verdict 对齐——
    ①markdown 装饰（**/`/>/-/数字./#/|）与引号包裹不再让「真 ok 件」收不进池
    （收集宽松→复检严格的落差是「存档 ok 复验 weak」机制成因之一）；
    ②反向收紧：判定行带转折词（但/不过/然而/however）或罗列 weak/unclear 不算 ok。"""
    s = (head or "").replace("：", ":").replace("　", " ")
    _ok = re.compile(r"判定\s*:\s*[\"'\x27“”‘’「『]?\s*evidence_ok\b", re.I)
    _bad = re.compile(r"evidence_(?:weak|unclear)\b|判定\s*:\s*evidence_ok\s*(?:[/、,，;；&＆]|\s*(?:但|不过|然而|however))", re.I)
    if _ok.search(s) and not _bad.search(s):
        return True
    # 剥行首 markdown 装饰后再试（**判定：ok** / - 判定：ok / 1. 判定：ok 等）
    stripped = re.sub(r"(?m)^[\s>#*|\-`·0-9.]+", "", s)
    return bool(_ok.search(stripped)) and not _bad.search(stripped)


def effective_run_date(run_root: Path):
    """2026-10-13 A4 修：生效线日期锚定「场次目录段」（run_root 最后一段）优先，
    找不到再回退整路径第一个日期串——旧版无锚定，版本段带日期（如 v3.2.1-20260905）即劫持生效线。
    2026-10-15 批三十三（era 逃逸洞）：无日期→99999999 fail-closed。
    2026-10-15 批三十六（用户红队二轮 P0-1）：批三十三的多源取 max 引入新后门——信封/alarm 是
    操作者可写文件，建无日期目录+信封回填旧日期即可把 era 压到存量档，六门全静默降级。
    改为 era 唯一锚 = 目录/路径名日期（SKILL 步 2 强制当日 YYYYMMDD 开头）；信封/alarm 日期
    一律不参与计算，回填旧日期零收益；无日期目录维持 99999999 最严档。返回保持 match 形状。"""
    m = re.search(r"20\d{6}", run_root.name) or re.search(r"20\d{6}", str(run_root))
    if m:
        return m
    return re.match(r"\d+", "99999999")  # fail-closed：无日期=按最新 era 最严档


def envelope_paths(run_root: Path):
    """2026-10-13 A3 修：信封候选统一为 4 处（envelope() 与 stamp/runner_model 原各自为政，
    envelope.json 场会 runner_model 静默跳过+盖章另造双信封）"""
    return (
        run_root / "run" / "envelope.json",
        run_root / "envelope.json",
        run_root / "test-session.json",
        run_root / "run" / "test-session.json",
    )


@collect_errors
def check_envelope_progress(run_root: Path, notes: list[str]) -> None:
    ts = None
    for cand in envelope_paths(run_root):
        data = load_json(cand)
        if data:
            ts = data
            break
    if not ts:
        # 2026-10-13 A2 修：无信封的场原只记 no_test_session 放行，close passed 后 stamp_test_session
        # 还会凭空创建 closed 信封——SKILL 步 2 写信封是硬步骤，闸必须兜底拦
        fail(
            "场次信封整体缺失（run/envelope.json、envelope.json、test-session.json、run/test-session.json 四处均无）"
            "——SKILL 步 2 开场信封是硬步骤，缺信封禁止 close（旧版放行+盖章回写=凭空造 closed 账）"
        )
    status = str(
        ts.get("execution_status")
        or ts.get("status")
        or ts.get("run_status")
        or ""
    ).lower()
    reason = str(ts.get("execution_not_started_reason") or "").lower()
    work = False
    for dirname, _allow in SOURCE_ROSTER:
        d = run_root / dirname
        if d.is_dir() and role_has_work(d):
            work = True
            break
    if (run_root / "reports").is_dir() and any((run_root / "reports").glob("*.docx")):
        work = True
    if work and (status in NOT_STARTED_STATUSES or "not_started" in reason or "尚无获准执行" in reason):
        fail(
            "角色已作业或已有 reports，但信封/test-session 仍写 execution_status=not_started；"
            "收口必须回填真实进度，禁止信封自称未开工"
        )
    # 批三十五 P2：era 源分叉注记（不拦）——目录名日期与信封日期不一致时可见化；
    # 一致回填旧日期逃 era 门的摸鱼手法靠此注记在 verify-close/复核时显形
    _dm = re.search(r"20\d{6}", run_root.name)
    if _dm:
        for _cand in envelope_paths(run_root):
            _ed = load_json(_cand) if _cand.is_file() else None
            if not _ed:
                continue
            for _key in ("opened_at", "created_at", "started_at"):
                _em = re.search(r"(20\d{2})-?(\d{2})-?(\d{2})", str(_ed.get(_key) or ""))
                if _em:
                    _env_d = _em.group(1) + _em.group(2) + _em.group(3)
                    if _env_d != _dm.group(0):
                        notes.append(f"era_date_mismatch(dir={_dm.group(0)},env={_env_d})")
                    break
            break
    notes.append("envelope_progress_ok")


@collect_errors
def check_bec_if_yujin(run_root: Path, notes: list[str]) -> None:
    yujin = run_root / "06-yu-jin"
    if not yujin.is_dir():
        notes.append("no_yu_jin")
        return
    nn = yujin / "not-needed.json"
    if nn.is_file() and not any(p.suffix.lower() == ".json" and p.name != "not-needed.json" for p in yujin.rglob("*.json")):
        notes.append("yu_jin_not_needed")
        return
    bec_hits = []
    for p in iter_json_files(run_root):
        data = load_json(p)
        if data and (data.get("kind") == "bec" or data.get("bec_id") or data.get("schema") == "bec"):
            bec_hits.append(p)
            continue
        # 批六十一②（r38 A-2）：文件名裸子串「bec」认定收窄——become-report.json 也算；
        # 改为：文件名含 bec 的还须件内含 02-cao-cao 目录签名或 chains/allowed_requests 类键
        if "bec" in p.name.lower() and isinstance(data, dict) and (
            any(k in data for k in ("chains", "allowed_requests", "budget", "quota", "authorized_chains"))
            or str(data.get("decided_by") or data.get("issuer") or "") == "02-cao-cao"
        ):
            bec_hits.append(p)
    if not bec_hits:
        fail(
            "已有 06-yu-jin/ 作业文件，但找不到 BEC JSON；于禁必须在 BEC 之后"
            "——BEC 认定须结构化（kind=bec / bec_id / chains/allowed_requests 键），"
            "文件名恰含 bec 不再单独算（批六十一②：become-report.json 之类误认在此收紧）"
        )
    # 批六十一③（r38 A-2 后半）：BEC 先于于禁作业的粗时序核——era≥20261017 场，
    # BEC 件 mtime 须早于 06-yu-jin/ 内最早作业件（同分钟内视为满足，容文件整理搬动）
    m61 = effective_run_date(run_root)
    if m61 and m61.group(0) >= "20261017" and bec_hits:
        yj_files = [p for p in yujin.rglob("*") if p.is_file() and p.name != "not-needed.json"]
        if yj_files:
            bec_t = min(p.stat().st_mtime for p in bec_hits)
            yj_t = min(p.stat().st_mtime for p in yj_files)
            if bec_t > yj_t + 60:
                fail(
                    "BEC 件晚于于禁最早作业件（mtime 时序倒挂，批六十一③）——于禁必须在 BEC 签发之后发包；"
                    "确属文件整理搬动导致，曹操在收口件待办节登记说明后重跑"
                )
    notes.append("bec_present")


@collect_errors
def check_source_roster(run_root: Path, notes: list[str]) -> None:
    if is_website(envelope(run_root)):
        for d in ("02-cao-cao", "02-cao-cao-shadow", "09-si-ma-yi"):
            if not (run_root / d).is_dir():
                fail(f"网站收口必须有 {d}/")
        notes.append("website_roster_ok")
        return
    verified = any_verified(run_root)
    missing = []
    for dirname, allow_nn in SOURCE_ROSTER:
        d = run_root / dirname
        if not d.is_dir():
            missing.append(f"缺 {dirname}/")
            continue
        nn = d / "not-needed.json"
        # 2026-10-13 C6 修：capability.json 不算作业件（对齐 role_has_work 口径——
        # 只交 not-needed+capability 的角色旧版误判「有其它作业」躲过拦截）
        has_other = any(p.is_file() and p.name not in ("not-needed.json", "capability.json") for p in d.rglob("*"))
        if dirname == "06-yu-jin" and verified and nn.is_file() and not has_other:
            missing.append("已有 verified 但于禁只有 not-needed.json")
        if dirname == "09-si-ma-yi" and not nn.is_file() and not has_other:
            missing.append("09-si-ma-yi/ 空目录")
        if dirname == "09-si-ma-yi" and nn.is_file() and not has_other and has_deployed_web_surface(run_root):
            blob = sima_reason_blob(d)
            if any(k.lower() in blob.lower() for k in SIMA_FAKE_NN):
                missing.append("司马懿假 not-needed（无网站/local_source）；部署实例就是黑盒面")
        if not allow_nn and nn.is_file() and not has_other:
            missing.append(f"{dirname} 不能只交 not-needed")
        if allow_nn and not has_other and not nn.is_file():
            missing.append(f"{dirname}/ 在但既没有作业也没有 not-needed.json")
    if missing:
        fail("源码收口九人必须现身（没活也要 not-needed.json）", {"missing": missing})
    notes.append("source_roster_ok")


def docx_plain_text(path: Path) -> str:
    # 2026-10-13 G3 修：畸形 DOCX（zip/xml 损坏）旧版抛 ParseError 裸冒到 main sys.exit(1)——
    # 不落 failures[]、不写回执，close 整轮报废。现捕获后返回空文本，走「8 块缺失」正规 fail 通道
    try:
        return _docx_plain_text_impl(path)
    except Exception as e:
        FAILURES.append({"reason": f"正位卷 {path.name} 解析失败（畸形 DOCX）：{e}——按 8 块缺失处理；修件后重跑 close"})
        return ""


def _docx_plain_text_impl(path: Path) -> str:
    import zipfile
    from xml.etree import ElementTree as ET

    ns = {"w": "http://schemas.openxmlformats.org/wordprocessingml/2006/main"}
    try:
        xml = zipfile.ZipFile(path).read("word/document.xml")
    except Exception:
        # 2026-10-13 新9 修：旧版调 fail()（GateFailure 被外层 except 捕获再记一次=双计）；改直接 raise 由外层统一记账
        raise RuntimeError(f"reports/{path.name} 打不开 word/document.xml")
    root = ET.fromstring(xml)
    paras = []
    for para in root.findall(".//w:p", ns):
        texts = []
        for t in para.findall(".//w:t", ns):
            if t.text:
                texts.append(t.text)
            if t.tail:
                texts.append(t.tail)
        line = "".join(texts).strip()
        if line:
            paras.append(line)
    return "\n".join(paras)


def is_summary_docx(name: str) -> bool:
    n = name.lower()
    # 总览/总报告/复审复测类是内部件，可带角色名，不当 finding 卷抽 8 块/查内部痕迹
    return (
        n.startswith("test-summary")
        or "test-summary" in n
        or n.startswith("summary")
        or "总报告" in name
        or "总览" in name
        or ("复审" in name and "复测" in name)  # 2026-10-13 遗4：仅「复审+复测」同现（=复审复测总报告类非卷件）豁免；单纯「复审卷」「复测卷」仍走八块检查
    )


def check_finding_docx_eight_blocks(path: Path, run_root: Path | None = None) -> None:
    text = docx_plain_text(path)
    compact = re.sub(r"\s+", "", text)
    missing = []
    if "目标网站URL" not in compact and "目标网站url" not in compact.lower():
        missing.append("目标网站URL")
    if not re.search(r"漏洞等级[:：]?(中危|高危|严重)", compact):
        if not re.search(r"(^|\n)(中危|高危|严重)(\n|$)", text):
            missing.append("漏洞等级（中危/高危/严重）")
    if "漏洞描述" not in compact:
        missing.append("漏洞描述")
    if "漏洞危害" not in compact:
        missing.append("漏洞危害")
    if "涉及接口" not in compact:
        missing.append("涉及接口清单")
    if "复现" not in compact:
        missing.append("复现步骤")
    if "修复" not in compact:
        missing.append("修复建议")
    # 2026-10-13 C1 修：任意单「我」即过（含「我们」）形同虚设——改为找独立第一人称「我」（前后非「们」）
    if not re.search(r"我(?!们)", text):
        missing.append("第一人称「我」")
    if "＃" not in text:
        missing.append("全角＃分隔")
    if not re.search(r"(GET|POST|PUT|DELETE|PATCH)\s+/\S+", text, re.I):
        missing.append("可复制整包（请求行）")
    if not re.search(r"(?im)^Host:\s*\S+", text):
        missing.append("整包 Host 头")
    # 批六十 G-11（r37：厂商块零核，xxl-job 判例同洞）——RF-ELEM-03 软件与厂商信息块存在核
    # （值可「未取得可核实地址」如实留缺，块名必须在场）。era≥20261017 场（run_root 可判时）。
    if run_root is not None:
        _m60 = effective_run_date(run_root)
        if _m60 and _m60.group(0) >= "20261017" and "软件与厂商" not in compact:
            missing.append("软件与厂商信息块（RF-ELEM-03）")
    # 批六十 G-10（r37：禁脱敏零核）——RF-DOC-08 实测实值，占位词直接 fail
    _redact60 = [w for w in ("<REDACTED>", "[REDACTED]", "credential_ref", "已脱敏", "***REDACTED") if w in text]
    if _redact60:
        missing.append(f"禁脱敏占位（{','.join(_redact60[:2])}，RF-DOC-08 实测实值）")
    # 批六十 G-02/G-04（r37：越权对比图与 admin 合法视角图零核）——按卷文本自判类型核图注词：
    # 越权/横向类须「admin|管理员视角」与「普通|低权|普通用户」双图注成对；
    # 泄露/未授权类须对比形态（合法视角图注或明写挂账/对照说明）。era≥20261017。
    if run_root is not None:
        _m60b = effective_run_date(run_root)
        if _m60b and _m60b.group(0) >= "20261017":
            _cap60 = "\n".join(ln for ln in text.splitlines() if "附图" in ln or "实测截图" in ln)
            if re.search(r"越权|横向|水平|IDOR|idor", text[:2000]):
                _has_adm = bool(re.search(r"admin|管理员|高权|超管", _cap60, re.I))
                _has_low = bool(re.search(r"普通|低权|普通用户|一般用户", _cap60))
                if not (_has_adm and _has_low):
                    missing.append("越权类对比图注（admin/管理员视角 + 普通/低权视角 双图注，RF-IMG-04/08）")
            if re.search(r"未授权|泄露|越权", text[:2000]):
                _has_cmp = bool(re.search(r"admin|管理员|合法视角|对照|对比|登录后|登录门", _cap60, re.I)) or bool(
                    re.search(r"合法视角|对比图|挂账|对照", text)
                )
                if not _has_cmp:
                    missing.append("泄露/未授权类对比形态（合法视角图注或卷内对照说明，RF-IMG-08）")
    ledger_hits = sum(1 for k in LEDGER_DOCX if k in text)
    if ledger_hits >= 3:
        missing.append("结案表顶正式通报")
    internal_hits = {k for k in INTERNAL_TRACE_DOCX if k in text}
    # 2026-10-15 批二十六：RF-IMG-13 图注禁词只扫图注行（含「实测截图」特征词的段落），
    # 正文/请求包实值合法含模型名不拦（旧版全文扫裸 "glm" 会误伤 AI 应用类目标，见词表注）
    caption_hits = set()
    for line in text.splitlines():
        if "实测截图" not in line:
            continue
        low = line.lower()
        for k in IMG_CAPTION_TRACE:
            if k in low:
                caption_hits.add(k)
    if caption_hits:
        missing.append(
            f"图注禁标模型名/机器复核字样（RF-IMG-13，复核结论只落 run/vision-reviews/ 确认件；"
            f"画面内真实可见的模型名/下拉不写具体值，写「模型列表页/模型下拉」类描述——RF-IMG-12 如实描述"
            f"与 RF-IMG-13 禁标注的分工：具体值走 vision_gate --claim 核对与请求包实值承载）: "
            f"{'、'.join(sorted(caption_hits)[:6])}"
        )
    # 2026-10-13 C2 修：chain-N 作为「链编号指代」仍拦，但排除证据文件名引用
    # （采证指针写「本场实测原件 chain-01-r1.txt」合法；裸提 chain-01 编号才违规）
    for m in re.finditer(r"chain-\d+", text, re.I):
        seg = text[max(0, m.start()-2):m.end()+24]
        is_evidence_filename = re.search(r"chain-\d+[-.\w]*\.(txt|json|png|md|jpeg|jpg|mkv|log|py|http)", seg, re.I)
        # 2026-10-15 批二十：载荷常量字面豁免——marker 串「CHAIN-01-RCE-MARKER …」是攻击载荷本体
        # （证据原件逐字内容），不是内部账指针指代；证据原件逐字呈现受 RF-DOC-06/08 保护，不得为过闸改写。
        is_payload_constant = re.search(r"chain-\d+-[A-Z][A-Z_-]{3,}", seg, re.I)  # 载荷常量段内含连字符（CHAIN-01-RCE-MARKER 的 RCE-）
        if not is_evidence_filename and not is_payload_constant:
            internal_hits.add(m.group(0).lower())
    if internal_hits:
        missing.append(f"内部角色/账目痕迹不得进正式卷: {'、'.join(sorted(internal_hits)[:6])}")
    # 批三十七（红队三轮 P1-10）：采证指针存在性核——RF-ELEM-06 要求每条接口带
    # 「——采证记录：本场实测原件〈文件名〉」，此前只查 8 块字不查指针指向的文件在不在；
    # 没实测的路由配一个不存在的「原件名」即可把没打的口写进危害段
    for pm in re.finditer(r"采证记录[：:]\s*本场实测原件[〈<]([^〉>\n]+)[〉>]", text):
        pname = pm.group(1).strip().strip("`")
        if not pname or pname.startswith("<"):
            continue
        found = any(p.name == pname for p in run_root.rglob(pname)) if run_root else False
        if not found:
            missing.append(f"采证指针指向的原件不存在: {pname}（没实测的口不得配幽灵原件进卷）")
    if missing:
        fail(
            f"reports/{path.name} 不是正式 8 块通报（vuln-report-format）",
            {"missing": missing},
        )


def _find_capture_image(run_root: Path, stem: str) -> Path | None:
    """批十一辅助：按确认件 stem 在场内常规位置找实图（captures-index 标注的路径优先，
    其次 captures/ 与 run/ 下同名 png/jpg/jpeg）。找不到返回 None（闸记注不拦）。"""
    # ① captures-index.json 里登记的 path/address 最准
    ci = run_root / "run" / "captures-index.json"
    if ci.is_file():
        try:
            data = json.loads(ci.read_text(encoding="utf-8"))
            items = data.get("items") if isinstance(data, dict) else data
            if isinstance(items, list):
                for it in items:
                    if not isinstance(it, dict):
                        continue
                    cand = str(it.get("path") or it.get("file") or "")
                    if cand and Path(cand).stem == stem:
                        p = Path(cand)
                        if not p.is_absolute():
                            p = run_root / cand
                        if p.is_file():
                            return p
        except Exception:  # noqa: BLE001
            pass
    # ② 常规目录同名兜底
    for d in (run_root / "run" / "captures", run_root / "captures", run_root / "run"):
        if d.is_dir():
            for ext in (".png", ".jpg", ".jpeg"):
                p = d / f"{stem}{ext}"
                if p.is_file():
                    return p
    return None


def _reports_high_sev(run_root: Path) -> bool:
    import json as _js

    rj = run_root / "reports" / "json"
    for jf in sorted(rj.glob("*.json")) if rj.is_dir() else []:
        try:
            _j = _js.loads(jf.read_text(encoding="utf-8"))
        except Exception:
            continue
        if isinstance(_j, dict):
            sev = str(_j.get("severity") or _j.get("level") or "").lower()
            if any(k in sev for k in ("high", "critical", "严重", "高危")):
                return True
    return False


def _vision_random_recheck(run_root: Path, ok_reviews: list[str], legacy: list[str], notes: list[str]) -> None:
    """批三十五 P1-4：嵌图确认件随机 faker 复检；批三十六（红队二轮 P1-6）两点升级：
    ① 抽样提率——legacy 无 sha 件必抽 1，高危/严重场加抽 1，基准 1 张、上限 3 张
    （1/N 抽中概率低于造假收益时闸的经济性反转，提率压缩伪造期望收益）；
    ② faker 通道断从 note 升 fail——通道断时抽查归零等于给造假者一个「拔网线」开关；
    对齐 RF-GATE-03「复核中断挂起等恢复」：close failed 不是终态，通道恢复重跑即过。"""
    import random

    era = effective_run_date(run_root)
    if not era or era.group(0) < LEDGER_STRICT_ERA:
        return
    pool: list[tuple[str, Path]] = []
    for stem in (legacy or []) + ok_reviews:
        img = _find_capture_image(run_root, stem)
        if img is not None:
            pool.append((stem, img))
    if not pool:
        notes.append("vision_recheck_no_resolvable_image(图不在常规位置，复检未执行)")
        return
    _base38 = max(1, -(-len(pool) // 4))  # 批三十八（红队四轮 P2-B）：抽 1→25% 起步（识图费极低）
    n_sample = _base38 + (1 if legacy else 0) + (1 if _reports_high_sev(run_root) else 0)
    n_sample = min(n_sample, 4, len(pool))
    legacy_stems = {s for s, _ in pool if s in (legacy or [])}
    picked: list[tuple[str, Path]] = [p for p in pool if p[0] in legacy_stems][:1]
    rest = [p for p in pool if p not in picked]
    picked.extend(random.sample(rest, min(n_sample - len(picked), len(rest))))
    try:
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        import vision_review as _vr

        for stem, img in picked:
            verdict = _vr.normalize_verdict(_vr.ask_verdict_faker([str(img)], ""))
            if verdict != "evidence_ok":
                fail(
                    f"嵌图确认件随机复检不一致：{stem}.review.md 存档 evidence_ok，faker 复检 {verdict}"
                    "——确认件疑似手写/张冠李戴（P1-4）；用现图重跑 vision_review.py 出新确认件再嵌"
                )
            notes.append(f"vision_recheck_ok({stem}->{verdict})")
    except SystemExit as exc:
        fail(
            f"嵌图确认件随机复检通道不可用（{str(exc)[:120]}）——faker 断线时抽查归零=造假开关（批三十六），"
            "按 RF-GATE-03 挂起等恢复；通道恢复后重跑 close 即过"
        )
    except Exception as exc:  # noqa: BLE001
        fail(
            f"嵌图确认件随机复检通道异常（{type(exc).__name__}: {str(exc)[:120]}）——"
            "按 RF-GATE-03 挂起等恢复，通道恢复后重跑 close 即过"
        )


@collect_errors
def check_vision_report_images(run_root: Path, notes: list[str]) -> None:
    # 2026-10-08 终版用户口径「默认不截图，截图我要申明」：仅当 run/screenshot-required.json（用户申明）存在时，
    # 才要求每份正位卷内嵌 ≥1 张攻击成功证明截图。
    # 2026-10-08 十五批补「报告也要这样写」：申明场嵌图必先过机器复核——run/vision-reviews/ 须有 ≥1 份
    # 判定行 evidence_ok 的复核件（vision_review.py 产出），分身只嵌复核通过清单里的图。
    # 2026-10-09 晚标准格式升级（用户令「以后报告都是这个格式、图片给 flash 模型看」）：附图段为默认标准件、
    # 申明制退役。20261010 起场次：任何内嵌图的正位卷必须有「本场实测截图」编号图注 + evidence_ok 复核件 ≥1；
    # 0 图卷（无利用成功画面）不拦——无图卷口径由 16 条/分身卡人工把关，不造死锁。旧场维持申明制不追溯。
    import zipfile as _zf

    m = effective_run_date(run_root)
    new_era = bool(m and m.group(0) >= "20261010")
    declared = (run_root / "run" / "screenshot-required.json").is_file()
    # 批五十（用户问「交假的截图怎么办」）：mock/仿真/占位嫌疑件在场时，证据图与嫌疑件做字节/像素级
    # 对账——嵌卷图与 mock 产物同哈希或像素同图 = 自导自演实锤 fail。三个侦察面：
    # ①文件名带 mock/lab/simulate/fake/仿真/占位 的图片件 ②PoC 目录（*/poc/、*/packs/）内图片
    # ③卷内 media 图与上述嫌疑池任一命中。不拦 mock 本身（仿真靶场是 RF-PKG-04 合法工具）。
    _suspect_pool: dict[str, str] = {}
    if m and m.group(0) >= "20261016":
        import hashlib as _hl50
        import re as _re50

        _mock_pat = _re50.compile(r"mock|lab|simulat|fake|dummy|placeholder|仿真|占位|演示靶", _re50.I)
        # 批五十三 R5-02 补刀：lab 只作独立词命中（collab/gitlab/label 子串误杀），其余关键词子串安全
        _mock_sub = _re50.compile(r"mock|simulat|fake|dummy|placeholder|仿真|占位|演示靶", _re50.I)
        _lab_tok = _re50.compile(r"(?:^|[._\-/ ])lab(?:[._\-/ ]|$)", _re50.I)
        _mock_hit = lambda t: bool(_mock_sub.search(t) or _lab_tok.search(t))
        for p in run_root.rglob("*"):
            if not p.is_file() or p.suffix.lower() not in IMAGE_EXT:
                continue
            rel = str(p.relative_to(run_root))
            if any(seg in p.parts for seg in SKIP_WALK):
                continue
            in_poc = any(seg.lower() in ("poc", "packs", "pack-src") for seg in p.relative_to(run_root).parts)
            # 批五十一 R4-S-02：目录名同样入侦察（mock-target/01.png 此前不进池）
            # 批五十三 R5-02：改用 run_root 相对段——绝对路径祖先含 lab（gitlab/collab）曾致全图误判
            dir_hit = any(_mock_hit(seg) for seg in p.relative_to(run_root).parts[:-1])
            if _mock_hit(p.name) or in_poc or dir_hit:
                try:
                    _suspect_pool[_hl50.sha256(p.read_bytes()).hexdigest()] = rel
                except OSError:
                    continue
    if not new_era and not declared:
        notes.append("vision_images_skip(not_declared)")
        return
    img_docs: list[tuple[Path, int]] = []
    zero_docs: list[str] = []
    for docx in _official_finding_docxs(run_root):  # 批四十五 B-11：子目录卷一并查
        name = docx.name
        # 2026-10-13 四4 修：豁免收紧——复审/复测卷按重写线新规也要九要素附图检查，不再豁免；
        # 只豁免明确非 finding 卷（test-summary 总览件/复审复测「总报告」）
        if any(k in name for k in ("test-summary",)) or ("总报告" in name and ("复审" in name or "复测" in name)):
            continue
        try:
            media = [n for n in _zf.ZipFile(docx).namelist() if n.startswith("word/media/")]
        except OSError:
            media = []
        # 批五十：嵌卷图 × mock 嫌疑池字节级对账
        if media and _suspect_pool:
            try:
                _z50 = _zf.ZipFile(docx)
                for _mn in media:
                    _mh = _hl50.sha256(_z50.read(_mn)).hexdigest()
                    if _mh in _suspect_pool:
                        fail(
                            f"正位卷 {name} 内嵌图 {_mn} 与 mock/仿真嫌疑件字节一致（{_suspect_pool[_mh]}）——"
                            "自导自演实锤（批五十）：仿真靶场图只能进 PoC 验证记录，禁当证据图嵌卷（RF-IMG-11）"
                        )
            except OSError:
                pass
        if media:
            img_docs.append((docx, len(media)))
        else:
            zero_docs.append(name)
    if declared and zero_docs:
        fail(f"申明场正位卷必须内嵌攻击成功截图（效果实测原图；报错图禁交）: {zero_docs[0]} 等 {len(zero_docs)} 卷 0 张内嵌图")
    # 批四十七 RF-IMG-19：截图默认必嵌——website 场 0 图卷须落机器可读豁免件（「人工把关」实测无人把关，退役）
    # 批四十八 起服优先（用户令「有源码直接起服复现」）：材料/源码在场=无豁免资格，起服复现拍真图
    if m and m.group(0) >= "20261016" and zero_docs:
        _env = envelope(run_root) or {}
        _branch = str(_env.get("branch", ""))
        _va = _env.get("visual_available")
        if _branch and _va is False:
            # 批四十九：visual_available=false 是自报键——本场明明有采证图/采证账还自称无视觉=谎报降级躲截图
            _cap_dir = run_root / "run" / "captures"
            _has_shots = _cap_dir.is_dir() and any(p.suffix.lower() in IMAGE_EXT for p in _cap_dir.rglob("*") if p.is_file())
            _cap_idx = run_root / "captures-index.json"
            if not _has_shots and _cap_idx.is_file():
                _ci = load_json(_cap_idx) or {}
                _has_shots = bool(_ci.get("captures"))
            # 批五十三 R5-09：run/ 标准位 captures-index 同样入反查（此前只认根位，穿盾）
            if not _has_shots:
                _ci_run = run_root / "run" / "captures-index.json"
                if _ci_run.is_file():
                    _cir = load_json(_ci_run) or {}
                    _has_shots = bool(_cir.get("captures"))
            _capb = run_root / "capability.json"
            if not _has_shots:
                for _cd in run_root.glob("0*/capability.json"):
                    _cb = load_json(_cd) or {}
                    # 批五十八 D（SKILL 体检 r36 P2）：capability 模板用字符串枚举（available/unavailable），
                    # 此处按布尔 is True 读——照模板填永远不命中。双态兼容。
                    if _cb.get("screenshot_capture_in_run") is True or str(_cb.get("screenshot_capture_in_run") or "").lower() in ("available", "true"):
                        _has_shots = True
                        break
            if _has_shots:
                fail(
                    "信封 visual_available=false 与本场采证事实矛盾（run/captures 有图 / captures-index 有账 / capability 记 in_run=true）"
                    "——谎报视觉降级躲截图（批四十九）；如实改 true 并按 RF-IMG-19 起服拍图或走真实豁免"
                )
        if _branch and _va is not False:
            _mat = str(_env.get("material_source_path", "") or "").strip()
            _has_source = _branch in ("local_source", "source_and_website") or bool(_mat)
            _wf = run_root / "run" / "no-screenshot-waiver.json"
            if _has_source:
                if _wf.is_file():
                    notes.append("no_screenshot_waiver_ignored(材料/源码在场——豁免无效)")
                # 批五十三 R5-04：起服失败的诚实出口——尝试记录在案（≥2 条命令+≥1 证据件）降 note 交曹操裁
                _sf = run_root / "run" / "service-start-failure.json"
                _sf_ok = False
                if _sf.is_file():
                    _sfd = load_json(_sf) or {}
                    _sfr = str(_sfd.get("reason", "")).strip()
                    _cmds = [c for c in (_sfd.get("attempted_commands") or []) if isinstance(c, str) and c.strip()]
                    _evs = [e for e in (_sfd.get("evidence") or []) if (run_root / str(e)).is_file()]
                    # 批五十五（摸鱼 v3 招3）：命令必须落在证据件文本里（编两条没跑过的命令+无关假报错曾直接过）
                    _ev_txt = "".join((run_root / str(e)).read_text(encoding="utf-8", errors="ignore")[:40000] for e in _evs)
                    _cmds_in_ev = bool(_evs) and all(c in _ev_txt for c in _cmds)
                    if len(_sfr) >= 20 and len(set(_sfr)) >= 6 and len(_cmds) >= 2 and _cmds_in_ev:
                        _sf_ok = True
                if _sf_ok:
                    notes.append("service_start_failed(起服尝试在案 run/service-start-failure.json——交曹操裁，批五十三 R5-04)")
                else:
                    fail(
                        f"正位卷 {zero_docs[0]} 等 {len(zero_docs)} 卷 0 张内嵌图——本场材料/源码在场，无豁免资格："
                        "起服复现（起服账认 run/process-provenance.json）拍真实攻击效果截图嵌卷"
                        "（RF-IMG-19/RF-IMG-11，禁 mock/仿真图充当）；确实起不来：落 run/service-start-failure.json"
                        "（reason ≥20 字 + attempted_commands ≥2 条 + evidence ≥1 实件）交曹操裁（批五十三 R5-04 出口）"
                    )
            # 批五十五（摸鱼 v3 W4b 实锤）：起服失败出口拿 note 后不得再掉进 website 豁免路径——
            # 材料在场场（_has_source）已被上面分支处置（fail 或 sf 出口 note），豁免路径只属非材料场
            if not _has_source:
                if not _wf.is_file():
                    fail(
                        f"正位卷 {zero_docs[0]} 等 {len(zero_docs)} 卷 0 张内嵌图——website 场默认必嵌攻击成功截图"
                        "（RF-IMG-19 效果类前端打底）；确无可拍（纯远程目标不可达）须先落 "
                        "run/no-screenshot-waiver.json（reason ≥20 字写实理由+证据指针），无豁免件 close 不放行"
                    )
                _wj = load_json(_wf) or {}
                _r = str(_wj.get("reason", "")).strip()
                # 批五十三 R5-11：去水字数——20 个「靶」字这类同字堆砌不算理由（不同字符 ≥6）
                if len(_r) < 20 or len(set(_r)) < 6:
                    fail("no-screenshot-waiver.json reason 不合格（≥20 字且不同字符 ≥6，写实理由+证据指针，如 nslookup/curl 不可达原件路径）——无图豁免不许空壳")
                notes.append("no_screenshot_waiver(" + _r[:40] + "…)")
    if new_era and img_docs:
        for docx_p, n in img_docs:
            try:
                xml = docx_plain_text(docx_p)  # 批四十二：原文 XML 中文图注跨 run 拆段会假阴性（批四十五 B-11：子目录卷传完整路径）
            except Exception:
                continue
            if "本场实测截图" not in xml:
                fail(f"正位卷 {docx_p.name} 内嵌 {n} 图但无「本场实测截图」编号图注——标准格式附图段图注=「附图N…：〈描述〉（本场实测截图）」（2026-10-09 格式升级）")
    # 批五十八 E（用户看卷抓出：RF-IMG-15 布局 A 正文有规、闸无机械核——F 卷 6 张全是单窗图照过闸）；
    # 批五十八 E 收口（r37 审计 G-01 三洞）：①分支覆盖扩全分支（is_website 只认 website 两值，
    # source_and_website/local_source 场可整支逃逸）；②dual 件必须哈希绑定真实嵌图——此前场级
    # 存在性核：任意一份手写「kind: dual」件（无 sha/图路径 orphan 件）即可让全场嵌图卷过闸，
    # 且该件图路径不解析时 faker 随机复检直接跳过（零复检风险）。修：确认件 sha256 命中嵌图 media
    # 或 图: 路径实文件哈希命中 media 才算 dual 达标；零达标=构图不合格 fail。
    if new_era and img_docs:
        _envE = envelope(run_root)
        if _envE.get("visual_available") is not False:
            import hashlib as _hl58e
            import zipfile as _zf58e

            _media58e: set[str] = set()
            for _dp, _dn in img_docs:
                try:
                    _z58e = _zf58e.ZipFile(_dp)
                except Exception:  # noqa: BLE001
                    continue
                with _z58e:
                    for _ii in _z58e.infolist():
                        if _ii.filename.startswith("word/media/"):
                            _media58e.add(_hl58e.sha256(_z58e.read(_ii.filename)).hexdigest())
            _vrE = run_root / "run" / "vision-reviews"
            _dual58e = False
            if _vrE.is_dir() and _media58e:
                for _rvE in _vrE.glob("*.review.md"):
                    try:
                        _txtE = _rvE.read_text(encoding="utf-8", errors="ignore")
                    except OSError:
                        continue
                    if not re.search(r"kind\s*[:=]\s*dual|--kind\s+dual", _txtE[:2000], re.I):
                        continue
                    _msha58 = re.search(r"sha256\s*[:=]\s*([0-9a-fA-F]{64})", _txtE)
                    if _msha58 and _msha58.group(1).lower() in _media58e:
                        _dual58e = True
                        break
                    _mimg58 = re.search(r"图\s*[:=]\s*(\S+)", _txtE)
                    if _mimg58:
                        _ip58 = run_root / _mimg58.group(1).strip().strip("`")
                        try:
                            if _ip58.is_file() and _hl58e.sha256(_ip58.read_bytes()).hexdigest() in _media58e:
                                _dual58e = True
                                break
                        except OSError:
                            pass
            if not _dual58e:
                fail(
                    "附图段构图不合格（RF-IMG-15 布局 A，批五十八 E）：嵌图卷零 dual 达标确认件"
                    "——效果类取证图必须「浏览器最大化打底为画面主体+cmd 浮窗配角」同框两证"
                    "（scripts/vision_gate.py --kind dual 拍摄，确认件 sha256 或 图: 路径须与嵌图"
                    "哈希绑定，手写 orphan dual 件不算），纯 cmd 图仅限无前端可拍证据（库侧查询/"
                    "文件读回/纯 API 回包）；重拍效果类图过 dual 确认后嵌卷"
                )
            else:
                notes.append("rf_img15_dual_ok")
    if img_docs or declared:
        vr_dir = run_root / "run" / "vision-reviews"
        ok_reviews = []
        if vr_dir.is_dir():
            # 批五十九 D-2（r38 实锤）：旧习 .gate.json 扩展名件（metinfo/hkcms 真实场已在产）
            # 与 .review.md 同内容——三消费点全部硬编码 review.md 摸不到它们；双扩展名同收
            for rv in sorted(list(vr_dir.glob("*.review.md")) + list(vr_dir.glob("*.gate.json"))):
                try:
                    head = rv.read_text(encoding="utf-8")[:400]
                except OSError:
                    continue
                if verdict_ok_in(head):
                    ok_reviews.append(rv.name)
        # 2026-10-13 C7 修：按图 stem 去重计数（<stem>.review.md 同 stem 多份只算一份——
        # 「逐张对齐」旧实现是裸计数，同图刷多份确认件可过闸）；批五十九 D-2：双扩展名归一 stem
        def _stem59(r: str) -> str:
            return r[:-len('.review.md')] if r.endswith('.review.md') else (r[:-len('.gate.json')] if r.endswith('.gate.json') else r)
        _uniq = {_stem59(r) for r in ok_reviews}
        if len(_uniq) < len(ok_reviews):
            notes.append(f"vision_review_dup_stems({len(ok_reviews) - len(_uniq)})")
        ok_reviews = sorted(_uniq)
        if not ok_reviews:
            fail(
                "内嵌图卷缺 flash 机器复核通过件：run/vision-reviews/ 无「判定: evidence_ok」——"
                "每张附图先过 scripts/vision_review.py（glm-5.3-flash），只嵌 evidence_ok 清单里的图"
                "（2026-10-09 用户令「图片给 flash 模型看」＝硬门）"
            )
        # 2026-10-15 批十一（哈希绑定，批十挂账项）：确认件写了 sha256 的必须与盘上实图一致——
        # 图被换掉/重存后旧确认件哈希对不上 = 张冠李戴，fail。旧格式件（无 sha256 行）不追溯放行+记注。
        import hashlib as _hg_hl
        mismatch: list[str] = []
        legacy: list[str] = []
        for stem in ok_reviews:
            rv = next((vr_dir / n for n in (f"{stem}.review.md", f"{stem}.gate.json") if (vr_dir / n).is_file()), vr_dir / f"{stem}.review.md")
            try:
                txt = rv.read_text(encoding="utf-8")
            except OSError:
                continue
            m_sha = re.search(r"sha256:\s*([0-9a-fA-F]{64})", txt)
            if not m_sha:
                legacy.append(stem)
                continue
            # 同件可复核多图（--image 多张）：比对件内全部 sha256，任一命中盘上同名图即算绑定成立
            shas = set(re.findall(r"sha256:\s*([0-9a-fA-F]{64})", txt))
            img_path = _find_capture_image(run_root, stem)
            if img_path is None:
                # 图不在 captures/ 常规位置（可能嵌卷后挪档）——有 sha256 但找不到实图可核，记注不拦
                notes.append(f"vision_hash_unverifiable({stem})")
                continue
            actual = _hg_hl.sha256(img_path.read_bytes()).hexdigest()
            if actual not in shas:
                mismatch.append(stem)
        if mismatch:
            fail(
                "确认件与实图哈希不符（张冠李戴）："
                + ",".join(mismatch)
                + "——图在复核后被替换/重存，须用现图重跑 vision_review.py 出新确认件"
            )
        if legacy:
            notes.append(f"vision_hash_legacy_no_sha({len(legacy)})")
        # 批六十 G-12（r37：RF-GATE-01 拍后即验无痕）——note 级轻核：图 mtime 晚于确认件落盘时间
        # 超 60s=图在复核后被重存/触碰（哈希绑定已拦换图，这里抓「重存同内容」的时序异常留痕供链审）
        import datetime as _dt60

        for stem in ok_reviews:
            rv60 = next((vr_dir / n for n in (f"{stem}.review.md", f"{stem}.gate.json") if (vr_dir / n).is_file()), None)
            img60 = _find_capture_image(run_root, stem)
            if rv60 is None or img60 is None:
                continue
            _t60m = re.search(r"时间[：:]\s*(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})", rv60.read_text(encoding="utf-8", errors="ignore"))
            if not _t60m:
                continue
            try:
                _rt60 = _dt60.datetime.fromisoformat(_t60m.group(1)).timestamp()
            except ValueError:
                continue
            if img60.stat().st_mtime - _rt60 > 60:
                notes.append(f"vision_review_after_touch({stem}: 图 mtime 晚于确认件 {int(img60.stat().st_mtime - _rt60)}s——复核后重存痕迹，链审复核)")
        # 批五十九 D-1+B-2（r38 体检：orphan 手写 ok 件三关全免 + 「逐张对齐」实为数量对比）：
        # ①orphan 剔除——ok 件按 stem 找不到图、件内「原图:」路径也解析不出实图的，不计入 ok_reviews
        #   （手写指向不存在图的假确认件：收集认→哈希 skip→复检池空，三关全免的完整伪造链在此堵死）；
        # ②media 逐张绑定——卷内每张嵌图哈希必须命中某份 ok 确认件可溯源的图哈希集（件内 sha256 ∪
        #   盘上实图哈希），嵌图数>可溯源唯一图数=拿别图 ok 件凑数，fail。era≥20261017 场生效。
        _era59 = bool((m_59 := effective_run_date(run_root)) and m_59.group(0) >= "20261017")
        import zipfile as _zf59mod

        def _zf59_zip(_p):
            return _zf59mod.ZipFile(_p)

        if _era59:
            _orphan59: list[str] = []
            _bind59: set[str] = set()
            for stem in ok_reviews:
                rv59 = next((vr_dir / n for n in (f"{stem}.review.md", f"{stem}.gate.json") if (vr_dir / n).is_file()), vr_dir / f"{stem}.review.md")
                try:
                    _txt59 = rv59.read_text(encoding="utf-8")
                except OSError:
                    _txt59 = ""
                img59 = _find_capture_image(run_root, stem)
                if img59 is None:
                    _mp59 = re.search(r"[-–]\s*原图[:：]\s*(\S+)", _txt59)
                    if _mp59:
                        _cand59 = run_root / _mp59.group(1).strip().strip("`\"'")
                        if _cand59.is_file():
                            img59 = _cand59
                if img59 is None:
                    _orphan59.append(stem)
                    continue
                _bind59.add(_hg_hl.sha256(img59.read_bytes()).hexdigest())
                _bind59.update(re.findall(r"sha256:\s*([0-9a-fA-F]{64})", _txt59))
            if _orphan59:
                ok_reviews = [s for s in ok_reviews if s not in set(_orphan59)]
                notes.append("vision_orphan_excluded(" + ",".join(_orphan59) + ")")
                if not ok_reviews:
                    fail(
                        "嵌图确认件全部为 orphan（图路径解析不出实图）："
                        + ",".join(_orphan59)
                        + "——指向不存在图的手写 ok 件不算机器复核（批五十九 D-1）；"
                        "每张附图用真图重跑 vision_review.py，件内「原图:」路径须指向实文件"
                    )
            _media59: set[str] = set()
            for _dp59, _dn59 in (img_docs or []):
                try:
                    _z59 = _zf59_zip(_dp59)
                except Exception:  # noqa: BLE001
                    continue
                with _z59:
                    for _ii59 in _z59.infolist():
                        if _ii59.filename.startswith("word/media/"):
                            _media59.add(_hg_hl.sha256(_z59.read(_ii59.filename)).hexdigest())
            _unbound59 = _media59 - _bind59
            if _unbound59:
                fail(
                    f"嵌图 {len(_unbound59)}/{len(_media59)} 张无对应 ok 确认件可溯源哈希（批五十九 B-2）——"
                    "「逐张对齐」旧实现只比数量，别图 ok 件可给未确认嵌图凑数；每张嵌图都须有"
                    "vision_review.py 确认件（sha256/原图路径与卷内 media 哈希一致）"
                )
        # 批三十五 P1-4：随机抽 1 张重跑 faker 判定（防纯手写确认件——外部神谕抽查）
        _vision_random_recheck(run_root, ok_reviews, legacy, notes)
    notes.append("vision_report_images_ok")
    if img_docs:
        notes.append(f"vision_review_evidence_ok({len(ok_reviews) if img_docs or declared else 0})")


def check_wugai_report_standard(run_root: Path, notes: list[str]) -> None:
    # 2026-10-11 五改四样上闸（用户令「上闸机拦」）：⑮脚本全文段 / ⑯PDF 副本 / ⑰前端图存在 /
    # ⑱禁脚本截图（内容形态机器不可判，归 flash 复核问题清单，闸层只留 skip 注记）。
    # 生效线 20261011 起新场次；旧场不追溯（追补走工单，不受闸约束）。
    import zipfile as _zf

    m = effective_run_date(run_root)
    if not m or m.group(0) < "20261011":
        notes.append("wugai_standard_skip(pre_20261011)")
        return
    reports = run_root / "reports"
    if not reports.is_dir() or not _official_finding_docxs(run_root):  # 批四十五 B-11：子目录卷一并计入
        notes.append("wugai_standard_skip(no_reports)")
        return
    # 场次是否用到脚本/工具件（run/files 下 py/js/bat/sql 或 tools-pack.zip）
    files_dir = run_root / "run" / "files"
    has_tools = (run_root / "tools-pack.zip").is_file() or (run_root / "run" / "tools-pack.zip").is_file()
    if files_dir.is_dir():
        has_tools = has_tools or any(files_dir.glob(f"*{e}") for e in (".py", ".js", ".bat", ".sql"))
    for docx in _official_finding_docxs(run_root):  # 批四十五 B-11：子目录卷一并查
        name = docx.name
        # 2026-10-13 四4 修：豁免收紧——复审/复测卷按重写线新规也要九要素附图检查，不再豁免；
        # 只豁免明确非 finding 卷（test-summary 总览件/复审复测「总报告」）
        if any(k in name for k in ("test-summary",)) or ("总报告" in name and ("复审" in name or "复测" in name)):
            continue
        try:
            xml = _zf.ZipFile(docx).read("word/document.xml").decode("utf-8", errors="ignore")
            media = [n for n in _zf.ZipFile(docx).namelist() if n.startswith("word/media/")]
            embeds = re.findall(r'r:embed="(rId\d+)"', xml)  # 实际引用数（孤儿 media part 不算嵌入）
        except Exception:
            continue
        # ⑮ 脚本全文段：用了工具件的场次，每卷须有「附：脚本全文」段
        if has_tools and "附：脚本全文" not in xml:
            fail(f"五改⑮：正位卷 {name} 缺「附：脚本全文」段——复现脚本全文上卷（无长度豁免），不只锁 tools-pack.zip")
        # ⑯ PDF 副本：同名 .pdf 必须在 reports/ 同目录（批四十五 B-11：子目录卷按同目录判）
        if not docx.with_suffix(".pdf").is_file():
            fail(f"五改⑯：reports/ 缺 {docx.stem}.pdf——正式报告 DOCX 之外须单独存同名 PDF 副本（报告文件永不进 zip）")
        # ⑰ 前端图存在：有图卷须有前端/UI 位置图注（静态壳与否的内容判定归 flash 复核）
        if embeds and ("前端" not in xml and "UI" not in xml):
            fail(f"五改⑰：内嵌 {len(embeds)} 图的卷 {name} 无前端/UI 位置图注——每卷必有前端漏洞位置图（效果或多视角；纯 API 截项目关联前端，仅无前端项目回包顶替）")
        # ⑭ 落地前后（写入文件类，2026-10-11 用户令）：卷名含写入类关键词时，图注须同时有「前」与「后」基线/落地图注
        _write_kw = ("写入", "文件写", "建表", "改数", "RCE")
        if embeds and any(k in name for k in _write_kw):
            has_before = any(k in xml for k in ("攻击前", "落地前", "建表前", "文件不存在", "BASELINE"))
            has_after = any(k in xml for k in ("攻击后", "落地后", "读回", "marker 行"))
            if not (has_before and has_after):
                fail(f"四改⑭（2026-10-11 强化）：写入文件类卷 {name} 缺攻击前/攻击后配对图注——前基线图（文件不存在/ERROR 1146/计数 0）与后落地图（读回/marker 行）两张缺一不可、同会话同链")
        # ⑱ 禁脚本控制台截图：机器不可判终端形态，分身卡+flash 复核 question 带此问；闸层注记
        # ㉒ 占位图（2026-10-12 八改）：同卷内重复引用同一 media part 充当多张不同证据图＝占位图铁证，拦
        if embeds and len(embeds) != len(set(embeds)):
                fail(f"八改㉒：卷 {name} 同一张图被重复嵌入充当多张证据图（{len(embeds)} 次引用仅 {len(set(embeds))} 张不同图）——占位图禁用；无合格图按无图卷口径出卷+补拍挂账")
        # ㉔ 模型确认门逐张对齐（2026-10-12 九改）：嵌入图数须 ≤ evidence_ok 确认件数（每张图一份确认件）
        if embeds:
            vr_dir = run_root / "run" / "vision-reviews"
            ok_stems = set()
            ok_n = 0
            if vr_dir.is_dir():
                for rv in vr_dir.glob("*.review.md"):
                    try:
                        head = rv.read_text(encoding="utf-8")[:400]
                    except OSError:
                        continue
                    if verdict_ok_in(head):
                        # 2026-10-13 C7 真修：按图 stem 去重（同图 N 份确认件禁凑 N 张配额——刷件洞堵主闸）
                        _stem = rv.name[:-len('.review.md')] if rv.name.endswith('.review.md') else rv.name
                        if _stem not in ok_stems:
                            ok_stems.add(_stem)
                            ok_n += 1
            if ok_n < len(set(embeds)):
                fail(f"九改㉔：卷 {name} 嵌入 {len(set(embeds))} 张图但 run/vision-reviews/ 仅 {ok_n} 份 evidence_ok 确认件——每张嵌入图须一份模型看图确认件（图注↔画面相符+形态合规+非内部界面；flash 不可用由主会话出件）；无确认件＝未确认图禁嵌")
    notes.append("wugai_standard_ok(⑮脚本段/⑯副本/⑰前端图注/㉒占位图/㉔逐张确认件已拦；⑱内容形态归复核)")


def check_one_docx(f: Path, label: str) -> None:
    if f.stat().st_size < 2000:
        fail(f"{label} 太小，不像正式 DOCX")
    if file_head(f, 4)[:2] != b"PK":
        fail(f"{label} 不是 ZIP/DOCX 文件头")
    if "cors" in f.name.lower():
        fail(f"正式报告文件名含 cors: {f.name}")


def has_below_medium_disposition(run_root: Path) -> bool:
    # 2026-10-07 口径：低危 verified 不出正式卷（verified ≠ 可交，认 rules vuln-report-format「不写」行）。
    # 全场只剩低危时，close 凭判决件 below_medium/低危不交处置放行；否则仍要求至少一份独立 finding DOCX。
    # 批三十六（红队二轮 P2-10）：verdict 里任何位置出现 below_medium 子串即免检的口径收紧——
    # era≥20261015 只认 levels 段结构化条目（grade/level/severity/判* 键值含 低危/below_medium）；
    # 存量场保留子串兼容。
    verdict = run_root / "02-cao-cao-shadow" / "delivery-verdict.json"
    if not verdict.is_file():
        return False
    try:
        data = json.loads(verdict.read_text(encoding="utf-8"))
    except Exception:
        return False
    if not isinstance(data, dict):
        return False
    levels = data.get("levels")
    if isinstance(levels, list):
        for item in levels:
            if isinstance(item, dict) and any(
                "低危" in str(v) or "below_medium" in str(v).lower()
                for k, v in item.items()
                if "判" in str(k) or "grade" in str(k).lower() or "level" in str(k).lower() or "severity" in str(k).lower()
            ):
                return True
    m = effective_run_date(run_root)
    if m and m.group(0) >= H22_STRICT_ERA:
        return False
    return "below_medium" in json.dumps(data, ensure_ascii=False)


def has_sealing_disposition(run_root: Path) -> bool:
    # 封存条款：同路由公开编号的卷不出正位（reports/discarded + sealing-receipt）。
    # 全场 verified 都封存时 close 凭回执放行；否则仍要求至少一份独立 finding DOCX。
    receipt = run_root / "reports" / "discarded" / "sealing-receipt.json"
    if not receipt.is_file():
        return False
    try:
        data = json.loads(receipt.read_text(encoding="utf-8"))
    except Exception:
        return False
    items = data.get("sealed_items") if isinstance(data, dict) else None
    return isinstance(items, list) and len(items) > 0


@collect_errors
def check_reports(run_root: Path, notes: list[str]) -> None:
    reports = run_root / "reports"
    # 2026-10-15 批三十四（draft batch30 §1 合入，H-13 机械件）：正位只放 finding DOCX——
    # HTML/MD 等非 DOCX 交付物混正位（真报告用 HTML、docx 放壳的摸鱼手法）直接拦；
    # Word 锁文件单独提示清理。
    # 批三十五修死锁：白名单须放行 .pdf——五改⑯/RF-DOC-07 要求同名 PDF 副本在 reports/ 同目录，
    # 批三十四版把 pdf 一并拒绝=有正位卷的场 close 必 fail（诚实执行者无法收口），单元回归未覆盖义务交叉
    if reports.is_dir():
        for _p in sorted(reports.iterdir()):
            if _p.is_dir():
                continue
            if _p.name.startswith("~$"):
                fail(f"reports/ 存在 Word 临时锁文件 {_p.name}——清理后重跑 close（close failed 清掉成因后重跑）")
            elif _p.suffix.lower() not in (".docx", ".pdf"):
                fail(f"reports/ 正位只放正式 finding DOCX 及其 PDF 副本（H-13；⑯ 要求同名 .pdf 同目录），发现其它文件: {_p.name}——交付物随交付包走，不进正位")
    # 批四十五 B-11：正位卷=reports/ 下全部 docx（rglob，合法子目录除外）——旧顶层 glob 让
    # reports/hidden/secret.docx 逃 8 块检查
    official = _official_finding_docxs(run_root)
    revisions = list((reports / "revisions").rglob("*.docx")) if (reports / "revisions").is_dir() else []
    if not official and not revisions:
        extra = "（本场已有 verified）" if any_verified(run_root) else "（交付/收口必须有 test-summary 或 finding DOCX）"
        fail("reports/ 没有 docx" + extra)
    finding_official = []
    finding_rev = []
    for f in official:
        check_one_docx(f, f"reports/{f.name}")
        if is_summary_docx(f.name):
            continue
        finding_official.append(f)
        check_finding_docx_eight_blocks(f, run_root)
    for f in revisions:
        check_one_docx(f, f"reports/revisions/{f.name}")
        if is_summary_docx(f.name):
            continue
        finding_rev.append(f)
        check_finding_docx_eight_blocks(f, run_root)
    if (
        any_verified(run_root)
        and not finding_official
        and not finding_rev
        and not has_below_medium_disposition(run_root)
        and not has_sealing_disposition(run_root)
    ):
        fail("已有 verified，但 reports/ 与 reports/revisions/ 都没有独立 finding DOCX（test-summary 不算）；若本场 verified 全部低危不交或全部封存，须在 delivery-verdict levels 段记 below_medium 处置、或 reports/discarded/sealing-receipt.json 记 sealed_items（verified ≠ 可交，2026-10-07 口径）")
    if any_verified(run_root) and not finding_official and finding_rev:
        fail("已有 verified，但 reports/ 正位没有独立 8 块 finding（结案壳占正位、真卷只进 revisions 不算交付）")
    # 批三十九（红队五轮 P2）：⑯ 条文「DOCX 同目录同名 PDF 副本」此前无机械核——era≥20261016
    # 正位 finding 卷逐卷核同名 .pdf 存在且 >1KB（0 字节/占位件不算副本）
    if _b39_era(run_root):
        for f in finding_official + finding_rev:
            pdf = f.with_suffix(".pdf")
            if not pdf.is_file():
                fail(f"reports/{f.name} 缺同名 PDF 副本（RF-DOC-07/⑯：DOCX 同目录存同名 .pdf，批三十九机械核）")
            elif pdf.stat().st_size < 1024:
                fail(f"reports/{pdf.name} PDF 副本 <1KB（占位/空件不算副本，批三十九）")
    if not (run_root / "02-cao-cao-shadow").is_dir():
        fail("没有 02-cao-cao-shadow/；分身必须现身出正式 DOCX")
    notes.append("reports_and_shadow_ok")
    if finding_official or finding_rev:
        notes.append("finding_docx_eight_blocks_ok")


@collect_errors
def check_cors_audit(run_root: Path, notes: list[str]) -> None:
    # 2026-10-07 盘问修正：CORS 只对有 web 面的场可测。static_only / 无部署 web 面（同 check_sima_web_duty 口径）
    # 不逼交 Origin+ACAO 实测——起不来的目标测不了 CORS，硬拦 = 死锁。
    env = envelope(run_root)
    d = run_root / "cors-audit"
    if is_static_only(env):
        notes.append("static_only_skip_cors")
        return
    if not is_website(env) and not has_deployed_web_surface(run_root) and not d.is_dir():
        notes.append("no_web_surface_skip_cors")
        return
    if not d.is_dir():
        fail("收口必须有 cors-audit/（CORS 仍挖，不上正式报告）")
    files = [p for p in d.rglob("*") if p.is_file() and p.stat().st_size >= 40]
    if not files:
        fail("cors-audit/ 是空的；至少要有一份实测记录")
    blob = ""
    for p in files:
        if p.suffix.lower() in IMAGE_EXT | VIDEO_EXT | {".zip", ".jar", ".png"}:
            continue
        try:
            blob += p.read_text(encoding="utf-8", errors="ignore") + "\n"
        except OSError:
            continue
    low = blob.lower()
    if "origin" not in low:
        fail("cors-audit 没有 Origin 请求痕迹，空夹/说明文不算实测")
    if "access-control-allow-origin" not in low and "acao" not in low:
        fail("cors-audit 没有 Access-Control-Allow-Origin / ACAO 回包痕迹，必须实测")
    notes.append("cors_audit_ok")


@collect_errors
def check_sima_isolation(run_root: Path, notes: list[str]) -> None:
    root = run_root / "09-si-ma-yi"
    if not root.is_dir():
        notes.append("no_sima_dir")
        return
    leaks = []
    for p in root.rglob("*"):
        if not p.is_file() or p.suffix.lower() in IMAGE_EXT | VIDEO_EXT | {".zip", ".jar"}:
            continue
        if p.stat().st_size > 2_000_000:
            continue
        try:
            text = p.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if SIMA_LEAK.search(text):
            leaks.append(str(p.relative_to(run_root)).replace("\\", "/"))
    if leaks:
        fail("司马懿目录出现郭嘉菜谱/解密链/01-guo-jia 路径", {"files": leaks[:12]})
    notes.append("sima_isolation_ok")


@collect_errors
def run_credential_scan(run_root: Path, notes: list[str]) -> None:
    out_p = run_root / "run" / "credential-scan.json"
    if not CREDENTIAL_SCAN.is_file():
        fail(f"包内 credential_scan.py missing: {CREDENTIAL_SCAN}")
    out_p.parent.mkdir(parents=True, exist_ok=True)
    cmd = [
        sys.executable,
        str(CREDENTIAL_SCAN),
        "--run-root",
        str(run_root),
        "--out",
        str(out_p),
    ]
    try:
        # 批四十五 B-20：加 timeout=300——挂起的扫描旧版永久阻塞 close；超时结构化 fail
        proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=300)
    except subprocess.TimeoutExpired:
        fail("credential_scan 超时（>300s）——挂起的扫描不得放行 close（批四十五 B-20）；排查 v7 credential_scan.py 后重跑")
    except OSError as exc:
        fail(f"credential_scan failed to start: {exc}")
    payload = load_json(out_p)
    if not payload:
        raw = (proc.stdout or "") + (proc.stderr or "")
        fail("credential_scan did not write a JSON receipt", {"stdout_tail": raw[-2000:]})
    status = str(payload.get("status") or "").lower()
    if status == "violations":
        fail("credential_scan found leaked values outside allowed files", {"scan": str(out_p)})
    if status == "no_credentials_declared":
        # 2026-10-08 用户口径：白盒源码自带公开默认值不算凭据、不脱敏、不扫描；
        # 凭据账里写明口径标记（无私产凭据）即算有账，防的是「没盘点」不是「没私产」。
        cred_files = list((run_root / "01-guo-jia").glob("credentials-local.txt")) + list((run_root / "run" / "access").glob("*"))
        marker = any("无私产凭据" in (p.read_text(encoding="utf-8", errors="replace") if p.is_file() else "") for p in cred_files)
        if marker:
            notes.append("credential_scan=no_private_creds(白盒口径)")
            return
        fail("收口必须有凭据账（credentials-local.txt 或 run/access）；空账不算过（白盒全场源码默认值可在账内写「本场无私产凭据」标记放行）")
    if status != "clean":
        fail(f"credential_scan status not accepted: {status}", {"scan": str(out_p)})
    notes.append("credential_scan=clean")


def phase_env(run_root: Path) -> None:
    env = envelope(run_root)
    notes: list[str] = []
    if is_website(env):
        check_in_run(run_root, notes)
        check_era_sanity(run_root, notes)  # 批四十一：website 场此前整条 era 回拨防线蒸发（唯一调用点在 return 之后）
        check_canonical_root(run_root, notes)  # 批三十九 P0-3：website 场同样要过 canonical 根（闸自检不分分支）
        notes.append("website_skip_two_topo")
        ok("env", notes)
        return
    if (run_root / "01-guo-jia").is_dir():
        check_three_shots(run_root, notes)
        check_captures(run_root, notes)
        check_cao_chong(run_root, notes)
        check_sink_runtime(run_root, notes)
        check_component_cve(run_root, notes)
        check_keyword_scan(run_root, notes)
        check_auto_chain_scan(run_root, notes)
        check_hybrid_discovery(run_root, notes)
        check_methodology_gap(run_root, notes)
    check_branch_material_cross(run_root)  # 批三十七 P0-2：源码材料谎报 website_only 对称拦
    check_era_sanity(run_root, notes)  # 批三十八 P0-2：era 回拨交叉核
    check_canonical_root(run_root, notes)  # 批三十九 P0-3：开局与 canonical 根比对（防开局后改闸；
    # 开局前改闸会连本检查一起橡皮化——那层防线在闸外：verify.bat 对照 canonical + 用户外发对账，见 draft 批三十九）
    check_in_run(run_root, notes)
    ok("env", notes)


def phase_verify(run_root: Path) -> None:
    notes: list[str] = []
    check_era_sanity(run_root, notes)  # 批五十一 R4-S-06：verify 相位补挂 era 核（run_date 双对账此前仅 env/close 挂，verify 是结 verified 的最后门）
    check_complex_video(run_root, notes)
    check_recording_integrity(run_root, notes)
    check_obfuscation(run_root, notes)
    check_in_run(run_root, notes)
    check_verified_evidence(run_root, notes)
    check_bec_if_yujin(run_root, notes)
    ok("verify", notes)


def _excerpt_in_file(text: str, target_text: str, min_len: int = 15) -> bool:
    """批三十六（红队二轮 P1-7）摘录锚：text 的某一行/行内标点分词片段（去空白后 ≥min_len 字）
    逐字出现在 target_text 中——「左手核右手」的最小机械锚：核对件至少真的引用了被核对文件原文。
    分词防「原文摘录：xxx」带前缀引文被整行匹配误杀。"""
    import re as _re

    norm = _re.sub(r"\s+", "", target_text or "")
    if not norm:
        return False
    for line in (text or "").splitlines():
        s = _re.sub(r"\s+", "", line)
        if len(s) >= min_len and s in norm:
            return True
        _PUNCT = "：:，,；;（）()[]【】「」『』" + chr(34) * 2 + chr(39) * 2  # 批五十六 R29-E-02：raw-string 引号陷阱拆除
        for frag in _re.split("[" + _re.escape(_PUNCT) + "]", s):
            if len(frag) >= min_len and frag in norm:
                return True
    return False


def _iter_dicts(obj):
    stack = [obj]
    while stack:
        cur = stack.pop()
        if isinstance(cur, dict):
            yield cur
            stack.extend(cur.values())
        elif isinstance(cur, list):
            stack.extend(cur)


def _has_anchored_pointer(run_root: Path, obj) -> bool:
    """批三十六 P1-7：指针升级版——dict 内同时有可解析文件指针与 excerpt 键，
    且 excerpt ≥15 字逐字出现在被指文件里（摘录锚，治「指向任何 ≥40B 文件即过」的弱实现）。"""
    for d in _iter_dicts(obj):
        excerpt = str(d.get("excerpt") or "").strip()
        if len(excerpt) < 15:
            continue
        stack = [d]
        while stack:
            cur = stack.pop()
            if isinstance(cur, dict):
                stack.extend(cur.values())
            elif isinstance(cur, list):
                stack.extend(cur)
            elif isinstance(cur, str):
                s = cur.strip()
                if len(s) < 4 or len(s) > 260 or "\n" in s:
                    continue
                p = Path(s)
                if not p.is_absolute():
                    p = run_root / s
                if p.is_file() and p.stat().st_size >= 40:
                    try:
                        if _excerpt_in_file(excerpt, p.read_text(encoding="utf-8", errors="ignore")):
                            return True
                    except OSError:
                        continue
    return False


def _has_resolved_pointer(run_root: Path, obj) -> bool:
    """批三十五 P1-5：段内任一字符串值按场内相对/绝对路径解析到 ≥40B 实件即算有原件指针。"""
    if obj is None:
        return False
    stack = [obj]
    while stack:
        cur = stack.pop()
        if isinstance(cur, dict):
            stack.extend(cur.values())
        elif isinstance(cur, list):
            stack.extend(cur)
        elif isinstance(cur, str):
            s = cur.strip()
            if len(s) < 4 or len(s) > 260 or "\n" in s:
                continue
            p = Path(s)
            if not p.is_absolute():
                p = run_root / s
            if p.is_file() and p.stat().st_size >= 40:
                return True
    return False


def _count_entries(sec) -> int:
    if isinstance(sec, list):
        return len([e for e in sec if isinstance(e, dict)])
    if isinstance(sec, dict):
        return len(sec)
    return 0


@collect_errors
def check_shadow_delivery_verdict(run_root: Path) -> None:
    # 2026-10-07 合同：新开场次 close 必查分身出卷三判决（等级重判/剔除复验/查重实查）+ 曹操逐点回应。
    # 生效窗口按场次目录日期机械判断：20261007 之前命名的在飞场次不追溯；路径无日期则不拦（合同层仍管）。
    m = effective_run_date(run_root)
    if not m or m.group(0) < "20261007":
        return
    verdict = run_root / "02-cao-cao-shadow" / "delivery-verdict.json"
    if not verdict.is_file():
        fail(f"close 缺分身出卷判决 {verdict}（2026-10-07 起场次：levels/eliminations/dedup 三段）")
    try:
        data = json.loads(verdict.read_text(encoding="utf-8"))
    except Exception as exc:
        fail(f"分身出卷判决不是合法 JSON: {exc}")
    if not isinstance(data, dict) or not (
        data.get("no_findings_to_review") or all(k in data for k in ("levels", "eliminations", "dedup"))
    ):
        fail("分身出卷判决缺三段（levels/eliminations/dedup）或 no_findings_to_review")
    # 批三十六（红队二轮 P2-10）：no_findings_to_review 一键免检收紧——该键成立前提是
    # 盘面真没有 finding；reports/json 里躺着带 status 的 finding JSON 还写它 = 矛盾 fail
    if isinstance(data, dict) and data.get("no_findings_to_review"):
        _m_nf = effective_run_date(run_root)
        if _m_nf and _m_nf.group(0) >= H22_STRICT_ERA:
            _rj_nf = run_root / "reports" / "json"
            for _jf_nf in sorted(_rj_nf.glob("*.json")) if _rj_nf.is_dir() else []:
                _d_nf = load_finding_json(_jf_nf, "shadow_no_findings_cross")
                if not _d_nf:
                    continue
                for _cur in walk_dicts(_d_nf):
                    _st_nf = _finding_status(_cur)  # 批四十五 M31：三键统一
                    if _st_nf in {"verified", "suspected", "eliminated", "disproved", "below_medium"}:
                        fail(
                            f"delivery-verdict 写 no_findings_to_review 但 reports/json/{_jf_nf.name} 有 finding（status={_st_nf}）"
                            "——一键免检与盘面矛盾（批三十六），该走三段判决就走三段"
                        )
                        break
    response = run_root / "02-cao-cao" / "shadow-verdict-response.json"
    if not response.is_file():
        fail(f"close 缺曹操判决回应 {response}（逐点 accepted/rejected 带理由）")
    # 批三十五 P1-5：补文档-代码缺口——gates.md/SKILL 闸表既写「三段带独立证据指针、response 逐点带理由」，
    # 批三十四前闸只查键名。era≥20261015 场硬拦：三段各 ≥1 个可解析原件指针（≥40B 实件），
    # response 含 ≥ levels 条目数的 accepted/rejected 逐点行；存量场记注不拦（祖父条款）。
    if isinstance(data, dict) and not data.get("no_findings_to_review"):
        _m37 = effective_run_date(run_root)
        _new37 = bool(_m37 and _m37.group(0) >= LEDGER_STRICT_ERA)
        for sec in ("levels", "eliminations", "dedup"):
            body_sec = data.get(sec)
            if _count_entries(body_sec) == 0:
                continue  # 空段无条目即无指针义务（没有剔除项/没有查重路由不要求硬造指针）
            # 批三十六 P1-7：新场指针必须带摘录锚（excerpt ≥15 字逐字命中被指文件）——
            # 「指向任何 ≥40B 文件即过」的弱实现让判决可以指着不相干文件过闸
            anchored = _has_anchored_pointer(run_root, body_sec)
            if anchored:
                continue
            if _new37 and not _has_resolved_pointer(run_root, body_sec):
                fail(
                    f"分身出卷判决 {sec} 段无可解析原件指针（file/path/receipt 指向 ≥40B 实件）"
                    "——回述型假判决 fail（gates.md 既有口径，批三十五机械落地）"
                )
            elif _new37:
                fail(
                    f"分身出卷判决 {sec} 段指针无摘录锚（excerpt ≥15 字须逐字出现在被指文件里）"
                    "——防指鹿为马式指针（批三十六）；核对件必须引用被核对文件原文"
                )
            print(json.dumps({"shadow_verdict_pointer": "legacy_skip", "section": sec}, ensure_ascii=False))
        if _new37:
            n_levels = _count_entries(data.get("levels"))
            if n_levels:
                resp_text = response.read_text(encoding="utf-8", errors="ignore")
                # 批四十九拆死锁（r18 L/E 两线交叉印证）：批三十五行首锚正则与合法 JSON 互斥——
                # 严格 JSON 里 "accepted" 前有引号/键名，行首锚恒 0 命中，诚实 response 反而必 fail。
                # 现 JSON 结构优先（数 decision/status/verdict/result 键值 + 纯字符串数组元素），旧 md 行锚兜底（存量场）。
                n_resp = 0
                try:
                    resp_json = json.loads(resp_text)
                except Exception:  # noqa: BLE001
                    resp_json = None
                if isinstance(resp_json, (dict, list)):
                    def _count_resp(obj) -> int:
                        n = 0
                        if isinstance(obj, dict):
                            for k, v in obj.items():
                                if str(k).lower() in ("decision", "status", "verdict", "result", "judgment") and re.match(r"(?i)^(accepted|rejected)\b", str(v)):
                                    n += 1
                            for v in obj.values():
                                n += _count_resp(v)
                        elif isinstance(obj, list):
                            for it in obj:
                                if isinstance(it, str) and re.match(r"(?i)^(accepted|rejected)\b", it.strip()):
                                    n += 1
                                else:
                                    n += _count_resp(it)
                        return n

                    n_resp = _count_resp(resp_json)
                else:
                    n_resp = len(re.findall(r"(?im)^\s*[-*\d.）)]*\s*(accepted|rejected)\b", resp_text))
                if n_resp < n_levels:
                    fail(
                        f"shadow-verdict-response 逐点回应不足：levels {n_levels} 条 vs accepted/rejected {n_resp} 处"
                        "——每条判决须逐点回应（合法 JSON 用 decision/status 键值 accepted|rejected，或旧式行首逐点行；批四十九两态兼容）"
                    )

    # 2026-10-07 盘问修正：查重结论必须见处置。判决 dedup 路由绑定表点名的同路由公开编号，
    # 每条要么封存（reports/discarded/sealing-receipt.json 记同源编号），要么正位 DOCX 引编号声明差异；
    # 查了不下处置 = close fail。
    routes: list[dict] = []
    if isinstance(data, dict) and isinstance(data.get("dedup"), dict):
        rb = data["dedup"].get("route_binding")
        if isinstance(rb, list):
            routes = [e for e in rb if isinstance(e, dict)]
    import zipfile

    cve_pat = re.compile(r"CVE-\d{4}-\d+")
    cited: set[str] = set()
    for docx in sorted((run_root / "reports").glob("*.docx")):
        try:
            xml_text = docx_plain_text(docx)  # 批四十二：CVE 编号跨 run 拆段会漏收（fail-open）
            cited.update(cve_pat.findall(xml_text))
        except Exception:  # noqa: BLE001
            continue
    sealed: set[str] = set()
    receipt = run_root / "reports" / "discarded" / "sealing-receipt.json"
    if receipt.is_file():
        try:
            sealed.update(cve_pat.findall(receipt.read_text(encoding="utf-8", errors="ignore")))
        except Exception:  # noqa: BLE001
            pass
        # 批三十七（红队三轮 P1-7②）：封存真实性核——编一个不存在的 CVE 编号把真 0day 封存成
        # same_problem_covered = 少出卷少干活。era 新场每条 sealed_items 须带查询原件 + 老向量
        # 阴性对照回包（封存的本质=「老向量已覆盖」，没打过老向量不许封——对齐 RF-SPEC-02②）
        _m_seal = effective_run_date(run_root)
        if _m_seal and _m_seal.group(0) >= H22_STRICT_ERA:
            seal_data = load_json(receipt) or {}
            items_seal = seal_data.get("sealed_items")
            if isinstance(items_seal, list) and items_seal:
                for si_i, si in enumerate(items_seal):
                    if not isinstance(si, dict):
                        continue
                    ev_ok = _has_resolved_pointer(run_root, si.get("query_evidence") or si.get("evidence"))
                    neg_ok = _has_resolved_pointer(run_root, si.get("negative_control") or si.get("old_vector_evidence"))
                    if not ev_ok:
                        fail(f"sealing-receipt.sealed_items[{si_i}] 缺可解析查询原件（同源编号查询落盘）——封存无据（批三十七）")
                    if not neg_ok:
                        fail(
                            f"sealing-receipt.sealed_items[{si_i}] 缺老向量阴性对照回包——封存的主张是"
                            "「老向量已覆盖本路由」，没真实发过老向量不许封（RF-SPEC-02②，批三十七）"
                        )
    if not routes:
        return
    skip_words = ("无覆盖", "无公开", "no_public_coverage", "无编号", "不出卷", "参考件", "对照件", "否证")
    for e in routes:
        if str(e.get("conclusion", "")) == "no_public_coverage":
            continue
        blob = " ".join(str(v) for v in e.values())
        if any(w in blob for w in skip_words):
            continue
        # 批三十七（红队三轮 P1-7③）：dedup 查询原件特征——era 新场点名公开编号的 route 条目
        # 须带可解析 evidence 且内容含真实查询特征（http/HTTP 响应），纯本地一句 md 不算查过
        _m_dd = effective_run_date(run_root)
        if _m_dd and _m_dd.group(0) >= H22_STRICT_ERA:
            if not _has_resolved_pointer(run_root, e.get("evidence") or e.get("query_evidence")):
                fail(f"查重 route_binding（{e.get('route', '?')}）点名公开编号但无可解析查询原件——查重实查义务（批三十七）")
            else:
                for cand_v in (e.get("evidence"), e.get("query_evidence")):
                    if isinstance(cand_v, str):
                        pp = Path(cand_v)
                        if not pp.is_absolute():
                            pp = run_root / cand_v
                        if pp.is_file():
                            ev_text = pp.read_text(encoding="utf-8", errors="ignore")
                            break
                if ev_text and not re.search(r"https?://|HTTP/1\.", ev_text, re.I):
                    fail(f"查重 route_binding（{e.get('route', '?')}）查询原件缺真实查询特征（URL/HTTP 响应行）——本地自述不算查询（批三十七）")
        for cve in cve_pat.findall(blob):
            if cve not in cited and cve not in sealed:
                fail(
                    f"查重未处置：判决 route_binding 点名 {cve}（{e.get('route', '?')}）——"
                    f"同路由公开编号要么封存进 reports/discarded/sealing-receipt.json（记同源编号），"
                    f"要么正位 DOCX 引用编号声明差异；查了不执行 = close fail（2026-10-07 盘问修正）"
                )


@collect_errors
def check_reports_after_receipt(run_root: Path, notes: list[str]) -> None:
    # 2026-10-08 手续改良：收口后动正位卷必须重跑 close（guns 场 00:45 passed、02:00 仍改正位卷盘出的违规）。
    # 失败回执本身会刷新锚点（emit_failures 重写回执 = 新 mtime），修完重跑一次即过，无死锁。
    receipt = run_root / "run" / "hard-gate-close.json"
    if not receipt.is_file():
        return
    newest = 0.0
    newest_rel = ""
    for dirpath, dirnames, filenames in os.walk(run_root / "reports"):
        # 2026-10-13 四5 修：reports/json/ 的正常后补 finding JSON 不算「正位卷被修改」
        dirnames[:] = [d for d in dirnames if d not in ("revisions", "discarded", "json")]
        for name in filenames:
            p = Path(dirpath) / name
            try:
                m = p.stat().st_mtime
            except OSError:
                continue
            if m > newest:
                newest, newest_rel = m, str(p.relative_to(run_root)).replace("\\", "/")
    if newest > receipt.stat().st_mtime + 1:
        fail(
            f"正位卷在收口回执之后被修改（{newest_rel}）——改正位必须重跑 close 重新验收"
            "（修订走 reports/revisions/ 不触发本条；本次重跑通过即刷新基线）"
        )
    notes.append("reports_after_receipt_ok")


@collect_errors
def check_alarm_account(run_root: Path, notes: list[str]) -> None:
    # 2026-10-08 手续改良：开考即挂闹钟并落账 run/alarm.json（治低级模型不自觉执行条文）。
    # 生效窗口按场次目录日期机械判断：20261008 之前命名的在飞场次不追溯（同分身出卷判决条款）。
    m = effective_run_date(run_root)
    if not m or m.group(0) < "20261008":
        return
    acc = run_root / "run" / "alarm.json"
    if not acc.is_file():
        fail("2026-10-08 起场次必须有 run/alarm.json 闹钟落账（开考即挂：automation_id/title/interval/mounted_at/teardown）")
    data = load_json(acc)
    if not isinstance(data, dict) or not (data.get("automation_id") or data.get("alarm_id")):
        fail("run/alarm.json 缺 automation_id（兼容旧写 alarm_id）——五键标准见 mini SKILL 字段契约节")
    notes.append("alarm_account_ok")


def stamp_test_session(run_root: Path) -> None:
    # 2026-10-08 手续改良：close passed 后闸自动盖章回写（治「gates 空着 / closed_at 写 16:5x」的糊弄式回写）。
    import datetime

    # 2026-10-13 M3 修：盖章目标与 check 侧对齐——按「第一个能解析出内容的」选（旧版按第一个存在的文件选，
    # run/envelope.json 坏 JSON 时检查读 test-session、盖章却覆写坏 envelope 且 or {} 丢光原内容）
    path = None
    data = {}
    for cand in envelope_paths(run_root):
        if not cand.is_file():
            continue
        d = load_json(cand)
        if d:
            path, data = cand, d
            break
    if path is None:
        path = run_root / "run" / "test-session.json"
        data = load_json(path) or {}
    gates = data.get("gates") if isinstance(data.get("gates"), dict) else {}
    close_gate = gates.get("close")
    if isinstance(close_gate, dict):
        close_gate["status"] = "passed"
        close_gate["stamped_by"] = "hard_gate"
    else:
        gates["close"] = {"status": "passed", "stamped_by": "hard_gate"}
    data["gates"] = gates
    data["execution_status"] = "closed"
    data["closed_at"] = datetime.datetime.now().astimezone().isoformat(timespec="seconds")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def write_closure_ledger(run_root: Path) -> None:
    # 2026-10-09 坏账洞①修复（收口即并账）：close passed 当刻把本场战果自动记进数据根 closure-ledger.jsonl，
    # 总览 DOCX 并账以台账为准，不再靠人脑记「哪场收口了没收进账」。只追加不回改；失败不拦 close（无死锁）。
    import datetime

    try:
        # 数据根台账 = 向上最近的 library 目录（不再 parents[4] 硬编码，旧 runs/<run_id> 布局也写对层）
        lib = next((p for p in [run_root, *run_root.parents] if p.name == "library"), None)
        if lib is None:
            return
        ledger = lib / "closure-ledger.jsonl"
        findings = []
        rep = run_root / "reports"
        if rep.is_dir():
            for f in sorted(rep.glob("*.docx")):
                name = f.name
                if "test-summary" in name.lower():
                    continue
                findings.append(name[:-5])
        sealed = 0
        receipt = run_root / "reports" / "discarded" / "sealing-receipt.json"
        if receipt.is_file():
            try:
                sealed = len(json.loads(receipt.read_text(encoding="utf-8")).get("sealed_items") or [])
            except Exception:
                sealed = 0
        runner_model = None
        for cand in envelope_paths(run_root):
            if not cand.is_file():
                continue
            d = load_json(cand)  # 修复批十九：同 stamp M3，坏档跳过找下一个能解析的
            if d:
                runner_model = d.get("runner_model")
                break
        entry = {
            "kind": "closure_ledger",
            "run_root": str(run_root),
            "closed_at": datetime.datetime.now().astimezone().isoformat(timespec="seconds"),
            "findings": findings,
            "sealed_count": sealed,
            "runner_model": runner_model,
            # 批四十九（r18 遗留7）：无图豁免入账留痕——下场同目标收口/用户翻台账可见「欠补拍」笔数；
            # 补拍 -rev 卷出齐后本场再收口该数自然归零
            "pending_screenshot_waivers": 1 if (run_root / "run" / "no-screenshot-waiver.json").is_file() else 0,
        }
        # 批四十（红队六轮 P0-3）：素材摘要入账——图哈希+请求行 path 指纹，下场次
        # check_cross_session_reuse 据此比对同目标旧场（整场复读在收口时被拦）
        try:
            import hashlib as _hl45
            _imgs: list[str] = []
            cap_dir = run_root / "run" / "captures"
            if cap_dir.is_dir():
                for p in sorted(cap_dir.rglob("*")):
                    if p.is_file() and p.suffix.lower() in IMAGE_EXT:
                        _imgs.append(_hl45.sha256(p.read_bytes()).hexdigest())
                        if len(_imgs) >= 60:
                            break
            _paths: list[str] = []
            for f in sorted((run_root / "reports").glob("*.docx")):
                if is_summary_docx(f.name):
                    continue
                try:
                    _t = docx_plain_text(f)  # 批四十二：请求行跨 run 拆段漏提取（素材摘要失真）
                except Exception:  # noqa: BLE001
                    continue
                for mu in re.finditer(r"(?m)(?:GET|POST|PUT|DELETE|PATCH)\s+(/\S+?)(?:\s|$)", _t):  # 批四十二：plain text 后行尾可命中
                    _q = mu.group(1).split("?")[0][:80]
                    if _q not in _paths:
                        _paths.append(_q)
                if len(_paths) >= 60:
                    break
            env_d = load_json(next((c for c in envelope_paths(run_root) if c.is_file()), run_root / "envelope.json")) or {}
            entry["target_identity"] = str(env_d.get("target_identity") or "")
            entry["material_digest"] = {"img_shas": _imgs, "req_paths": _paths}
        except Exception:
            pass
        with ledger.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except Exception:
        return


@collect_errors
def check_recording_integrity(run_root: Path, notes: list) -> None:
    """2026-10-15 批十（guns JWT 判例，用户令「任何东西都不允许伪造」）：交付前录屏完整性硬闸。
    ① ffprobe 实测时长 ↔ recording-index 宣称时长对账（碎片冒全长=fail）；
    ② run/recording-index.json 里 full_span=true 的视频抽帧存在性由关键帧确认件的 @mm:ss 与实测时长交叉
       （确认件宣称时点超出实测时长=确认件是敷衍件，fail）。
    2026-10-15 批二十五补两判据：③ RF-VID-03 的 13 分钟硬上限机械拦（实测>780s=fail，此前条文有闸无）；
    ④ full_span 项缺 duration_sec/claimed_duration_sec 记 note（老账不追溯，模板已补键——缺键时对账静默
    跳过是批十遗留 fail-open，note 让它可见）。"""
    rec_dir = run_root / "run" / "recordings"
    if not rec_dir.is_dir():
        notes.append("recording_integrity(no recordings dir)")
        return
    idx_p = run_root / "run" / "recording-index.json"
    idx = load_json(idx_p) if idx_p.is_file() else None
    items = (idx or {}).get("items") if isinstance((idx or {}).get("items"), list) else []

    def ffprobe_dur(f: Path):
        import subprocess as _sp
        try:
            r = _sp.run(
                ["ffprobe", "-v", "error", "-show_entries", "format=duration",
                 "-of", "csv=p=0", str(f)],
                capture_output=True, text=True, timeout=30,
            )
            return float(r.stdout.strip())
        except Exception:
            return None

    checked = 0
    problems: list[str] = []
    for item in items:
        if not isinstance(item, dict) or item.get("full_span") is not True:
            continue
        rel = str(item.get("video") or "").strip()
        if not rel:
            continue
        claimed = item.get("duration_sec") or item.get("claimed_duration_sec")
        f = None
        try:
            f = resolve_inside(run_root, rel, "video")
        except Exception:
            problems.append(f"video 路径越界: {rel}")
            continue
        if not f.is_file():
            continue  # 文件缺失归 check_complex_video 管
        checked += 1
        # 批六十一⑫（r38 G-05，RF-VID-05 每步截图对账）：required_shots 清单逐项核存在
        # ——录屏计划写了登录/每关键步截图而盘上没有=卷不完整；不写本键记 note（老账兼容）
        _req61 = item.get("required_shots")
        if isinstance(_req61, list) and _req61:
            for _rs61 in _req61:
                _rsp61 = str(_rs61 or "").strip()
                if not _rsp61:
                    continue
                _hit61 = any((run_root / sub / _rsp61).is_file() for sub in ("run/captures", "captures", "run"))
                if not _hit61 and not (run_root / _rsp61).is_file():
                    problems.append(f"{rel}: required_shots 缺件 {_rsp61}（RF-VID-05 每步截图——写了没拍）")
        elif _req61 is None:
            notes.append(f"recording_required_shots_absent({rel}——计划未列每步截图清单，链审复核)")
        dur = ffprobe_dur(f)
        if dur is None:
            notes.append(f"recording_integrity(ffprobe 不可用，跳过 {f.name})")
            continue
        # 批二十五③：RF-VID-03 13 分钟硬上限（780s）机械拦——超时=流程编排问题，条文此前无闸
        if dur > 780.0:
            problems.append(
                f"{f.name}: 实测 {dur:.1f}s 超 RF-VID-03 的 13 分钟硬上限（780s）——精简重录，禁拆多段绕时长")
        if claimed:
            try:
                c = float(claimed)
                if abs(dur - c) > 2.0:
                    problems.append(
                        f"{f.name}: 实测 {dur:.1f}s vs 宣称 {c:.1f}s（偏差>2s——碎片冒全长或旧账未更新）")
            except (TypeError, ValueError):
                problems.append(f"{f.name}: recording-index duration_sec 不是数字: {claimed!r}")
        else:
            # 批二十五④原为 note；批三十六（红队二轮 P0-2）：era≥20261015 缺 duration_sec 改 fail——
            # 缺键=对账静默跳过=碎片冒全长无人查
            _m_du = effective_run_date(run_root)
            if _m_du and _m_du.group(0) >= H22_STRICT_ERA:
                problems.append(f"{f.name}: full_span 项缺 duration_sec/claimed_duration_sec（批三十六硬拦：无宣称时长=时长对账被跳过）")
            else:
                notes.append(f"recording_integrity(no duration_sec for {f.name}——模板已补键，新账必填；对账未执行)")
        # ③ 时点解说交叉：卷内正文引用的 @mm:ss 不得超过实测时长
        # 批六十一⑤（r38 B-8）：旧配对 `stem.split("-")[0] in name` 过宽——视频名 rec-xxx 的
        # 前缀 "rec" 命中一切含 rec 确认件（帧名 rec-ch01-frame1 也中），别人的时点拿来对账=
        # 假阳性/假阴性双向。收紧：确认件 stem 须含视频 stem 本身、或视频完整 stem 含确认件
        # 帧语义段（ch01 类长 token ≥4 重合），短前缀（<4 字符）不再单独算配对。
        vr_dir = run_root / "run" / "vision-reviews"
        if vr_dir.is_dir():
            _toks_v = {t for t in re.split(r"[-_.\s]+", f.stem.lower()) if len(t) >= 4}
            for rv in vr_dir.glob("*.review.md"):
                name = rv.stem.lower()
                _toks_r = {t for t in re.split(r"[-_.\s]+", name) if len(t) >= 4}
                if f.stem.lower() not in name and name not in f.stem.lower() and not (_toks_v & _toks_r):
                    continue
                try:
                    head = rv.read_text(encoding="utf-8", errors="replace")[:2000]
                except OSError:
                    continue
                for mts in re.findall(r"@(\d{1,2}):(\d{2})", head):
                    sec = int(mts[0]) * 60 + int(mts[1])
                    if sec > dur + 2:
                        problems.append(
                            f"确认件 {rv.name} 宣称 @{mts[0]}:{mts[1]} 超出 {f.name} 实测时长 {dur:.0f}s——确认件对应的不是这个视频")
                        break
    if problems:
        fail(
            "批十：录屏完整性不过——实测时长与宣称对不上或确认件时点越界（2026-10-15 guns JWT 判例："
            "13.9s 碎片冒 2:20 交付；确认件时点必须落在视频真实时长内）",
            {"problems": problems[:12]},
        )
    notes.append(f"recording_integrity_ok({checked} videos ffprobe-checked)")


def check_verified_disposition(run_root: Path, notes: list[str]) -> None:
    # 2026-10-09 坏账洞②修复（verified 必须有终态处置）：每条 verified 链 close 前必须能对上四路证明之一——
    # ① 正位/修订卷引用（reports/json 或 docx 内含该 chain_id）② 封存回执（sealing-receipt）
    # ③ 分身判决留档（delivery-verdict：below_medium/sealed/retained 行点名该 id）
    # ④ 交付清单（02-cao-cao-shadow/final-delivery-manifest 点名该 id）。
    # 治「验证完晾着没人管」型坏账（实战判例：低权读 PII / 越权链验证后未处置）。生效线 20261010（同 runner_model，旧场不追溯）。
    m = effective_run_date(run_root)
    if not m or m.group(0) < "20261010":
        return
    vids: list[tuple[str, str]] = []
    for p in iter_json_files(run_root):
        data = load_json_tree(p, "check_verified_disposition")
        if not data:
            continue
        for cur in walk_dicts(data):
            # 2026-10-13 C8 修：终态键兼容 finding_status/final_status（对齐 check_verified_evidence——
            # 旧版只认 status，用 finding_status 签的链过证据检查却逃终态处置）
            # 批四十五 M31：换 _finding_status 三键统一 helper
            if _finding_status(cur) != "verified":
                continue
            vid = str(cur.get("chain_id") or cur.get("chain") or cur.get("id") or "")
            if vid:
                vids.append((vid, str(p.relative_to(run_root)).replace("\\", "/")))
    if not vids:
        return
    import zipfile
    proof = ""
    receipt = run_root / "reports" / "discarded" / "sealing-receipt.json"
    if receipt.is_file():
        proof += receipt.read_text(encoding="utf-8", errors="ignore")
    verdict = run_root / "02-cao-cao-shadow" / "delivery-verdict.json"
    if verdict.is_file():
        proof += verdict.read_text(encoding="utf-8", errors="ignore")
    manifest = run_root / "02-cao-cao-shadow" / "final-delivery-manifest.json"
    if manifest.is_file():
        proof += manifest.read_text(encoding="utf-8", errors="ignore")
    rep = run_root / "reports"
    if rep.is_dir():
        for f in list(rep.glob("*.docx")) + list(rep.glob("json/*.json")) + list(rep.glob("revisions/*.docx")):
            try:
                if f.suffix.lower() == ".docx":
                    proof += docx_plain_text(f)  # 批四十二：原文 XML 文本跨 run 拆段漏匹配
                else:
                    proof += f.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue
    orphans = [f"{vid}（{src}）" for vid, src in vids
               if not re.search(r"(?<![\w-])" + re.escape(str(vid)) + r"(?![\w-])", proof)]
    if orphans:
        fail(
            "verified 链无终态处置（2026-10-09 坏账洞②修复）："
            + "；".join(orphans[:4])
            + " ——四选一：出正位/修订卷、封存进 reports/discarded/sealing-receipt、"
            "delivery-verdict 记 below_medium/sealed/retained 行点名该 id、或 final-delivery-manifest 点名。"
            "验证完晾着不处置 = close fail"
        )
    notes.append("verified_disposition_ok")


def _gate_sha256() -> str:
    import hashlib as _hl

    return _hl.sha256(Path(__file__).resolve().read_bytes()).hexdigest()


def _scene_digest(run_root: Path) -> str:
    """2026-10-15 批三十四（draft batch30 §2 合入，H-23 机械件）：场景指纹。
    批四十五（B-2/B-4）v4 全量口径：run_root 下全部文件全量 sha256——旧口径只锚
    reports/**+12 个点名件，09-si-ma-yi/js-collection、hybrid-discovery.jsonl、角色
    not-needed/capability、03/04/05/06/08 作业件、run/vision-reviews、run/h24-replay、
    run/alarm.json、run/process-provenance、material-manifest-src、信封本体收口后改动
    全部不炸 verify-close；且 ≥1MB 大件 size+mtime_ns 可被「同长改写+utime 回填」骗过。
    v4 语义：排除集（close/verify-close 自身会写的回执与闸产物，最小集）之外任何文件
    新增/改动/删除都必须炸 verify-close；>256MB 超大件保留弱档但指纹值带 weak: 前缀
    （回执可见弱指纹面）；信封按「剥 stamp 三键（gates/execution_status/closed_at）
    规范化」哈希——close passed 后 stamp 合法盖章不扰动指纹，收口后改信封其它内容照炸。"""
    import hashlib as _hl

    _env_rels = {cand.relative_to(run_root).as_posix() for cand in envelope_paths(run_root)}

    def _envelope_norm_hash(p: Path) -> str:
        try:
            data = json.loads(p.read_text(encoding="utf-8-sig"))
        except Exception:
            return "raw:" + _hl.sha256(p.read_bytes()).hexdigest()[:16]
        if not isinstance(data, dict):
            return "raw:" + _hl.sha256(p.read_bytes()).hexdigest()[:16]
        for k in ("gates", "execution_status", "closed_at"):
            data.pop(k, None)
        return "env:" + _hl.sha256(json.dumps(data, ensure_ascii=False, sort_keys=True).encode("utf-8")).hexdigest()[:16]

    items: list[str] = []
    for dirpath, _dirnames, filenames in os.walk(run_root):
        for name in filenames:
            p = Path(dirpath) / name
            rel = p.relative_to(run_root).as_posix()
            # 排除集（最小）：close 回执自身（防自引用）+ close 每跑必重写的闸产物
            # （credential-scan 子进程输出、CVE 重放落件 replayed_at、官方源探针落件
            # downloaded_at——内容含时间性字段，重跑必变，不能当用户改动锚）
            if rel in ("run/hard-gate-close.json", "run/credential-scan.json"):
                continue
            if rel.startswith("run/cve-replay/") or rel.startswith("run/official-probe/"):
                continue
            try:
                st = p.stat()
            except OSError:
                items.append(rel + ":gone")
                continue
            if rel in _env_rels:
                items.append(rel + ":" + _envelope_norm_hash(p))
                continue
            if st.st_size > 256_000_000:
                # 批四十五 B-4：>256MB 超大件保留弱档，指纹值带 weak: 前缀（回执可见）
                items.append(rel + ":weak:" + str(st.st_size) + ":" + str(st.st_mtime_ns))
            else:
                items.append(rel + ":c" + _hl.sha256(p.read_bytes()).hexdigest()[:16])
    items.sort()
    h = _hl.sha256()
    for it in items:
        h.update((it + "\n").encode("utf-8"))
    return h.hexdigest()


CHECKER_BASELINE_FILES = (
    "hard_gate.py",
    "dispatch_check_lite.py",
    "vision_gate.py",
    "vision_review.py",
    "check_finding.py",
    # 批三十七（红队三轮 P0-4）：账本产出工具入基线——改 hard_gate 会被 H-25 抓，
    # 改 walker/hybrid/解包/哈希工具生产「合法形态」的假账没人管；生产者与检查者同锚
    "auto_chain_scan.py",
    "hybrid_discovery.py",
    "js_unpack.py",
    "material_hash.py",
    # 批三十九：canonical 生成器自身入基线——否则改它生成与假闸自洽的 canonical 无闸拦
    "make_canonical.py",
    # 批六十一①（用户问「角色会不会改公用工具」盘出）：vis-tools 截图/录屏族零监控——
    # 改 snapchrome/cmdsend 在截屏落盘前偷换画面内容（如替换手机号），tool_baseline 不响
    # （12 键全是 scripts/*.py）。证据链最上游的拍摄工具与检查者同锚。
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


def _tool_baseline_now() -> dict:
    import hashlib as _hl

    base = Path(__file__).resolve().parent
    out: dict = {}
    for name in CHECKER_BASELINE_FILES:
        p = base / name
        if p.is_file():
            out[name] = _hl.sha256(p.read_bytes()).hexdigest()
    # 批三十六（用户红队二轮 P0-4）：扫描工具身份入基线——防被换成永远输出 clean 的假件，
    # 闸必须锚定被调脚本本体哈希
    tj = base.parent / "tools.json"
    if tj.is_file():
        out["tools.json"] = _hl.sha256(tj.read_bytes()).hexdigest()
    pkgcred = _pkg_script("credential_scan.py")
    if pkgcred.is_file():
        out["credential_scan.py"] = _hl.sha256(pkgcred.read_bytes()).hexdigest()
    return out


@collect_errors
def check_tool_baseline(run_root: Path, notes: list[str]) -> None:
    # 2026-10-15 批三十四（draft batch30 §5 合入，H-25 机械件）：开局锚检查器哈希、
    # 收口比对；漂移必须逐条对应信封 gate_change_refs（draft/ + CHANGELOG 条目），
    # 缺 = 按 H-21 伪造论处。批三十六（红队二轮 P0-2/P0-4）：era≥20261015 基线缺失改 fail
    # （「存量兼容」不适用于新场——缺键不该是第二把钥匙）；基线必须含外挂工具身份两键。
    data = None
    for cand in envelope_paths(run_root):
        data = load_json(cand) if cand.is_file() else None
        if data:
            break
    m = effective_run_date(run_root)
    new_era = bool(m and m.group(0) >= H22_STRICT_ERA)
    baseline = (data or {}).get("tool_baseline")
    # 批六十二①消费端（摸鱼洞「收口前重锚」，era≥20261017）：信封 tool_baseline 的现哈希
    # 必须与 env 回执锚一致——env 过后整体改写信封锚使其与收口实况自洽（close 两头比对
    # 全可控）在此炸。放最前：必锚键检查先 fail 会抛 GateFailure 终止函数，锚核对段必须
    # 在任何 fail 之前跑（t2 沙箱实测漏拦教训）
    if isinstance(baseline, dict) and baseline:
        _m62b = effective_run_date(run_root)
        if _m62b and _m62b.group(0) >= "20261017":
            _envrc62 = load_json(run_root / "run" / "hard-gate-env.json") or {}
            _anchored62 = str(_envrc62.get("envelope_tool_baseline_sha256") or "")
            if _anchored62:
                import hashlib as _hl62b

                _now62 = _hl62b.sha256(
                    json.dumps(baseline, sort_keys=True, ensure_ascii=False).encode("utf-8")
                ).hexdigest()
                if _now62 != _anchored62:
                    fail(
                        "H-25 锚时刻对账不符（批六十二①）：信封 tool_baseline 与 env 回执锚的不一致——"
                        "开局基线被中段改写（重锚洗白）；合法改闸须 gate_change_refs 登记并在 draft/ 有对应，"
                        "凭登记重跑 env 重锚"
                    )
            else:
                notes.append("tool_baseline_env_anchor_absent(env 回执无 envelope_tool_baseline_sha256——批六十二前老回执，重跑 env 即补锚)")
    if not isinstance(baseline, dict) or not baseline:
        if new_era:
            # 批四十五 B-21：键数按 _tool_baseline_now() 实算动态生成——写死数字随包演进漂移
            fail(f"H-25：era≥20261015 场信封必落 tool_baseline（十件检查/产出工具+tools.json+credential_scan 共 {len(_tool_baseline_now())} 键 sha256，以 _tool_baseline_now() 实际键为准）——缺基线=改闸自判零成本，close 不放行")
        notes.append("tool_baseline_missing(H-25：开局未锚检查器哈希——存量场放行，新场必落)")
        return
    current = _tool_baseline_now()
    if new_era:
        _required37 = [
            "tools.json",
            "credential_scan.py",
            "auto_chain_scan.py",
            "hybrid_discovery.py",
            "js_unpack.py",
            "material_hash.py",
        ]
        missing_keys = [k for k in _required37 if k not in baseline]
        if missing_keys:
            fail(f"H-25：tool_baseline 缺必锚键（{', '.join(missing_keys)}）——外挂工具+账本产出工具身份防伪（批三十四/三十七），开局重算信封基线")
    if m and m.group(0) < H22_STRICT_ERA:
        # 存量场：只比 baseline 里已有的键（新键不追溯，防升级即误伤在飞场）
        drift = sorted(k for k in baseline if baseline.get(k) != current.get(k))
    else:
        drift = sorted(k for k in set(baseline) | set(current) if baseline.get(k) != current.get(k))
        if not _b39_era(run_root):
            # 批三十九新键不追溯 20261015~16 在飞场（同祖父条款；B39 场起必锚）
            drift = [k for k in drift if k != "make_canonical.py"]
    if not drift:
        notes.append("tool_baseline_ok")
        return
    refs = (data or {}).get("gate_change_refs")
    if not isinstance(refs, list) or not refs:
        fail(
            "H-25：检查器哈希开局↔收口漂移（"
            + ", ".join(drift)
            + "）且信封无 gate_change_refs 对应 draft/ 与 CHANGELOG 条目——按 H-21 伪造论处，本场收口作废待用户裁决"
        )
        return
    # 批四十五 B-7：refs 每条须在包 CHANGELOG.md 命中——旧版任意非空列表即免除漂移，
    # 随手写 ["x"] 的豁免口子收死（≥4 字防单字符子串误命中）
    _cl_p = Path(__file__).resolve().parent.parent / "CHANGELOG.md"
    _cl_text = _cl_p.read_text(encoding="utf-8-sig", errors="ignore") if _cl_p.is_file() else ""
    _bad_refs = [r for r in refs if not (isinstance(r, str) and len(r.strip()) >= 4 and r.strip() in _cl_text)]
    if _bad_refs:
        fail(
            "H-25：gate_change_refs 条目未在包 CHANGELOG.md 命中（"
            + ", ".join(str(r)[:40] for r in _bad_refs[:4])
            + "）——漂移豁免必须逐条对应真实 changelog 条目（批四十五 B-7）；随手写非空 refs 不构成豁免"
        )
        return
    notes.append(f"tool_baseline_drift_with_refs({len(drift)})")


H22_STRICT_ERA = "20261015"
# 批三十九（红队五轮）：新拦只对 era≥20261016 生效，存量场放行记注（祖父条款同批三十四口径）
B39_STRICT_ERA = "20261016"


def _b39_era(run_root: Path) -> bool:
    m = effective_run_date(run_root)
    return bool(m and m.group(0) >= B39_STRICT_ERA)


@collect_errors
def check_finding_source_refs(run_root: Path, notes: list[str]) -> None:
    # 2026-10-15 批三十四（H-22 机械件）：白盒 finding 的源码出处 sha256 必须与开局
    # 逐文件清单（run/material-manifest.json = material_hash.py 目录形态输出）一致——
    # 防「往项目里塞洞再挖出来」。出处不在清单=引用场外/伪造出处；哈希不符=材料被中途改动，该链作废。
    # 批三十五补口（用户红队二轮 P0-B）：批三十四版两处 fail-open——source_refs 不写即不查、
    # manifest 不落只记 note，机械件成「自愿参加制」。era≥20261015 场收紧：白盒 verified 必带
    # source_refs、源码场必落 manifest；另加清单本体防换（env 回执锚开局哈希，close 比对——
    # 收口前重写一份与毒化材料自洽的清单在此被拦）。存量场维持原放行口径（era 线判）。
    import hashlib as _hl

    era = effective_run_date(run_root)
    new_era = bool(era and era.group(0) >= H22_STRICT_ERA)
    website = is_website(envelope(run_root))
    mpath = run_root / "run" / "material-manifest.json"
    manifest = load_json(mpath)
    if not manifest or not isinstance(manifest.get("files"), list):
        if new_era and not website:
            fail(
                "H-22：era≥20261015 的源码场开局必须落 run/material-manifest.json 逐文件清单"
                "（material_hash.py 目录形态输出）——清单缺失=注毒检测整体旁路，close 不放行"
                "（存量场放行记注）"
            )
        notes.append("material_manifest_missing(H-22：开局未落逐文件清单——存量场放行，新场按 H-22 必落)")
        return
    m_sha = _hl.sha256(mpath.read_bytes()).hexdigest()
    env_receipt = load_json(run_root / "run" / "hard-gate-env.json") or {}
    anchored = str(env_receipt.get("material_manifest_sha256") or "")
    if anchored and anchored != m_sha:
        fail(
            "H-22：run/material-manifest.json 与 env 回执锚定哈希不一致——清单在 env 阶段后被重写"
            "（换自洽清单=按 H-21 伪造论处）；材料确有合法变更须重跑 env 刷新锚"
        )
    root = str(manifest.get("path") or "").replace("\\", "/").rstrip("/").lower()
    idx = {}
    for f in manifest["files"]:
        if isinstance(f, dict) and f.get("path"):
            idx[str(f["path"]).replace("\\", "/").lstrip("/").lower()] = str(f.get("sha256") or "").lower()
    checked = 0
    jdir = run_root / "reports" / "json"
    for jf in sorted(jdir.glob("*.json")) if jdir.is_dir() else []:
        data = load_json(jf)
        if not data:
            continue
        refs = data.get("source_refs")
        if not isinstance(refs, list) or not refs:
            # 批三十五：白盒 verified 缺省 source_refs = 旁路注毒检测，新场必拦（blackbox/网站场豁免——H-22 只管源码出处）
            st = _finding_status(data)  # 批四十五 M31：三键统一
            if new_era and not website and st == "verified":
                fail(f"{jf.name} 白盒 verified 缺 source_refs——H-22 必填（模板 finding.json：file+sha256 逐出处），缺省即旁路")
            continue
        for i, ref in enumerate(refs):
            if not isinstance(ref, dict):
                continue
            fp = str(ref.get("file") or "").replace("\\", "/").strip().lstrip("/").lower()
            want = str(ref.get("sha256") or "").strip().lower()
            if not fp or not want:
                fail(f"{jf.name}.source_refs[{i}] 缺 file/sha256（H-22：出处哈希脚本算，禁手抄）")
                continue
            rel = fp
            if root and rel.startswith(root + "/"):
                rel = rel[len(root) + 1:]
            base_hash = idx.get(rel)
            if base_hash is None:
                fail(f"{jf.name}.source_refs[{i}] 出处 {fp} 不在开局材料清单——引用场外/伪造出处（H-22）")
                continue
            if want != base_hash:
                fail(f"{jf.name}.source_refs[{i}] {fp} 哈希与开局清单不一致——材料被中途改动（H-22：该链作废重查）")
                continue
            checked += 1
    if checked:
        notes.append(f"source_refs_ok({checked})")
    if anchored:
        notes.append("material_manifest_anchored(env)")
    # 批三十六（红队二轮 P1-9）：开局即毒盲区可见化——manifest 锚的是「算哈希那一刻」的材料，
    # 开局前已注毒则 H-22 全盲。有官方源的项目登记 official_source_url 供曹操抽 diff；
    # 无官方源在收口件记 waiver。注记不拦（diff 抽验是人工层）。
    if new_era and not website and not str(envelope(run_root).get("official_source_url") or "").strip():
        notes.append("official_source_url_missing(H-22 开局即毒盲区：有官方源登记进信封供抽 diff，无官方源记 waiver)")


def verify_close_receipt(run_root: Path, old: dict | None) -> None:
    # 2026-10-15 批三十四（draft batch30 §2 合入，H-23/H-25 机械件）：重验收口——
    # 比对既有回执防伪指纹与当前闸/场景（全量 close 重跑已由调用方先行完成且 passed）。
    # 缺字段=手写回执；闸哈希不符=收口后改闸（H-25）；场景指纹不符=收口后改动（含改 mtime）。
    if not old:
        fail("verify-close：无可验的既有回执——先正常 close 一次再 --verify-close")
        return
    if str(old.get("status")) != "passed":
        fail("verify-close：既有回执 status 非 passed，无可重验的收口")
        return
    if "scene_digest" in old and int(old.get("scene_digest_version") or 0) < 4:
        # 批四十五：指纹口径升 v4（全量文件哈希）——旧口径回执重验必失配，按「闸升级需重跑」处理
        # 而非误判伪造；重跑 close 刷新基线后再 verify-close
        fail("verify-close：回执为旧指纹口径（scene_digest_version<4）——闸已升级全量扩覆盖，重跑一次 close 刷新基线后再重验")
        return
    for k in ("gate_sha256", "scene_digest", "tool_baseline_at_close"):
        if k not in old:
            fail(f"verify-close：回执缺防伪字段 {k}——手写回执按 H-23 伪造论处")
    if old.get("gate_sha256") != _gate_sha256():
        fail(
            "verify-close：闸自身哈希与收口时不一致（闸在收口后被改）——按 H-25 须逐条对应 "
            "draft/ 与 CHANGELOG 条目，否则本场收口作废待用户裁决"
        )
        return
    if old.get("scene_digest") != _scene_digest(run_root):
        fail("verify-close：场景指纹与收口时不一致（正位卷/收口原件在收口后被改动，改 mtime 也拦）——H-23")
        return
    if old.get("tool_baseline_at_close") != _tool_baseline_now():
        fail("verify-close：检查器哈希与收口时不一致（H-25）——须对应 draft/ 与 CHANGELOG 条目")
        return
    print(json.dumps({"verify_close": "pass", "note": "回执指纹与场景均一致，close 检查器已全量重跑通过"}, ensure_ascii=False))


@collect_errors
def check_ledger_tool_trace(run_root: Path, notes: list[str]) -> None:
    # 2026-10-15 批三十四（draft batch30 §3 合入，深挖条款 25 机械锚点）：五套硬账工具
    # 运行痕迹——有 tool_trace 做数值合理性校验（扫描计数非负整数），缺 = 记 note 供
    # 曹操按深挖 25 抽验（软锚不硬拦：存量手写账兼容，硬拦升级由曹操合入窗口定夺）。
    # hybrid-discovery 为 JSONL 逐行形态，单独记 note 指向 batch31 规格。
    targets = (
        ("keyword-scan", "01-guo-jia/keyword-scan.json"),
        ("auto-chain-scan", "01-guo-jia/auto-chain-scan.json"),
        ("sink-runtime-modules", "01-guo-jia/sink-runtime-modules.json"),
        ("component-cve-ledger", "01-guo-jia/component-cve-ledger.json"),
    )
    notes.append("hybrid_discovery_trace(jsonl 形态，见 draft/hardgate-batch31 §P1-3)")
    # 批三十六（红队二轮 P0-2）：era≥20261015 缺 tool_trace 从 note 升 fail——缺键不是中性态，
    # 手写垃圾账与工具账不可区分的局面不该在新场延续（深挖 25 抽验仍并行）
    _m_lt = effective_run_date(run_root)
    _strict_trace = bool(_m_lt and _m_lt.group(0) >= H22_STRICT_ERA)
    for name, rel in targets:
        data = load_json(run_root / rel)
        if not data:
            continue
        tr = data.get("tool_trace")
        if not isinstance(tr, dict):
            if _strict_trace:
                fail(f"{rel} 缺 tool_trace（tool+扫描计数+耗时）——era≥20261015 硬拦（批三十六）：手写账须留下真实运行痕迹")
            notes.append(f"ledger_without_tool_trace:{name}(深挖25曹操抽验)")
            continue
        cnt = tr.get("scanned_files", tr.get("file_count", 0))
        try:
            cnt_i = int(cnt)
        except Exception:
            cnt_i = -1
        if cnt_i < 0:
            fail(f"{rel}.tool_trace.scanned_files 非法（须为非负整数扫描计数）")
        else:
            notes.append(f"ledger_tool_trace_ok:{name}({cnt_i})")


SEV_RANK = {
    "below_medium": 1,
    "低危": 1,
    "low": 1,
    "中危": 2,
    "medium": 2,
    "高危": 3,
    "high": 3,
    "严重": 4,
    "critical": 4,
}
# H-26 下限判定词（正文单一出处=SKILL H-26；此处只做词匹配。「上传」归中危下限——可执行落地类
# finding 类型名通常含 rce/命令执行，天然走高危线）。批三十七（红队三轮 P1-6）：补信息泄露/
# 认证绕过/未授权——原词表漏这些类型=降 below_medium 逃必录与最大攻击效果画面零阻力
SEV_FLOOR_HIGH = ("rce", "命令执行", "命令注入", "command", "deserialize", "反序列化", "任意文件写")
SEV_FLOOR_MED = (
    "sql", "sqli", "注入", "盲注", "idor", "越权", "broken access", "ssrf", "xss", "上传",
    "info_leak", "泄露", "泄漏", "auth_bypass", "认证绕过", "鉴权绕过", "未授权", "unauthorized",
)
# 批三十七 P1-6：受控类型枚举（可选字段 evidence_loop_class，与闭环表对齐）——自由文本
# finding_type 写「逻辑缺陷/数据外泄」即逃类型配套与下限；枚举写了按它判，缺省走关键词（兼容）
EVIDENCE_LOOP_ENUM = {
    "auth_register": 2, "rce": 3, "command_injection": 3, "ssti": 3, "deserialization_rce": 3,
    "sqli": 2, "file_read": 2, "file_write": 3, "upload_exec": 3, "upload": 2,
    "xss_reflected": 2, "xss_stored": 2, "idor": 2, "ssrf": 2, "auth_bypass": 2,
    "info_leak": 2, "business_logic": 2, "deserialization": 2,
}


@collect_errors
def check_severity_floor(run_root: Path, notes: list[str]) -> None:
    """批三十五 P1-6（H-26 机械件）：类型→级别下限——防自降级别逃高危必录/最大攻击效果画面。

    降级永远允许，但必须双留痕：finding 的 downgrade_reason ≥20 字 + 同文出现在 delivery-verdict
    （H-26 正文口径）。era≥20261015 场生效，存量场不追溯（祖父条款）。"""
    m = effective_run_date(run_root)
    if not m or m.group(0) < LEDGER_STRICT_ERA:
        return
    verdict_text = ""
    vp = run_root / "02-cao-cao-shadow" / "delivery-verdict.json"
    if vp.is_file():
        verdict_text = vp.read_text(encoding="utf-8", errors="ignore")
    problems: list[str] = []
    rj = run_root / "reports" / "json"
    for jf in sorted(rj.glob("*.json")) if rj.is_dir() else []:
        data = load_finding_json(jf, "check_severity_floor")  # 批四十五 B-1：数组根/malformed 明确 fail
        if not data:
            continue
        st = _finding_status(data)  # 批四十五 M31：三键统一
        if st != "verified":
            continue
        ftype = finding_type(data)
        # 批三十七 P1-6：受控枚举优先——写了 evidence_loop_class 按它定下限，自由文本关键词退居辅助
        loop_cls = str(data.get("evidence_loop_class") or "").strip().lower()
        if loop_cls:
            if loop_cls not in EVIDENCE_LOOP_ENUM:
                problems.append(f"{jf.name}：evidence_loop_class『{loop_cls}』不在受控枚举（认 templates/finding.json）")
                continue
            floor = EVIDENCE_LOOP_ENUM[loop_cls]
        else:
            floor = 3 if any(k in ftype for k in SEV_FLOOR_HIGH) else (2 if any(k in ftype for k in SEV_FLOOR_MED) else 0)
        sev_raw = str(data.get("severity") or data.get("level") or "").strip()
        rank = SEV_RANK.get(sev_raw.lower())
        if rank is None:
            # 批三十六（红队二轮 P0-2）：verified 不写 severity 键 = 级别下限整体绕过，新场必拦
            _m_sf = effective_run_date(run_root)
            if _m_sf and _m_sf.group(0) >= H22_STRICT_ERA:
                problems.append(f"{jf.name}：verified 缺 severity 键——H-26 级别下限无法判定（缺键不是降级豁免）")
            continue
        if not floor or rank >= floor:
            continue
        dr = str(data.get("downgrade_reason") or "").strip()
        if len(dr) < 20:
            problems.append(
                f"{jf.name}：{ftype or '未知类型'} 判『{sev_raw}』低于 H-26 下限且 downgrade_reason 缺或 <20 字"
                "（谁拍板、依据什么）"
            )
        elif dr not in verdict_text:
            problems.append(f"{jf.name}：downgrade_reason 未同步进 delivery-verdict levels 段（H-26 双留痕）")
    if problems:
        fail("H-26 类型级别下限未过（批三十五机械件）：" + "；".join(problems[:6]))
    notes.append("severity_floor_ok")


def _collect_replay_candidates(run_root: Path) -> list[tuple[str, str, Path]]:
    """批三十八 P1-A：收集「查询原件」重放候选——(来源标签, URL, 原件路径)。
    批三十九第三元：数值核要回读卷内原件文本提取 totalResults 与重放响应比对
    （红队五轮 P1-1：此前只查 HTTP 200+20B，手写原件照过）。CVE 账第三方 queried 条目
    与封存回执 sealed_items 各自的 query_evidence 文本里抽第一个 http(s) URL。"""
    cands: list[tuple[str, str, Path]] = []
    ledger = load_json(run_root / "01-guo-jia" / "component-cve-ledger.json") or {}
    for it in ledger.get("items") or []:
        if not isinstance(it, dict) or str(it.get("cve_query") or "") != "queried":
            continue
        for rel in it.get("query_evidence") or []:
            p = run_root / str(rel)
            if p.is_file():
                text = p.read_text(encoding="utf-8", errors="ignore")
                m = re.search(r'https?://[^\s<>]+', text)
                if m:
                    cands.append((f"cve-ledger:{it.get('component', '?')}", m.group(0), p))
                    break
    receipt = run_root / "reports" / "discarded" / "sealing-receipt.json"
    seal = load_json(receipt) if receipt.is_file() else None
    for si in (seal or {}).get("sealed_items") or []:
        if not isinstance(si, dict):
            continue
        for rel in (si.get("query_evidence") or si.get("evidence") or []):
            p = run_root / str(rel)
            if p.is_file():
                text = p.read_text(encoding="utf-8", errors="ignore")
                m = re.search(r'https?://[^\s<>]+', text)
                if m:
                    cands.append((f"sealing:{si.get('cve', si.get('route', '?'))}", m.group(0), p))
                    break
    # 批四十（红队六轮 P1-4）：第三池——分身判决 dedup「零重复/全部原创」声明的查询原件
    # （声称 0day 恰是不点名编号的一侧，此前不进重放池=纯口头原创）
    verdict_p = run_root / "02-cao-cao-shadow" / "delivery-verdict.json"
    dv = load_json(verdict_p) if verdict_p.is_file() else None
    if isinstance(dv, dict) and isinstance(dv.get("dedup"), dict):
        for rel in (dv["dedup"].get("query_evidence") or dv.get("query_evidence") or []):
            p = run_root / str(rel)
            if p.is_file():
                text = p.read_text(encoding="utf-8", errors="ignore")
                m = re.search(r'https?://[^\s<>]+', text)
                if m:
                    cands.append(("dedup-origin:原创声明", m.group(0), p))
                    break
    return cands


@collect_errors
def check_cve_replay(run_root: Path, notes: list[str]) -> None:
    """批三十八（红队四轮 P1-A）：查询原件机械重放——手写一个含 HTTP/1. 行+公开库 URL+JSON
    计数键的 42 字节 txt 即可伪造「查无此洞」或草率封存真 0day（CVE_EVIDENCE_STRICT_RE 三条
    特征全可手写）。修：era≥20261015 场 close 对 CVE 账与封存回执各随机抽 1 条查询原件，
    用卷内记录的同一 URL 真实重放（响应落 run/cve-replay/ 供用户比对），弱核=响应含组件名
    或引用编号；网络异常 fail 挂起（对齐 faker 口径——断网不许关掉抽查）。
    批三十九（红队五轮 P1-1）：批三十八版弱核没兑现（实际只查 200+20B）且与原件零内容比对——
    藏 N 条命中手写「0 条目」照过。补两核：①弱核兑现=重放响应含组件名 token / CVE- 编号模式 /
    totalResults 计数键任一（0 结果真查询含 totalResults，不误杀）；②数值核=原件文本与重放响应
    各提取 totalResults 数值，不等 → fail 挂起（伪造嫌疑或库数据演进；用户比对 run/cve-replay/
    裁量，确认演进在信封 cve_replay_drift_waiver 数组里写 label 后重跑降 note）。"""
    import random as _rd
    import urllib.request as _ur

    m = effective_run_date(run_root)
    if not m or m.group(0) < H22_STRICT_ERA:
        return
    strict39 = _b39_era(run_root)
    drift_waivers = envelope(run_root).get("cve_replay_drift_waiver")
    drift_waivers = [str(x) for x in drift_waivers] if isinstance(drift_waivers, list) else []
    _op44 = _declared_proxy_opener(envelope(run_root))
    if _op44:
        notes.append("cve_replay_via_declared_proxy(批四十四：信封登记代理，开局外发账可对)")
    cands = _collect_replay_candidates(run_root)
    if not cands:
        # 批五十二（摸鱼 AI 招13→16 实锤）：查询件提及漏洞库却零可重放 URL——
        # 去 scheme 蒸发重放池的偷懒出口（https:// 抹掉后收集正则不认→整个保护 skip），fail 挂起
        _src52: list[Path] = [p for p in (run_root / "01-guo-jia").glob("*cve*") if p.is_file()]
        _dedup52 = run_root / "02-cao-cao-shadow" / "dedup"
        if _dedup52.is_dir():
            _src52 += [p for p in _dedup52.rglob("*") if p.is_file()]
        # 批五十三 R5-05：dedup 指针与封存回执也在侦察面（去 scheme 件挪 run/ 蒸发保护的绕路堵死）
        for _extra52 in (
            run_root / "02-cao-cao-shadow" / "delivery-verdict.json",
            run_root / "reports" / "discarded" / "sealing-receipt.json",
        ):
            if _extra52.is_file():
                _src52.append(_extra52)
        # 批五十三 R5-01：词表收窄到库域名级——裸 cve/osv 与账本键名（cve_query 等）撞车，
        # 纯 first_party 诚实账（零查询）曾被整族误拦
        # 批五十六 R29-E-01：再删中文泛词（查重/漏洞库）与裸 nvd/ghsa——诚实 zero-claim 留痕、否认性陈述、
        # 分身卡义务动作名全被误杀；谎账由域名白名单+真实重放+totalResults 三层兜，泛词只贡献误杀面
        _lib_pat52 = re.compile(r"nvd\.nist\.gov|osv\.dev|cve\.org|circl\.lu|advisories", re.I)
        _hit52 = [p.name for p in _src52 if _lib_pat52.search(p.read_text(encoding="utf-8", errors="ignore")[:20000])]
        if _hit52:
            fail(
                f"查询件提及漏洞库/查重（{_hit52[0]} 等 {len(_hit52)} 件）却零可重放 URL——"
                "去 scheme/手写占位蒸发重放池嫌疑（摸鱼 AI 招13→16 实锤路径，批五十二堵口）；"
                "查询件必须含 https:// 官方库完整 URL；纯 first_party 零查询账不写库名即不触发"
            )
        notes.append("cve_replay_skip(no candidates)")
        return
    picked = _rd.sample(cands, min(2, len(cands)))  # 各来源至多 1 条由收集序保证，这里至多抽 2
    out_dir = run_root / "run" / "cve-replay"
    out_dir.mkdir(parents=True, exist_ok=True)
    import datetime as _dt38
    import hashlib as _hl38

    def _total_results(text: str) -> str | None:
        mm = re.search(r'totalResults"?\s*[:=]\s*"?(\d+)"?', text)
        return mm.group(1) if mm else None

    for label, url, orig_p in picked:
        # 批四十九（r18 R3-L 锚②）：查询 URL 域白名单——httpbin/echo 类应声虫端点回显什么闸就信什么，
        # 「打给回显端点拿 totalResults:0」的假查重在此拦死；era≥20261016 场生效
        if strict39:
            try:
                import urllib.parse as _up52

                _host49 = _up52.urlsplit(url).netloc.split("@")[-1].split(":")[0].lower()
            except Exception:  # noqa: BLE001
                _host49 = ""
            _allow49 = {
                "nvd.nist.gov", "services.nvd.nist.gov", "cve.circl.lu", "cve.org", "www.cve.org",
                "github.com", "api.github.com", "api.osv.dev", "osv.dev", "security-tracker.debian.org",
                "access.redhat.com", "ubuntu.com/security", "api.first.org", "cveawg.mitre.org",
            }
            if _host49 not in _allow49:
                fail(
                    f"CVE 查询原件 URL 域非官方漏洞库（{label}：{_host49}，批四十九白名单）——"
                    "应声虫/回显端点伪造查询嫌疑；查询件必须打官方库（NVD/GHSA/OSV/CVE.org 等）"
                )
        slug = _hl38.sha256((label + url).encode("utf-8")).hexdigest()[:10]
        try:
            req = _ur.Request(url, headers={"User-Agent": "Mozilla/5.0 (gate-cve-replay)", "Accept": "application/json"})
            with (_op44.open(req, timeout=30) if _op44 else _ur.urlopen(req, timeout=30)) as resp:
                body = resp.read(200_000).decode("utf-8", errors="ignore")
                status = resp.status
        except Exception as exc:  # noqa: BLE001
            fail(
                f"CVE 查询原件重放失败（{label}：{url}）：{type(exc).__name__}: {str(exc)[:120]}"
                "——重放不可达=查询件真伪无法自证（批三十八）；网络恢复后重跑 close 即过"
            )
            continue
        out_p = out_dir / f"{slug}.txt"
        out_p.write_text("replayed_at: " + _dt38.datetime.now().astimezone().isoformat(timespec='seconds') + "\nurl: " + url + "\nstatus: " + str(status) + "\n---\n" + body, encoding="utf-8")
        if status != 200 or len(body.strip()) < 20:
            fail(f"CVE 查询原件重放异常（{label}）：HTTP {status} 空/短响应——卷内查询件与真实响应不符嫌疑（批三十八），原件已落 {out_p.name}")
            continue
        if strict39:
            token = label.split(":", 1)[1] if ":" in label else ""
            weak_hit = (len(token) >= 2 and token in body) or re.search(r'CVE-\d{4}-\d{4,}', body) or '"totalResults"' in body or "totalResults:" in body
            if not weak_hit:
                fail(
                    f"CVE 查询原件重放弱核不过（{label}）：响应既不含组件名/编号也不含 totalResults 计数键"
                    f"——原件与真实库响应对不上（批三十九），响应已落 {out_p.name} 供比对"
                )
                continue
            orig_text = orig_p.read_text(encoding="utf-8", errors="ignore") if orig_p.is_file() else ""
            o_tr, r_tr = _total_results(orig_text), _total_results(body)
            if o_tr is not None and r_tr is not None and o_tr != r_tr:
                # 批五十五（摸鱼 v3 招4）：空串/超短 waiver 双向子串恒真通杀——豁免词必须 ≥4 字且与 label 互含
                _ws55 = [w for w in drift_waivers if len(w.strip()) >= 4]
                if any(label in w or w in label for w in _ws55):
                    notes.append(f"cve_replay_drift_waived({label}: 原件{o_tr}/重放{r_tr})")
                else:
                    fail(
                        f"CVE 查询原件计数不符（{label}）：卷内原件 totalResults={o_tr}，真实重放={r_tr}"
                        f"——手写「0 条目」藏命中在此被拦；若确属库数据演进（新披露），用户比对 run/cve-replay/{out_p.name}"
                        " 裁量后在信封 cve_replay_drift_waiver 写入本 label 重跑（批三十九）"
                    )
                    continue
            elif o_tr is None:
                # 批四十五 B-6：原件缺 totalResults 不再静默跳过数值核（双非空才比的 fail-open）——
                # 重放带命中（CVE 编号/非零计数）=「查无此洞」无法对账，fail 挂起；重放也无命中记 note
                # （body 为声明代理/直连统一取得的响应，不绕开 declared_proxy 通道）
                _replay_hits = bool(re.search(r'CVE-\d{4}-\d{4,}', body)) or (r_tr is not None and r_tr != "0")
                if _replay_hits:
                    fail(
                        f"CVE 查询原件无 totalResults 无法对账（{label}）：重放响应却带命中（CVE 编号/非零计数）"
                        f"——『查无此洞』类原件无法自证（批四十五 B-6）；补真实响应原件（含 totalResults）后重跑；"
                        f"响应已落 {out_p.name} 供比对"
                    )
                    continue
                notes.append(f"cve_replay_orig_no_totalresults({label}: 原件与重放均无计数/命中——note 留痕，批四十五 B-6)")
        notes.append(f"cve_replay_ok({label} -> {out_p.name})")


@collect_errors
def check_process_provenance(run_root: Path, notes: list[str]) -> None:
    """批三十九（红队五轮 P0-1 运行态绑定材料）：H-22/材料溯源全链只锚「文件哈希」，
    从不锚「监听端口的进程跑的是哪个工件」——真材料入账后起一个仿写/魔改迷你服务
    （同路由+自带反射 XSS）跑本场端口，全部验证真发、截图真浏览器、报告真出，
    闭环证明的是「这端口有洞」而非「目标产品有洞」。修：郭嘉起服时落
    run/process-provenance.json（模板 templates/process-provenance.json）：每 component
    {name, port, pid, main_artifact, main_sha256, start_command, built_from?}；
    close 三层核（era≥20261016 源码场，有 environment-inventory 即必有账）：
    ①账实核——main_artifact 盘上重算 sha256 == main_sha256（假账在此炸）；
    ②追溯核——main_sha256 必须命中开局材料清单 files[].sha256，或走 built_from
    （构建命令非空 + source_manifest_sha256 == 当前 material-manifest.json 哈希）；
    仿写迷你服务的二进制不在清单=当场 fail；③活端口核——netstat 查到端口在听且
    PID 与账不符 = 验证期间换过服务（fail）；端口无监听 = 合规关停记注不拦。"""
    import hashlib as _hl39
    import subprocess as _sp39

    if not _b39_era(run_root) or is_website(envelope(run_root)):
        return
    inv = run_root / "01-guo-jia" / "environment-inventory.json"
    prov_p = run_root / "run" / "process-provenance.json"
    prov = load_json(prov_p)
    comps = prov.get("components") if isinstance(prov, dict) else None
    if inv.is_file():
        if not isinstance(comps, list) or not comps:
            fail(
                "本场有 01-guo-jia/environment-inventory.json（起过服务）但 run/process-provenance.json 缺失或空"
                "——郭嘉起服必须逐 component 落运行工件账（批三十九：port/pid/main_artifact/main_sha256/start_command，"
                "模板 templates/process-provenance.json）；无账=验证对象身份不可追溯，close 不放行"
            )
            return
    else:
        if not isinstance(comps, list) or not comps:
            # 批五十九 A-1（r38 体检）：起服证据在场而 inv 缺失=「不写账」旁路——三枪回执 pass/
            # removed_instance_ready/双拓扑图任一在场都是真起过服的机器证据，闸握着不交叉就
            # 让「防仿写迷你服务」三层核整体蒸发（probe7 实测 FAILURES=0）。era≥20261017 补交叉。
            _era59a = bool((m59a := effective_run_date(run_root)) and m59a.group(0) >= "20261017")
            _evid59a = False
            _ts59 = run_root / "01-guo-jia" / "captcha-removed-three-shots.json"
            if _ts59.is_file():
                try:
                    _tj59 = load_json(_ts59) or {}
                    _vals59 = [str(v).lower() for v in (_tj59.get("shots") or {}).values()] if isinstance(_tj59.get("shots"), dict) else [
                        str(_tj59.get(k) or "").lower() for k in ("login_without_captcha", "wrong_password", "no_account")
                    ]
                    if any(v == "pass" for v in _vals59):
                        _evid59a = True
                except Exception:  # noqa: BLE001
                    pass
            if not _evid59a and any((run_root / "01-guo-jia" / f).is_file() for f in ("removed-instance-ready.json", "removed_instance_ready.json")):
                _evid59a = True
            # 批六十 G-15：双拓扑图对在场（native_login+removed_* 成对实拍件）也是真起服证据
            if not _evid59a:
                _cd60 = run_root / "run" / "captures"
                if _cd60.is_dir():
                    _names60 = [p.name.lower() for p in _cd60.iterdir() if p.is_file()]
                    if any("native" in n for n in _names60) and any("removed" in n for n in _names60):
                        _evid59a = True
            if _era59a and _evid59a:
                fail(
                    "起服证据在场（三枪 pass / removed_instance_ready）但 01-guo-jia/environment-inventory.json 缺失"
                    "——「不写账」不能旁路批三十九运行工件三层核（批五十九 A-1）；补落环境清单"
                    "（环境配置/账号/页面/代码位置）与 run/process-provenance.json 后重跑 close"
                )
            notes.append("process_provenance_skip(未起服)")
            return
        notes.append("process_provenance_voluntary(无环境清单但落了账，照核)")
    manifest = load_json(run_root / "run" / "material-manifest.json")
    manifest_shas: set[str] = set()
    if isinstance(manifest, dict) and isinstance(manifest.get("files"), list):
        for f in manifest["files"]:
            if isinstance(f, dict):
                manifest_shas.add(str(f.get("sha256") or "").lower())
    man_sha_now = _hl39.sha256((run_root / "run" / "material-manifest.json").read_bytes()).hexdigest() if (run_root / "run" / "material-manifest.json").is_file() else ""
    try:
        netstat = _sp39.run(["netstat", "-ano"], capture_output=True, text=True, timeout=30).stdout or ""
    except Exception:  # noqa: BLE001
        netstat = ""
    alive: dict[str, str] = {}  # port -> pid
    for line in netstat.splitlines():
        parts = line.split()
        if len(parts) >= 5 and parts[3] == "LISTENING":
            port = parts[1].rsplit(":", 1)[-1]
            alive[port] = parts[4]
    for ci, c in enumerate(comps):
        if not isinstance(c, dict):
            continue
        name = str(c.get("name") or f"[{ci}]")
        art = str(c.get("main_artifact") or "").strip()
        want = str(c.get("main_sha256") or "").strip().lower()
        if not art or not want:
            fail(f"process-provenance.components[{name}] 缺 main_artifact/main_sha256——运行工件账必填（批三十九）")
            continue
        p = Path(art)
        if not p.is_file():
            fail(
                f"process-provenance.components[{name}].main_artifact 不在盘上：{art}"
                "——收口前运行工件必须在档（收口后清理环境是收口后动作；docker 镜像类工件在 built_from 记构建账并把"
                " main_artifact 指向镜像内主 jar 的构建产物路径）（批三十九）"
            )
            continue
        got = _hl39.sha256(p.read_bytes()).hexdigest()
        if got != want:
            fail(f"process-provenance.components[{name}] 账实分离：{art} 重算 sha256 与账不符——工件事后被换或账是手编（批三十九）")
            continue
        built = c.get("built_from") if isinstance(c.get("built_from"), dict) else {}
        traced = got in manifest_shas or (
            bool(str(built.get("command") or "").strip())
            and man_sha_now
            and str(built.get("source_manifest_sha256") or "").lower() == man_sha_now
        )
        if not traced:
            fail(
                f"process-provenance.components[{name}] 工件不可追溯：{art} 的哈希既不在开局材料清单、"
                "也无 built_from 构建账——验证跑的不是清单内目标产品（仿写/魔改迷你服务在此被拦，批三十九）"
            )
            continue
        port = str(c.get("port") or "")
        if port and port in alive:
            pid = str(c.get("pid") or "")
            if pid and alive[port] != pid:
                fail(
                    f"process-provenance.components[{name}] 端口 {port} 现由 PID {alive[port]} 监听、账内 PID 是 {pid}"
                    "——验证期间服务被换（批三十九）；合法重启须更新账并保留重启前后哈希一致的证据"
                )
            else:
                notes.append(f"process_alive_ok({name}:{port})")
    notes.append(f"process_provenance_ok({len(comps)})")


@collect_errors
def check_official_source_probe(run_root: Path, notes: list[str]) -> None:
    """批三十九（红队五轮 P0-2 官方源外部锚）：official_source_url 批三十六起只是 notes 提示、
    diff 抽验挂曹操人工（自演时左手核右手）——开局前注毒全盲。修（era≥20261016 源码场）：
    ①升格：official_source_url 与 official_source_waiver（≥20 字理由）必居其一，都缺 close fail；
    ②登记了 url 的场 close 真下载（剥代理，批三十七口径）落 run/official-probe/，信封若登记
    official_source_sha256（开局算好）则比对——登记哈希与现下载不符=登记时造假或官方包演进，fail 挂起；
    ③有原档账（material-manifest-src.json zip_entries）时官方包逐成员抽比对——本地清单多出官方包没有的
    成员=开局注毒在此暴露。URL 本身可指向模型可控站（私网/回环机械拦，其余拦不了）：开局外发账
    须含本 URL 由用户肉眼对，最终对账人是用户（如实记档，不假装能拦）。下载不可达 fail 挂起
    （对齐 CVE 重放口径：断网不关抽查）。"""
    import hashlib as _hl40
    import urllib.request as _ur40

    if not _b39_era(run_root) or is_website(envelope(run_root)):
        return
    env = envelope(run_root)
    url = str(env.get("official_source_url") or "").strip()
    waiver = str(env.get("official_source_waiver") or "").strip()
    _op44 = _declared_proxy_opener(env)
    if _op44:
        notes.append("official_probe_via_declared_proxy(批四十四：信封登记代理，开局外发账可对)")
    if not url and not waiver:
        fail(
            "H-22 开局即毒盲区：era≥20261016 源码场信封必填 official_source_url（官方仓库/release 地址）"
            "或 official_source_waiver（≥20 字无官方源理由）二选一（批三十九升格：此前仅 notes 提示）"
        )
        return
    if not url:
        if len(waiver) < 20:
            fail("official_source_waiver 不足 20 字——「为何无官方源」须写实理由（批三十九）")
        notes.append("official_source_waived")
        return
    low = url.lower()
    host = re.sub(r'^https?://', '', low).split("/", 1)[0]
    if (not low.startswith(("http://", "https://"))) or host.startswith(("127.", "localhost", "0.0.0.0", "10.", "192.168.")) or host.startswith("172.") or host.endswith(".local"):
        fail(f"official_source_url 非公网地址（{host}）——官方源锚必须是真实公网官方发布点（批三十九）")
        return
    out_dir = run_root / "run" / "official-probe"
    out_dir.mkdir(parents=True, exist_ok=True)
    slug = _hl40.sha256(url.encode("utf-8")).hexdigest()[:10]
    dest = out_dir / f"{slug}.bin"
    # 代理环境变量已在模块 import 时剥除（批三十七口径，见文件头部）；批四十四起信封登记
    # declared_proxy 的场走声明代理取官方包（值进开局外发账；暗代理仍剥、faker 通道永不走）
    try:
        req = _ur40.Request(url, headers={"User-Agent": "Mozilla/5.0 (gate-official-probe)"})
        with (_op44.open(req, timeout=60) if _op44 else _ur40.urlopen(req, timeout=60)) as resp:
            data = resp.read(500_000_000)
    except Exception as exc:  # noqa: BLE001
        fail(
            f"官方源探针下载失败（{url}）：{type(exc).__name__}: {str(exc)[:120]}"
            "——官方包哈希对不上账=开局注毒检测旁路（批三十九）；网络恢复后重跑 close 即过"
        )
        return
    dest.write_bytes(data)
    got = _hl40.sha256(data).hexdigest()
    import datetime as _dt40

    (out_dir / f"{slug}.meta.json").write_text(
        json.dumps({"url": url, "sha256": got, "size": len(data), "downloaded_at": _dt40.datetime.now().astimezone().isoformat(timespec="seconds")}, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    anchored = str(env.get("official_source_sha256") or "").strip().lower()
    if anchored and anchored != got:
        fail(
            f"官方源探针哈希与信封锚不符：登记 {anchored[:16]}… vs 现下载 {got[:16]}…（{url}）"
            "——登记时造假或官方包演进；用户比对 run/official-probe/ 裁量（批三十九）"
        )
        return
    src = load_json(run_root / "run" / "material-manifest-src.json") or {}
    entries = src.get("zip_entries")
    looks_zip = data[:2] == b"PK"
    if isinstance(entries, list) and entries and looks_zip:
        import zipfile as _zp40

        try:
            zf = _zp40.ZipFile(dest)
            off_names = {n for n in zf.namelist() if not n.endswith("/")}
            idx = {}
            for e in entries:
                if isinstance(e, dict) and (e.get("path") or e.get("name")):
                    # 批四十二 bug 修：material_hash.py zip_entries 条目键是 path（批三十九误写 name，
                    # idx 恒空 → 逐成员比对空转、永远 members_ok(0/N)——开局注毒比对实际从未执行）
                    idx[str(e.get("path") or e.get("name")).lstrip("/")] = str(e.get("sha256") or "").lower()
            import random as _rd40

            sample = _rd40.sample(sorted(idx), min(10, len(idx))) if idx else []
            mismatch = [n for n in sample if n not in off_names]
            if mismatch:
                fail(
                    "官方包缺原档账成员（抽 " + str(len(sample)) + " 例中 " + str(len(mismatch)) + " 例不在官方包）："
                    + "; ".join(mismatch[:5])
                    + "——本地材料与官方包不同源（开局注毒/魔改包在此暴露，批三十九）"
                )
                return
            notes.append(f"official_probe_members_ok({len(sample)}/{len(idx)})")
        except Exception as exc:  # noqa: BLE001
            notes.append(f"official_probe_zip_skip({type(exc).__name__})")
    else:
        notes.append("official_probe_saved(无原档账或非 zip——只锚下载哈希)")
    notes.append(f"official_probe_ok({slug} {len(data)}B)")


@collect_errors
def check_canonical_root(run_root: Path, notes: list[str]) -> None:
    """批三十九（红队五轮 P0-3 信任根补齐）：批三十八信任根外发锚的起点是「开局时刻」——
    开局前把闸改成橡皮图章再开局，外发哈希/verify.bat 自打印全是假闸的、对照自洽。修：
    ①canonical 清单 gates-canonical.json（默认包根或 CAOCAO_CANONICAL_ROOT、scripts/make_canonical.py
    生成、用户保管）——era≥20261016 场 env+close 双相逐件比对检查器/工具哈希与 canonical，
    漂移即 fail（不认 gate_change_refs 豁免：改闸属用户批的 rare event，用户令改闸后须重跑
    make_canonical.py 同步，fail 逼人工路径正是设计）；canonical 文件缺失也 fail（防删根绕过）。
    ②baseline_sent_at 升格：批三十八称「信封记 baseline_sent_at」但闸内零拦——era≥20261016
    close 缺键 fail。如实记档：①canonical 本身与闸同权限可被改；②「开局前改闸」会连本检查一起
    橡皮化——闸内自检只防开局后改闸；开局前改闸的防线在闸外（verify.bat 对照 canonical 由用户跑、
    开局外发值进聊天用户肉眼对），绝对根=用户把 canonical 文件 sha256 抄录到聊天外（模型改不了
    已发出的消息），保管义务见 README。"""
    if not _b39_era(run_root):
        return
    env = envelope(run_root)
    if PHASE == "close" and not str(env.get("baseline_sent_at") or "").strip():
        # 只在 close 查：env 时序在先（信封落盘→跑 env→当回合外发+记 baseline_sent_at），开局查必误拦
        fail(
            "H-25：era≥20261016 场信封必填 baseline_sent_at（开局基线外发进会话的时间戳，深挖条款 29①）"
            "——缺键=开局外发动作无从对账（批三十九：此前条文字面无机械后果）"
        )
    canon_path = Path(os.environ.get("CAOCAO_CANONICAL_ROOT") or str(Path(__file__).resolve().parent.parent / "gates-canonical.json"))
    canon = load_json(canon_path)
    if not isinstance(canon, dict) or not isinstance(canon.get("files"), dict) or not canon["files"]:
        fail(
            f"canonical 根缺失或为空：{canon_path}——用户用包内 scripts/make_canonical.py 重新生成"
            "（批三十九：开局前改闸防线=闸外对照物，删根=绕过，不静默放行）"
        )
        return
    current = _tool_baseline_now()
    drift = sorted(k for k in set(canon["files"]) | set(current) if str(canon["files"].get(k) or "") != str(current.get(k) or ""))
    if drift:
        fail(
            f"检查器/工具与 canonical 根漂移（{canon_path}）："
            + ", ".join(drift)
            + "——开局前改闸或忘同步 canonical 都在此炸（批三十九）；确属用户批的合规改闸，"
            "改完重跑 scripts/make_canonical.py 并在 CHANGELOG 记一行再收口；"
            "跑场者自救（无权改数据盘时）：本场闸用的是沙箱/旧副本，重同步整包副本后重锚信封 tool_baseline 重开局；"
            "或信封 gate_change_refs 登记对应 CHANGELOG 条目原文（批五十六 R29-E-03）"
        )
        return
    notes.append("canonical_root_ok")


@collect_errors
def check_dedup_route_compare(run_root: Path, notes: list[str]) -> None:
    """批三十九（红队五轮 P1-2 判重对照表机械件）：「颗粒度=路由」「命中去重留对照表」是条文
    （gates.md 第三方 CVE 段），但 advisory affected 路由 × 本地路由的对照全靠模型自觉——
    「真做但指向错误结论」（草率封存真 0day）全绿通过。修（era≥20261016）：
    ①sealing-receipt.sealed_items 每条必带 route_compare 数组 ≥1 行（advisory_route ≥4 字 +
    local_path 可解析 + local_line），且查询覆盖面 query_evidence ≥2 条或单件内 ≥2 个不同 URL
    （防查询词太窄漏查）；②reports/json 里 related_cve 非空的 finding（another_face_new 同族）
    同样必带 route_compare。语义对照真伪仍是曹操链审层（机械管形式齐不齐），如实记档。"""
    if not _b39_era(run_root):
        return
    manifest = load_json(run_root / "run" / "material-manifest.json")
    mroot = str(manifest.get("path") or "").strip() if isinstance(manifest, dict) else ""

    def _resolvable(pth: str) -> bool:
        if not pth:
            return False
        p = Path(pth)
        return p.is_file() or (run_root / p).is_file() or (Path(mroot) / p).is_file()

    def _check_rows(rows, owner: str) -> list[str]:
        bad: list[str] = []
        if not isinstance(rows, list) or not rows:
            bad.append(f"{owner}: route_compare 缺失/空数组")
            return bad
        for ri, row in enumerate(rows):
            if not isinstance(row, dict):
                bad.append(f"{owner}: route_compare[{ri}] 非对象")
                continue
            adv = str(row.get("advisory_route") or "").strip()
            lp = str(row.get("local_path") or "").strip()
            ll = str(row.get("local_line") or "").strip()
            if len(adv) < 4:
                bad.append(f"{owner}: route_compare[{ri}].advisory_route <4 字（须引公开 advisory 的受影响路由原文）")
            if not lp or not _resolvable(lp):
                bad.append(f"{owner}: route_compare[{ri}].local_path 不可解析（{lp or '空'}）")
            if not ll:
                bad.append(f"{owner}: route_compare[{ri}].local_line 空")
        return bad

    problems: list[str] = []
    receipt = run_root / "reports" / "discarded" / "sealing-receipt.json"
    seal = load_json(receipt) if receipt.is_file() else None
    for si_i, si in enumerate((seal or {}).get("sealed_items") or []):
        if not isinstance(si, dict):
            continue
        owner = f"sealed_items[{si_i}]({si.get('cve', '?')})"
        problems.extend(_check_rows(si.get("route_compare"), owner))
        qe = si.get("query_evidence") or si.get("evidence") or []
        urls: set[str] = set()
        if isinstance(qe, list):
            for rel in qe:
                p = run_root / str(rel)
                if p.is_file():
                    for mu in re.finditer(r'https?://[^\s<>"\']+', p.read_text(encoding="utf-8", errors="ignore")):
                        urls.add(mu.group(0).split("&")[0])
        if len(qe) < 2 and len(urls) < 2:
            problems.append(f"{owner}: 查询覆盖面不足——query_evidence ≥2 条或单件内 ≥2 个不同查询 URL（防单查询词太窄漏查，批三十九）")
    jdir = run_root / "reports" / "json"
    for jf in sorted(jdir.glob("*.json")) if jdir.is_dir() else []:
        data = load_json(jf)
        if not isinstance(data, dict):
            continue
        rel_cve = str(data.get("related_cve") or "").strip()
        if not rel_cve:
            continue
        problems.extend(_check_rows(data.get("route_compare"), f"{jf.name}(related_cve={rel_cve})"))
    if problems:
        fail("判重对照表不齐（批三十九 route_compare 机械件）：" + "；".join(problems[:8]))
        return
    notes.append("dedup_route_compare_ok")


@collect_errors
def check_visual_false_replay(run_root: Path, notes: list[str]) -> None:
    """批三十九（红队五轮 P1-3 无视觉场在线抽验）：visual_available:false 场「完整 CLI 链」的
    回包可手写（Date/UA 全自编），交叉验证只拦盘面矛盾（全程真不用浏览器时声明自洽），
    RF-DOC-13 主会话抽验是自演。修（era≥20261016）：close 对无视觉场 run/h24-replay/ 的
    curl GET 类命令抽 1 条，闸自己真发（不执行卷内命令——只提 URL），比对现响应状态码与
    .out 原件记录的状态码：服务还开着且回包对不上 = 手写实锤 fail；URL 不可达 = 服务已合规
    关停（批量流水口径），记注交 H-24 用户抽验，不拦。无可安全重放的 GET 候选记注。"""
    import urllib.request as _ur41

    if not _b39_era(run_root) or envelope(run_root).get("visual_available") is not False:
        return
    rd = run_root / "run" / "h24-replay"
    if not rd.is_dir():
        return
    cands: list[tuple[Path, str]] = []
    for c in sorted(rd.glob("*.cmd")):
        body = c.read_text(encoding="utf-8", errors="ignore")
        for line in body.splitlines():
            low = line.lower()
            if "curl" not in low:
                continue
            if any(k in low for k in ("-d ", "--data", "-x post", "-x put", "--upload", " -t ", "-f ", "--form")):
                continue  # 写操作/带体请求不自动重放
            mu = re.search(r'https?://[^\s"\'<>]+', line)
            if mu:
                cands.append((c, mu.group(0).rstrip("^&;,)")))
                break
        if len(cands) >= 6:
            break
    if not cands:
        notes.append("visual_false_replay_skip(无 curl GET 候选)")
        return
    import random as _rd41

    cmd_p, url = _rd41.choice(cands)
    try:
        req = _ur41.Request(url, headers={"User-Agent": "Mozilla/5.0 (gate-b39-replay)"})
        with _ur41.urlopen(req, timeout=15) as resp:
            status = str(resp.status)
    except _ur41.HTTPError as exc:
        status = str(exc.code)
    except Exception:  # noqa: BLE001
        notes.append(f"visual_false_replay_unreachable({cmd_p.name}: 服务已关/不可达，交 H-24 用户抽验)")
        return
    out = cmd_p.with_suffix(".out")
    out_text = out.read_text(encoding="utf-8", errors="ignore") if out.is_file() else ""
    mo = re.search(r'HTTP/[\d.]+\s+(\d{3})', out_text)
    if not mo:
        notes.append(f"visual_false_replay_skip({cmd_p.name}: .out 无状态行可比)")
        return
    if mo.group(1) != status:
        fail(
            f"无视觉场回包抽验不符（{cmd_p.name} → {url}）：卷内 .out 记录 HTTP {mo.group(1)}，"
            f"现真实响应 HTTP {status}——服务仍在监听但回包对不上=手写回包实锤（批三十九，按 H-21 伪造论处）"
        )
        return
    notes.append(f"visual_false_replay_ok({cmd_p.name}: {status})")


@collect_errors
def check_closure_stats(run_root: Path, notes: list[str]) -> None:
    """批三十九（红队五轮 P2 两小件，era≥20261016）：
    ①低覆盖亮灯：终态里 blocked/coverage_gap/suspected 占比 >50%（样本 ≥4）标
    low_coverage_session=true 落 run/closure-stats.json + 回执 note——不拦（H-21 允许如实缺陷），
    但 SKILL 最丑自报条文要求亮灯场第一条自报覆盖率问题，用户看灯；
    ②免录改标弱核：complexity=simple 的 verified 卷若结论/描述文本含 ≥2 个多步特征词
    （第二步/然后/切换/换token/再登录/第二次）记注不拦——防把复杂链改标 simple 逃必录，
    语义仍归曹操链审。"""
    if not _b39_era(run_root):
        return
    jdir = run_root / "reports" / "json"
    total = weak = 0
    multi_hint: list[str] = []
    feats = ("第二步", "第三步", "然后", "切换", "换token", "换身份", "再登录", "第二次", "另一账号")
    for jf in sorted(jdir.glob("*.json")) if jdir.is_dir() else []:
        data = load_finding_json(jf, "check_closure_stats")  # 批四十五 B-1：数组根/malformed 明确 fail
        if not isinstance(data, dict):
            continue
        st = _finding_status(data)  # 批四十五 M31：三键统一
        if not st:
            continue
        total += 1
        if st in ("blocked", "coverage_gap", "suspected"):
            weak += 1
        if st == "verified" and str(data.get("complexity") or "").lower() == "simple":
            blob = str(data.get("conclusion") or "") + str(data.get("description") or "")
            hits = sum(1 for w in feats if w in blob)
            if hits >= 2:
                multi_hint.append(f"{jf.name}({hits})")
    stats = {"low_coverage_session": bool(total >= 4 and weak / total > 0.5), "total_dispositions": total, "weak_dispositions": weak, "simple_multi_step_hint": multi_hint}
    (run_root / "run" / "closure-stats.json").write_text(json.dumps(stats, ensure_ascii=False, indent=2), encoding="utf-8")
    if stats["low_coverage_session"]:
        notes.append(f"low_coverage_session=true({weak}/{total} blocked|gap|suspected)——最丑自报第一条必须是覆盖率问题（批三十九）")
    if multi_hint:
        notes.append("simple_multi_step_hint(" + ",".join(multi_hint[:4]) + ")——complexity=simple 但文本多步特征，曹操链审复核是否改标逃必录（批三十九弱核）")
    # 批四十（红队六轮 P2-8）：降级理由复制粘贴核——同文 downgrade_reason 出现 ≥2 次记 note
    reasons: dict[str, int] = {}
    for jf in sorted(jdir.glob("*.json")) if jdir.is_dir() else []:
        d = load_json(jf)
        if isinstance(d, dict):
            r = str(d.get("downgrade_reason") or "").strip()
            if r:
                reasons[r] = reasons.get(r, 0) + 1
    dup = [f"{k[:24]}…x{v}" for k, v in reasons.items() if v >= 2]
    if dup:
        notes.append("downgrade_reason_duplicated(" + ",".join(dup[:3]) + ")——复制粘贴降级理由嫌疑，曹操链审复核（批四十弱核）")
    # 批四十（红队六轮 P2-7）：确认件 claim 机读弱核——review.md 无 key=value 行 = claim 废话化，
    # faker 复检永远判一致；有 key=value 行（vision_gate --claim 格式）复检才有值可问
    vr = run_root / "run" / "vision-reviews"
    if vr.is_dir():
        no_kv = 0
        total_rv = 0
        for rv in sorted(vr.glob("*.review.md")):
            total_rv += 1
            body = rv.read_text(encoding="utf-8", errors="ignore")
            # 批四十二 bug 修：判定行本身（evidence_ok: pass 等）就是 key=value 形态——
            # 不排除判定键则该弱核永远命中=形同虚设；只有非判定键才算「机读 claim 值」
            kv = re.search(r"(?m)^\s*([\w\u4e00-\u9fff.\-]+)\s*[=:]\s*\S+", body)
            if not kv or kv.group(1).lower() in ("evidence_ok", "verdict", "status", "result", "判定", "pass", "fail"):
                # 首个 key=value 是判定行：再看有没有第二处非判定键
                rest = body[kv.end():] if kv else body
                kv2 = re.search(r"(?m)^\s*([\w\u4e00-\u9fff.\-]+)\s*[=:]\s*\S+", rest)
                if not kv2 or kv2.group(1).lower() in ("evidence_ok", "verdict", "status", "result", "判定", "pass", "fail"):
                    no_kv += 1
        if total_rv and no_kv == total_rv:
            notes.append("vision_review_claims_no_kv(全部确认件无 key=value 行——claim 废话化，faker 复检无从按值问图；按 RF-GATE-02 补机读键值，批四十弱核)")
    # 批四十（红队六轮 P2-9）：js-collection 接口 source 锚弱核——整本手写无真值锚在此留痕
    for jc in (run_root / "01-guo-jia" / "js-collection.json", run_root / "09-si-ma-yi" / "js-collection.json"):
        if not jc.is_file():
            continue
        j = load_json(jc) or {}
        led = j.get("ledger")
        if isinstance(led, list) and led:
            anchored = sum(1 for it in led if isinstance(it, dict) and (it.get("source") or it.get("source_url") or it.get("js_sha256")))
            if anchored < len(led) * 0.5:
                notes.append(f"js_ledger_unanchored({jc.parent.name}/js-collection.json: {anchored}/{len(led)} 条带 source 锚)——手写嫌疑，曹操链审抽核（批四十弱核）")


@collect_errors
def check_material_snapshot(run_root: Path, notes: list[str]) -> None:
    """批四十（红队六轮 P0-2b 目录材料中段洗白）：ZIP 材料有 zip_entries 双账，目录形态材料
    此前只记 waiver（批三十七 docstring 自认「目录原档不适用」）——env 后往解压树塞洞、
    重跑 material_hash.py 覆盖清单、改写 env 回执锚值，中段洗白自洽。修（era≥20261016）：
    ①信封登记 material_source_path 且非 .zip（目录形态）→ 必须落 run/material-snapshot.sha256
    （对原档先 tar/zip 打包快照再算清单，快照哈希进外发）或信封 material_snapshot_waiver
    （≥20 字「为何无快照」+用户明示）二选一；②close 回执带 env_receipt_sha256（已落）+
    深挖 29③ 开局外发 env 指纹——中段改写在两点外发对不上。快照对象=用户原档，别把
    captcha_removed 声明副本混进快照。"""
    if not _b39_era(run_root) or is_website(envelope(run_root)):
        return
    env = envelope(run_root)
    src_path = str(env.get("material_source_path") or "").strip()
    if not src_path or src_path.lower().endswith(".zip"):
        return
    snap = run_root / "run" / "material-snapshot.sha256"
    waiver = str(env.get("material_snapshot_waiver") or "").strip()
    if snap.is_file() and snap.stat().st_size >= 16:
        notes.append("material_snapshot_ok")
        return
    if len(waiver) >= 20:
        notes.append("material_snapshot_waived")
        return
    fail(
        f"目录形态材料（material_source_path={src_path}）缺快照账：run/material-snapshot.sha256"
        "（对原档先打包快照——tar/zip 落 数据盘再算清单，快照哈希开局外发）或信封 material_snapshot_waiver"
        "（≥20 字无快照理由+用户明示）二选一（批四十：目录材料与 ZIP 双账同等待遇，堵中段洗白）"
    )


@collect_errors
def check_cross_session_reuse(run_root: Path, notes: list[str]) -> None:
    """批四十（红队六轮 P0-3 整场复读）：把旧 run_root 整套复制、改 run_id 刷新 mtime、
    era 核照过（只拦「谎报旧目录」不管「新目录装旧货」），write_closure_ledger 只写不比，
    全包零跨场查重——半小时复读交卷。修：close 算「素材摘要」（captures 全图 sha256 集合
    + 正位 DOCX 请求行 path 指纹），与数据根 closure-ledger.jsonl 同目标旧场的素材摘要比对：
    图哈希交集 ≥5 或 ≥50% 且信封未声明 reuses_prior_session → fail 挂起（合法复测/续考在
    信封 reuses_prior_session=true + prior_run_ids 登记旧场后放行记注，交用户裁决口径）。"""
    import hashlib as _hl42

    if not _b39_era(run_root):
        return
    cap_dir = run_root / "run" / "captures"
    img_shas: set[str] = set()
    if cap_dir.is_dir():
        for p in sorted(cap_dir.rglob("*")):
            if p.is_file() and p.suffix.lower() in IMAGE_EXT:
                try:
                    img_shas.add(_hl42.sha256(p.read_bytes()).hexdigest())
                except OSError:
                    continue
                if len(img_shas) >= 60:
                    break
    rep = run_root / "reports"
    req_paths: set[str] = set()
    for f in sorted(rep.glob("*.docx")) if rep.is_dir() else []:
        if is_summary_docx(f.name):
            continue
        try:
            text = docx_plain_text(f)  # 批四十二：请求行跨 run 拆段漏提取（跨场指纹失真）
        except Exception:  # noqa: BLE001
            continue
        for mu in re.finditer(r"(?m)(?:GET|POST|PUT|DELETE|PATCH)\s+(/\S+?)(?:\s|$)", text):
            req_paths.add(mu.group(1).split("?")[0][:80])
        if len(req_paths) >= 40:
            break
    if len(img_shas) < 5 and len(req_paths) < 5:
        notes.append("cross_session_skip(素材过少)")
        return
    lib = next((p for p in [run_root, *run_root.parents] if p.name == "library"), None)
    ledger_p = lib / "closure-ledger.jsonl" if lib else run_root.parent / "closure-ledger.jsonl"
    if not ledger_p.is_file():
        notes.append("cross_session_skip(无台账)")
        return
    target = str(envelope(run_root).get("target_identity") or "").strip()
    declared = envelope(run_root).get("reuses_prior_session") is True
    hits: list[str] = []
    for line in ledger_p.read_text(encoding="utf-8", errors="ignore").splitlines():
        try:
            row = json.loads(line)
        except Exception:  # noqa: BLE001
            continue
        if target and str(row.get("target_identity") or "") != target:
            continue
        old_imgs = set(row.get("material_digest", {}).get("img_shas") or [])
        old_paths = set(row.get("material_digest", {}).get("req_paths") or [])
        if not old_imgs and not old_paths:
            continue
        img_overlap = len(img_shas & old_imgs)
        path_overlap = len(req_paths & old_paths)
        high = (img_overlap >= 5 and img_overlap >= len(img_shas) * 0.5) or (path_overlap >= 5 and path_overlap >= len(req_paths) * 0.5)
        if high:
            hits.append(f"{row.get('run_id', '?')}(图交 {img_overlap}/路径交 {path_overlap})")
    if hits and not declared:
        fail(
            "跨场素材重合嫌疑（批四十整场复读核）：与旧场 " + "; ".join(hits[:3])
            + " 素材摘要高重合——整套复读旧 run_root 在此被拦；确属合法复测/续考，信封声明 "
            "reuses_prior_session=true 并登记 prior_run_ids 后重跑（记注交用户裁决）"
        )
        return
    if hits and declared:
        notes.append("cross_session_reuse_declared(" + ",".join(hits[:2]) + ")")
    else:
        notes.append("cross_session_ok")


@collect_errors
def check_dedup_origin_query(run_root: Path, notes: list[str]) -> None:
    """批四十（红队六轮 P1-4 原创声明零查询义务）：重放池此前只收组件账 queried + 封存件
    sealed_items——分身判决 dedup 段只要不点名公开编号（直接写「查无重复，全部原创」），
    零查询证据要求：声称 0day 恰是不点名编号的一侧，纯口头原创。修（era≥20261016）：
    ①dedup 段结论含「零重复/无重复/全部原创/查无重复」类声明且无可解析查询原件 → fail
    （≥1 条 NVD/GHSA/官方 advisory 查询件，且入 check_cve_replay 重放池）；②查询词弱核
    （note 级）：查询 URL 参数须含产品名 token 或版本号——「查了但用错词保证零结果」的
    高级偷懒至少留痕（产品中文名与英文查询词可能不同，故只 note 不 fail）。"""
    if not _b39_era(run_root):
        return
    verdict_p = run_root / "02-cao-cao-shadow" / "delivery-verdict.json"
    data = load_json(verdict_p) if verdict_p.is_file() else None
    dedup = data.get("dedup") if isinstance(data, dict) and isinstance(data.get("dedup"), dict) else None
    if dedup is None:
        return
    blob = json.dumps(dedup, ensure_ascii=False)
    origin_claim = re.search(r"零重复|无重复|全部原创|查无重复|没有重复|0\s*重复|无公开同", blob)
    if not origin_claim:
        return
    qe = dedup.get("query_evidence") or data.get("query_evidence") or []
    has_orig = any((run_root / str(rel)).is_file() for rel in qe if isinstance(rel, str))
    if not has_orig:
        fail(
            "分身判决 dedup 段声称「零重复/全部原创」但无可解析查询原件（批四十 P1-4）——"
            "原创声明与点名编号同义务：≥1 条 NVD/GHSA/官方 advisory 查询件（入重放池），"
            "纯口头原创不算查重"
        )
        return
    target = str(envelope(run_root).get("target_identity") or "")
    ver_token = re.search(r"\d+(\.\d+)+", target)
    name_token = re.split(r"[\s\-—vV\d]", target)[0] if target else ""
    # 批五十八 B（摸鱼洞⑥ 闸代考）：弱核升格——全套查询件与本场目标组件零绑定时 fail。
    # 手编查询件放真 NVD URL 能让重放真过（URL 真、数据真，只是查的是别家产品），note 级拦不住。
    # 机械可绑 token：产品名 ASCII 首词/版本号，raw+unquote 双态匹配；纯中文名且 unquote 仍绑不上时
    # 维持 note（避免误杀诚实中文查询）。
    import urllib.parse as _up58

    _ascii_tok58 = name_token if re.search(r"[A-Za-z0-9]{4,}", name_token or "") else ""
    _ver58 = ver_token.group(0) if ver_token else ""
    _bind58 = False
    _have_official58 = False
    for rel in qe:
        p = run_root / str(rel)
        if not p.is_file():
            continue
        text = p.read_text(encoding="utf-8", errors="ignore")
        for mu in re.finditer(r'https?://[^\s<>"\']+', text):
            u = mu.group(0)
            # 批五十八 B 修：原批四十此处 startswith(("nvd.nist.gov",…)) 拿 https:// 全 URL 对裸域名
            # 比前缀恒假——官方域判断从未命中（僵尸检查，弱核 note 也从未出场）。改域名级正则。
            if not re.search(r"nvd\.nist\.gov|cve\.circl\.lu|github\.com/advisories|api\.osv\.dev", u, re.I):
                continue
            _have_official58 = True
            _uu58 = _up58.unquote(u)
            ok_tok = (
                (_ascii_tok58 and (_ascii_tok58.lower() in u.lower() or _ascii_tok58.lower() in _uu58.lower()))
                or (name_token and name_token.lower() in _uu58.lower())
                or (_ver58 and _ver58 in _uu58)
            )
            if ok_tok:
                _bind58 = True
            else:
                notes.append(
                    f"dedup_query_term_weak({p.name}: 查询 URL 未含产品名/版本号 token——「用错词保证零结果」嫌疑，曹操链审复核，批四十弱核)"
                )
            break
        if not _bind58 and text.strip().startswith("{"):
            try:
                _qj58 = json.loads(text)
                for _q58 in (_qj58 or {}).get("queries") or []:
                    _t58 = str((_q58 or {}).get("term") or "")
                    if _t58 and (
                        (_ascii_tok58 and _ascii_tok58.lower() in _t58.lower())
                        or (name_token and name_token.lower() in _t58.lower())
                        or (_ver58 and _ver58 in _t58)
                    ):
                        _bind58 = True
                        break
            except Exception:  # noqa: BLE001
                pass
    if _have_official58 and not _bind58 and (_ascii_tok58 or _ver58):
        fail(
            "dedup 查询件与本场目标组件零绑定（批五十八 B，摸鱼洞⑥「闸代考」）：全套查询 URL/查询词"
            f"均不含产品名「{name_token}」或版本「{_ver58}」——手编他产品真查询件能让重放真过，"
            "查重义务绑定本场组件；官方英文名确与信封名不同时，查询词补产品 slug 并在卷内注明对应关系"
        )
    notes.append("dedup_origin_query_ok")


@collect_errors
def check_route_path_coverage(run_root: Path, notes: list[str]) -> None:
    """批四十（红队六轮 P1-5，batch31 #7 升格）：涉及接口清单只查「块名在+采证文件名在」——
    一条卷接口清单塞 N 个 path、实际只打过一个口，闸不查「每个 path 都有对应实测」；
    反向偷懒（把不同路由的洞并成一条卷少干活）零机械核。修（era≥20261016）：正位 finding
    DOCX 的请求行 path 集合逐个在本场证据文本（04/06/09 角色目录+run/captures 的文本件）里
    命中——清单里声明但全场没打过的 path 直接 fail（合并侧对账账）。URL 前缀匹配兜底：
    证据里 path 带 host 或前导上下文时按子串命中。"""
    if not _b39_era(run_root):
        return
    rep = run_root / "reports"
    docxs = [f for f in sorted(rep.glob("*.docx")) if not is_summary_docx(f.name)] if rep.is_dir() else []
    if not docxs:
        return
    ev_texts: list[str] = []
    ev_files: list[Path] = []
    for sub in ("04-cao-ren", "06-yu-jin", "09-si-ma-yi", "run/captures"):
        d = run_root / sub
        if not d.is_dir():
            continue
        for p in sorted(d.rglob("*")):
            if p.is_file() and p.suffix.lower() in (".txt", ".json", ".http", ".md", ".log", ".jsonl", ".cmd", ".out"):
                try:
                    ev_texts.append(p.read_text(encoding="utf-8", errors="ignore")[:400_000])
                    ev_files.append(p)
                except OSError:
                    continue
                if len(ev_texts) >= 120:
                    break
    ev_blob = "\n".join(ev_texts)
    problems: list[str] = []
    for f in docxs:
        try:
            text = docx_plain_text(f)  # 批四十二：请求行跨 run 拆段漏提取
        except Exception:  # noqa: BLE001
            continue
        paths = []
        for mu in re.finditer(r"(?m)(?:GET|POST|PUT|DELETE|PATCH)\s+(/\S+?)(?:\s|$)", text):
            p_ = mu.group(1).split("?")[0]
            if p_ not in paths:
                paths.append(p_)
        for p_ in paths[:20]:
            if p_ in ev_blob:
                continue
            # 批四十二 bug 修：模板 path（/api/user/{id}）vs 实测实例化请求（/api/user/123）
            # 直接子串必假阴性——{段} 转通配再比（整段模板才转，段内混排罕见不管）
            if "{" in p_:
                segs = [r"[^/\s]+" if s.startswith("{") and s.endswith("}") else re.escape(s) for s in p_.split("/")]
                if re.search("/".join(segs), ev_blob):
                    continue
            problems.append(f"{f.name}: {p_}")
    if problems:
        fail(
            "接口清单 path 覆盖核不过（批四十 P1-5/batch31#7）：清单声明但全场证据文本未命中的 path——"
            + "; ".join(problems[:6])
            + "——每个列出的接口必须有本场实测原件（把不同路由并成一条卷少干活在此被拦）；"
            "确未实测的 path 从清单移除或补测"
        )
        return
    notes.append(f"route_path_coverage_ok({len(docxs)} 卷)")


@collect_errors
@collect_errors
def check_run_artifacts_consumption(run_root: Path, notes: list[str]) -> None:
    """批四十九（r18 R3-E 接缝账）：两道「做了没人查」接上——
    ①vision_gate 逐张确认件（*.review.md）close 全程零消费（grep 实证 0 引用）：fail 判定滞留=未处置；
    ②派发三件套回执：run/agents/ 里有 dispatch 无 read-ack = 派活没回音。
    均 era≥20261016 场生效（存量不追溯）。"""
    m = effective_run_date(run_root)
    if not m or m.group(0) < "20261016":
        return
    # ① 确认件消费：重拍闭环后的 .review.md 应为通过态；滞留 fail = 有图被判弱却没重拍/没剔除
    # 批五十八 G：failed/ 归档目录豁免——诚实归档废件（重拍后的旧 weak 件挪 failed/ 保存）
    # 不算「滞留未处置」（B 场实测误杀：4 份全在 failed/ 仍被 rglob 扫进）；正位置上的 weak 才拦
    _fail_md: list[str] = []
    for p in list(run_root.rglob("*.review.md")) + list(run_root.rglob("*.gate.json")):  # 批五十九 D-2：gate.json 同收
        if any(seg in p.parts for seg in SKIP_WALK | {"failed"}):
            continue
        try:
            txt = p.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if re.search(r'"gate"\s*:\s*"fail"', txt) or re.search(r"判定\s*[:：]\s*evidence_weak", txt):
            _fail_md.append(str(p.relative_to(run_root)))
    if _fail_md:
        fail(
            f"vision_gate 确认件有 {len(_fail_md)} 份 fail 判定滞留未处置（如 {_fail_md[0]}）——"
            "重拍后 --out 同名覆盖为通过态，或剔除该图并同步图注/清单（r18 R3-E 接缝①，批四十九接上消费）"
        )
    # ② 派发回执配对：有 dispatch 必有 read-ack（lite 已在派发时跑过形态核，这里只核闭环存在性）
    _agents = run_root / "run" / "agents"
    if _agents.is_dir():
        _disp = sorted(_agents.glob("*-dispatch.json"))
        _missing_ack = [d.name for d in _disp if not (_agents / (d.name.replace("-dispatch.json", "") + "-read-ack.json")).is_file()]
        if _missing_ack:
            fail(
                f"派活无回执：{_missing_ack[0]} 等 {len(_missing_ack)} 件 dispatch 缺对应 read-ack"
                "（r18 R3-E 接缝②）——子代理到场先交 read-ack（lite 三件套契约）"
            )
    notes.append("run_artifacts_consumed")


def check_era_sanity(run_root: Path, notes: list[str]) -> None:
    """批三十八（红队四轮 P0-2）：era 回拨交叉核——era 唯一锚=目录名日期，而目录名是执行者
    起的：建旧日期目录即整批 era≥20261015 机械拦静默降级（批三十三/三十六堵了信封回填与
    无日期，没堵目录名本身撒谎）。交叉：目录声称日期比场内最早文件 mtime 日期还早 >1 天
    = 谎报旧目录（真实开场晚于声称）；整场回拨系统时钟可骗过本核，但需维持回拨到收口且
    会打乱宿主闹钟/Cron/其他文件时间戳——成本从「起个名」涨到「全程劫持时钟」。
    批四十五 B-12：补挂 @collect_errors（fail 记账不再中断后续检查）；非法日期（20269999）
    strptime 裸崩改结构化 fail。"""
    import datetime as _dt

    m = effective_run_date(run_root)
    if not m or m.group(0) == "99999999":
        return
    try:
        claimed = _dt.datetime.strptime(m.group(0), "%Y%m%d").date()
    except ValueError:
        fail(
            f"目录名日期 {m.group(0)} 不是合法日历日期——era 无法判定（批四十五 B-12）；"
            "按真实日期 YYYYMMDD 改名后重跑"
        )
    oldest = None
    for dirpath, dirnames, filenames in os.walk(run_root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_WALK]
        for name in filenames:
            try:
                mt = (Path(dirpath) / name).stat().st_mtime
            except OSError:
                continue
            d = _dt.datetime.fromtimestamp(mt).date()
            if oldest is None or d < oldest:
                oldest = d
    if oldest is None:
        return
    drift = (oldest - claimed).days
    if drift > 1:
        fail(
            f"era 回拨嫌疑：目录名声称 {claimed} 但场内最早文件落盘于 {oldest}（晚 {drift} 天）——"
            "目录名谎报旧日期=整批新机械拦静默降级（批三十八交叉核）；核对实际开场日期后改名重跑"
        )
    # 批五十三 R5-08：删 env 回执=era 双对账蒸发——era≥20261016 场 verify/close 必须有 env 回执在盘
    if PHASE in ("verify", "close") and m.group(0) >= "20261016" and not (run_root / "run" / "hard-gate-env.json").is_file():
        fail(
            "run/hard-gate-env.json 不存在（era≥20261016 场 verify/close 必须有 env 回执在盘，批五十三 R5-08）——"
            "删回执蒸发 run_date 双对账的出口已堵：按相位顺序 env→verify→close 重跑"
        )
    # 批四十九（r18 R3-L 锚①落地）：env 回执 run_date 双对账——正常场「目录名日期==env 实跑日期」
    # （昨开今收场两者同为昨天也一致）；只有改名降级场不一致。env 回执属 scene_digest v4 指纹域，
    # 事后改它的 run_date 会在 verify-close 炸（双保险）。
    _envrc49 = run_root / "run" / "hard-gate-env.json"
    if _envrc49.is_file():
        _er49 = load_json(_envrc49) or {}
        _rd49 = str(_er49.get("run_date", "")).strip()
        if _rd49 and _rd49 != m.group(0):
            fail(
                f"era 降级实锤：目录名日期 {m.group(0)} 与 env 回执实跑日期 {_rd49} 不一致（批四十九双对账）——"
                "目录名被改成旧日期以蒸发 era≥20261016 防线（基线/指纹/运行账全跳）；按真实日期改名重跑"
            )
    notes.append(f"era_sanity_ok({claimed} vs oldest {oldest})")


@collect_errors
def check_branch_material_cross(run_root: Path) -> None:
    """批三十七（红队三轮 P0-2）：branch 单向谎报反查——信封写 website_only 且不建
    01-guo-jia/ 时，源码场五套硬账/三枪/九人目录检查全部静默蒸发（现有 4081 只拦反向）。
    修：场内（排除 run/reports/快照目录豁免外全树）出现源码工程特征（pom.xml/build.gradle/
    composer.json/go.mod 或 *.java/*.php/*.cs 源文件 >20）而 branch=website_only → fail。
    批四十一（红队七轮挂账 b 落地）：input_scope_kind × branch 两键一致性核——is_website 以
    input_scope_kind 优先，website 场只改 branch 不改本键会被静默当源码场收口（fail-closed
    卡死整场九人+五套硬账）。era≥20261016：两键都写且 website 判定不一致 → 显式 fail
    （不翻判定语义，冲突交人核）；存量场放行。"""
    env = envelope(run_root)
    # 批五十一 R4-S-01（复核批 13② 正向闸落地）：材料登记在场=不可能合法自称纯远程——
    # material_source_path 有值而两键判定 website → fail（材料在手却谎报 website_only 蒸发起服优先/五套账）
    if _b39_era(run_root):
        _mat51 = str(env.get("material_source_path") or "").strip()
        if _mat51:
            _k51 = str(env.get("input_scope_kind") or "").lower()
            _b51 = str(env.get("branch") or "").lower()
            # 批五十三 R5-06：website 别名同拦（is_website 认 "website"，正向闸此前只认 website_only 子串）
            _web51 = lambda s: s == "website" or "website_only" in s
            if _web51(_k51) or _web51(_b51):
                fail(
                    f"信封登记 material_source_path={_mat51} 但 branch/input_scope_kind 自称纯远程网站——"
                    "材料在场无纯远程豁免资格（批五十一正向闸）：起服复现走源码场口径，改 branch=local_source/source_and_website 重跑"
                )
        # 批五十三 R5-07：era≥20261016 两键必填——缺键使 RF-IMG-19/起服优先整段蒸发
        # 批五十五（摸鱼 v3 招5）：补值域——"n/a" 类非空垃圾值曾同时骗过两口径
        _enum55 = {"website_only", "local_source", "source_and_website", "website"}
        _k55 = str(env.get("input_scope_kind") or "").strip()
        _b55v = str(env.get("branch") or "").strip()
        if not _b55v or not _k55:
            fail(
                "信封缺 branch/input_scope_kind（era≥20261016 必填）——缺键使起服优先/截图必嵌/分支反查整段蒸发（批五十三 R5-07）；补两键后重跑"
            )
        if _b55v not in _enum55 or _k55 not in _enum55:
            fail(
                f"信封 branch={_b55v!r} / input_scope_kind={_k55!r} 不在合法值域（website_only|local_source|source_and_website）——"
                "非空垃圾值（n/a 等）曾同时骗过 is_website 与材料口径（摸鱼 v3 招5，批五十五）；改真实分支重跑"
            )
    if _b39_era(run_root):
        kind = str(env.get("input_scope_kind") or "").lower()
        branch = str(env.get("branch") or "").lower()
        if kind and branch:
            kind_web = "website_only" in kind or kind == "website"
            branch_web = "website_only" in branch or branch == "website"
            if kind_web != branch_web:
                fail(
                    f"信封 input_scope_kind={kind} 与 branch={branch} 分支判定打架（一个 website 一个源码）"
                    "——is_website 以 input_scope_kind 优先会静默翻转整套收口检查（批四十一两键一致性核）；"
                    "核对真实材料形态后把两键改一致再跑"
                )
    if not is_website(env):
        return
    skip_parts = {"node_modules", ".git", "__pycache__", "run", "reports", "cors-audit"}
    hits = {"engines": [], "source_files": 0}
    for dirpath, dirnames, filenames in os.walk(run_root):
        dirnames[:] = [d for d in dirnames if d not in skip_parts]
        for name in filenames:
            low = name.lower()
            if low in ("pom.xml", "build.gradle", "build.gradle.kts", "composer.json", "go.mod", "settings.gradle",
                       "requirements.txt", "pyproject.toml", "setup.py", "Cargo.toml", "Gemfile"):
                hits["engines"].append(name)
            if low.endswith((".java", ".php", ".cs", ".go", ".py", ".rb", ".rs", ".kt")):
                hits["source_files"] += 1
        if hits["source_files"] > 40:
            break
    if hits["engines"] or hits["source_files"] > 20:
        fail(
            f"信封 branch=website_only 但场内出现源码工程特征（工程文件 {hits['engines'][:3]} / "
            f"源码文件 {hits['source_files']} 个）——源码材料谎报分支=五套硬账/三枪/九人花名册整体旁路"
            "（批三十七材料反查）；核对材料形态后改信封 branch 重跑"
        )


@collect_errors
def check_suspected_closure(run_root: Path, notes: list[str]) -> None:
    """批三十六（红队二轮 P1-8）：suspected-only 收口交叉拦——真洞全判 suspected 既不触发出卷
    也不触发录像的合法摸鱼出口。era≥20261015：全场零 verified 且盘面有 suspected 时，
    每条 suspected 必须带 closed_loop_gap（≥10 字：缺哪个闭环环节），供最丑自报与用户抽验对表。"""
    m = effective_run_date(run_root)
    if not m or m.group(0) < H22_STRICT_ERA:
        return
    if any_verified(run_root):
        notes.append("suspected_closure_skip(has verified)")
        return
    rj = run_root / "reports" / "json"
    bad = []
    n_sus = 0
    for jf in sorted(rj.glob("*.json")) if rj.is_dir() else []:
        data = load_finding_json(jf, "check_suspected_closure")  # 批四十五 B-1：数组根/malformed 明确 fail
        if not data:
            continue
        st = _finding_status(data)  # 批四十五 M31：三键统一
        if st != "suspected":
            continue
        n_sus += 1
        gap = str(data.get("closed_loop_gap") or "").strip()
        if len(gap) < 10:
            bad.append(jf.name)
    if n_sus and bad:
        fail(
            "suspected-only 收口（全场零 verified）但以下 finding 缺 closed_loop_gap（≥10 字："
            "缺哪个闭环环节/为什么不继续打）：" + "、".join(bad[:6])
            + "——判 suspected 不是免出卷免录像的合法终点，缺口须逐链留痕（批三十六）并进最丑自报"
        )
    if n_sus:
        notes.append(f"suspected_closure_ok({n_sus} 条已留缺口账)")


def _visual_env_attempts_ok(run_root: Path) -> tuple[bool, str]:
    """批五十七 W2（用户令「电脑里肯定有浏览器，永远不准免，除非环境搞了六七次都没成功」）：
    visual_available=false 不再认口头自报——须凭 run/visual-env-attempts.json 环境失败账
    （≥6 次真实尝试，每次 when/tool/error 齐全且 error ≥4 字）。无账=声明无效，按有视觉处理。"""
    p = run_root / "run" / "visual-env-attempts.json"
    data = load_json(p) if p.is_file() else None
    if not isinstance(data, dict):
        return False, "缺 run/visual-env-attempts.json"
    atts = data.get("attempts")
    if not isinstance(atts, list):
        return False, "attempts 不是数组"
    good = 0
    for a in atts:
        if not isinstance(a, dict):
            continue
        when = str(a.get("when", "")).strip()
        tool = str(a.get("tool", "")).strip()
        err = str(a.get("error", "")).strip()
        if when and tool and len(err) >= 4:
            good += 1
    if good < 6:
        return False, f"有效尝试仅 {good} 条（须 ≥6，每条 when/tool/error 齐全且 error ≥4 字）"
    return True, f"{good} 次环境搭建失败账在场"


@collect_errors
def check_visual_claim_consistency(run_root: Path, notes: list[str]) -> None:
    """批三十六（红队二轮 P2-13#1，draft batch31 P2#1 合入）：visual_available:false 自我声明
    交叉验证——声明全场无浏览器的场，盘面不得同时存在浏览器截图或 in_run=available。
    批五十七 W2：声明还须凭环境失败账，口头自报不再收。"""
    env = envelope(run_root)
    if is_static_only(env) or env.get("visual_available") is not False:
        return
    ok, detail = _visual_env_attempts_ok(run_root)
    if not ok:
        fail(
            "信封 visual_available=false 是口头自报——电脑默认有浏览器，无视觉豁免须凭证据："
            "run/visual-env-attempts.json 落 ≥6 次真实环境搭建失败尝试（每次 when/tool/error，"
            "error ≥4 字写实原因）。当前" + detail + "，缺账=声明无效按有视觉处理"
            "（批五十七 W2，用户令「永远不准免，除非环境搞了六七次都没成功，诚实说明情况」）；"
            "纯静态场请落 static_only 分支而非此键"
        )
        return
    contradictions = []
    for p in capability_files(run_root):
        data = load_json(p) or {}
        if str(data.get("screenshot_capture_in_run") or "").lower() == "available":
            contradictions.append(str(p.relative_to(run_root)).replace("\\", "/") + ":screenshot_capture_in_run=available")
    cap_dir = run_root / "run" / "captures"
    if cap_dir.is_dir() and any(p.suffix.lower() in IMAGE_EXT and is_real_image(p) for p in cap_dir.rglob("*")):
        contradictions.append("run/captures/ 存在真图")
    idx = load_json(run_root / "run" / "captures-index.json") or {}
    urls = idx.get("address_bar_urls") if isinstance(idx.get("address_bar_urls"), dict) else {}
    if any(isinstance(v, str) and v.startswith("http") for v in urls.values()):
        contradictions.append("captures-index.address_bar_urls 已登记实拍 URL")
    if contradictions:
        fail(
            "信封声明 visual_available=false（全场无浏览器）但盘面矛盾：" + "；".join(contradictions[:4])
            + "——自我声明豁免录像/截图义务须与盘面一致（批三十六）；确有浏览器就删掉该声明走正常义务"
        )
    notes.append("visual_claim_consistent")


def _official_finding_docxs(run_root: Path) -> list[Path]:
    """批四十五 B-11：正位 finding 卷=reports/ 下全部 docx（rglob），合法子目录
    （revisions/discarded/json/packs）除外——旧版顶层 glob 让 reports/hidden/secret.docx
    逃 8 块/附图/五改/交付包计数全部检查。"""
    rep = run_root / "reports"
    if not rep.is_dir():
        return []
    out: list[Path] = []
    for p in sorted(rep.rglob("*.docx")):
        rel = p.relative_to(rep).parts
        if rel and any(seg in {"revisions", "discarded", "json", "packs"} for seg in rel[:-1]):
            continue
        out.append(p)
    return out


@collect_errors
def check_era_vs_closure_ledger(run_root: Path, notes: list[str]) -> None:
    """批四十五（B-3）era 外部锚：era 唯一锚=目录名日期，整树改名+utime 全回拨可把全部
    era≥20261015/16 机械拦静默降级（utime 伪造无法用文件态彻底堵）。外部锚：收口总账
    （批四十起 close passed 会追加的 closure-ledger.jsonl——数据根（CAOCAO_LEDGER_ROOT 或包根）
    与 run_root 祖先 library 账两处都读）——同 target_identity 或同 run_root 目录名（剥日期段）
    存在更晚日期的既往收口条目 = 目录名日期被回拨，fail 挂起。
    读不到账/无匹配且 era<20261016 时回执记 era_anchor_note（残余风险可见化）。
    只加外部锚，不加自检条文（批三十九战略）。"""
    m = effective_run_date(run_root)
    if not m or m.group(0) == "99999999":
        return
    claimed = m.group(0)
    ledger_paths = [Path(os.environ.get("CAOCAO_LEDGER_ROOT") or str(Path(__file__).resolve().parent.parent / "closure-ledger.jsonl"))]
    _lib = next((p for p in [run_root, *run_root.parents] if p.name == "library"), None)
    if _lib is not None and (_lib / "closure-ledger.jsonl") not in ledger_paths:
        ledger_paths.append(_lib / "closure-ledger.jsonl")
    target = str(envelope(run_root).get("target_identity") or "").strip()
    stem = re.sub(r"20\d{6}", "", run_root.name).strip("-_ ")
    saw_match = False
    for ledger_p in ledger_paths:
        if not ledger_p.is_file():
            continue
        for line in ledger_p.read_text(encoding="utf-8", errors="ignore").splitlines():
            try:
                row = json.loads(line)
            except Exception:
                continue
            if not isinstance(row, dict):
                continue
            old_rr = str(row.get("run_root") or "")
            # 批五十一（G-R2-14 自锁修复，r18 e2e 实锤）：跳过本场自己的账行——
            # 「昨开今收」合法场第一次 close 写账后，重跑 close/--verify-close 不得被自己的账拦死。
            # 改名降级场路径已变，不会命中本豁免（豁免只认路径全等）
            if old_rr and run_root.is_absolute():
                try:
                    if Path(old_rr).resolve() == run_root.resolve():
                        continue
                except OSError:
                    if old_rr == str(run_root):
                        continue
            old_target = str(row.get("target_identity") or "").strip()
            old_stem = re.sub(r"20\d{6}", "", Path(old_rr).name).strip("-_ ") if old_rr else ""
            same = (target and old_target and target == old_target) or bool(stem and old_stem and stem == old_stem)
            if not same:
                continue
            cm = re.search(r"(20\d{2})-?(\d{2})-?(\d{2})", str(row.get("closed_at") or ""))
            if not cm:
                continue
            closed_d = cm.group(1) + cm.group(2) + cm.group(3)
            if closed_d > claimed:
                saw_match = True
                fail(
                    f"era 与收口总账矛盾（疑似目录改名降级，批四十五 B-3）：本场目录名声称 {claimed}，"
                    f"但总账里同 target/目录（{Path(old_rr).name or old_target}）已于 {closed_d} 收口——"
                    "更晚日期的既往收口条目在场=目录名日期被回拨；按真实日期改名后重跑"
                )
    if not saw_match and claimed < "20261016":
        notes.append(
            f"era_anchor_note(era={claimed}<20261016 且收口总账无同 target/目录既往条目——"
            "utime 伪造残余风险：本检查只锚外部账，改目录名+回拨 mtime 仍可能降级存量场，用户对账)"
        )


@collect_errors
def check_packs(run_root: Path, notes: list[str]) -> None:
    """批三十六（红队二轮 P2-13#3，draft batch31 P2#3 合入）：交付包机械检查——
    RF-PKG-01「每漏洞一个独立 zip」此前纯条文且未定落点。落点定死 reports/packs/；
    era≥20261015：有正位 finding 卷的场 close 必须有对应数量的交付包，
    每包须含 README、PDF 副本、可执行 PoC/脚本件（zipfile 列目录，不展开内容）。"""
    import zipfile as _zp

    m = effective_run_date(run_root)
    if not m or m.group(0) < H22_STRICT_ERA:
        return
    reports = run_root / "reports"
    # 批四十五 B-11：子目录 docx 一并计数（reports/hidden/*.docx 逃检口径统一）
    finding_docxs = [f for f in _official_finding_docxs(run_root) if not is_summary_docx(f.name)]
    n_finding = len(finding_docxs)
    if n_finding == 0:
        notes.append("packs_skip(no finding docx)")
        return
    packs = reports / "packs"
    zips = sorted(packs.glob("*.zip")) if packs.is_dir() else []
    if not zips:
        fail(
            f"有 {n_finding} 份正位 finding 卷但 reports/packs/ 无交付包——RF-PKG-01 每漏洞一个独立 zip"
            "（批三十六机械拦：落点 reports/packs/<项目>-<漏洞标识>.zip）"
        )
        return
    # 批四十五 B-5：zip 数量必须等于 finding 卷数——同一 zip 复制 N 份改名充 N 个洞的包在此被拦
    if len(zips) != n_finding:
        fail(
            f"正位 finding 卷 {n_finding} 份但交付包 {len(zips)} 个（reports/packs/）——"
            "数量必须一一对应（RF-PKG-01/02 每漏洞一个独立 zip；复制凑数/缺包都拦，批四十五 B-5）"
        )
    # 批四十五 B-5：对应核——zip 名或卷内 poc/脚本文件名与 finding 卷名（docx stem/chain_id）
    # 须有子串/token 交集，双向一一对应
    _stem_tokens = {
        fs: {t for t in re.split(r"[-_.\s]+", fs) if len(t) >= 3}
        for fs in (f.stem.lower() for f in finding_docxs)
    }
    _matched: set[str] = set()

    def _zip_hits_finding(id_blob: str, z_stem: str, fs: str) -> bool:
        if fs in id_blob or fs in z_stem or z_stem in fs:
            return True
        z_tokens = {t for t in re.split(r"[-_.\s]+", z_stem) if len(t) >= 3}
        return bool(_stem_tokens[fs] & z_tokens)

    for z in zips:
        try:
            zf = _zp.ZipFile(z)
            names = zf.namelist()
        except Exception as exc:
            fail(f"交付包 {z.name} 打不开（非 zip/损坏）：{exc}")
            continue
        _poc_names = [n for n in names if n.lower().endswith((".py", ".js", ".bat", ".cmd"))]
        _id_blob = (z.stem.lower() + " " + " ".join(_poc_names)).lower()
        _hit_stems = [fs for fs in _stem_tokens if _zip_hits_finding(_id_blob, z.stem.lower(), fs)]
        if not _hit_stems:
            fail(
                f"交付包 {z.name} 与任何正位 finding 卷对不上（zip 名/卷内 poc 文件名与 docx 名"
                "无子串或 token 交集）——同一 zip 复制改名凑数（批四十五 B-5）；"
                "包名/卷内脚本须含 finding 标识（<项目>-<漏洞标识>.zip，漏洞标识=chain_id）"
            )
        _matched.update(_hit_stems)
        low_names = [n.lower() for n in names]
        if not any("readme" in n for n in low_names):
            fail(f"交付包 {z.name} 缺 README（RF-PKG-06 七段审核 POV）")
        # 批六十 G-13（r37：README 只查文件名，一行「见报告」过闸）——读 zip 内 README 文本，
        # 七段特征词 ≥5 命中才算合规（标题/等级/目标/厂商信息/洞是什么/后果/复现）
        _rd_n = next((n for n in names if "readme" in n.lower()), "")
        if _rd_n and m.group(0) >= "20261017":
            try:
                with _zp.ZipFile(z) as _zr60:
                    _rd_txt = _zr60.read(_rd_n).decode("utf-8", errors="ignore")
            except Exception:  # noqa: BLE001
                _rd_txt = ""
            _seg60 = [
                bool(_rd_txt.strip()),
                bool(re.search(r"等级|高危|中危|低危|严重", _rd_txt)),
                bool(re.search(r"目标|官网|http", _rd_txt)),
                bool(re.search(r"厂商|仓库|版本", _rd_txt)),
                bool(re.search(r"洞是什么|漏洞描述|是什么", _rd_txt)),
                bool(re.search(r"后果|危害|影响", _rd_txt)),
                bool(re.search(r"复现|PoC|poc", _rd_txt)),
            ]
            if sum(_seg60) < 5:
                fail(
                    f"交付包 {z.name} 的 README 七段结构不合规（命中 {sum(_seg60)}/7）——"
                    "RF-PKG-06 审核 POV：标题/等级/目标/软件与厂商信息/洞是什么/后果/怎么复现，"
                    "一行「见报告」不算 README（批六十 G-13）"
                )
        if not any(n.endswith(".pdf") for n in low_names):
            fail(f"交付包 {z.name} 缺 PDF 副本（RF-PKG-01/03）")
        if not any(n.endswith((".py", ".js", ".bat")) for n in low_names):
            fail(f"交付包 {z.name} 缺一键 PoC/脚本件（RF-PKG-04 必带；verify.bat 认 RF-PKG-08）")
        # 批三十七（红队三轮 P0-5）+ 批三十八（红队四轮 P1-C/P0-A）：存在≠内容且含词≠合规——
        # 「含 hard_gate+verify-close 即跳检」的短路可被注释带词绕过（@echo off + rem hard_gate verify-close），
        # 三硬串改逐一必须；verify.bat 还须含 certutil 对 hard_gate.py 的哈希自打印行
        # （RF-PKG-08 第 -1 条：用户先对照开局外发的闸哈希再跑重验——信任根外置到聊天记录）
        for n in names:
            low = n.lower()
            if not low.endswith((".bat", ".cmd")):
                continue
            body = zf.read(n).decode("utf-8", errors="ignore")
            # 批四十五 B-5：注释行剥除后再做硬串核——关键串全写 rem/:: 注释行的绕过手法
            body = "\n".join(
                ln for ln in body.splitlines() if not re.match(r"^\s*(?:rem\b|::)", ln, re.I)
            )
            missing = [s for s in ("hard_gate.py", "--phase close", "--verify-close") if s not in body]
            has_hashline = ("certutil" in body.lower()) and ("hard_gate.py" in body)
            # 批三十九（红队五轮 P0-3）：verify.bat 须同时提示对照 canonical 根——开局外发值
            # 对「开局前改闸」自洽（外发的就是假闸哈希），canonical（用户保管）才是闸外对照物
            if _b39_era(run_root) and has_hashline and "gates-canonical" not in body:
                fail(
                    f"交付包 {z.name}/{n} 的哈希自打印行缺 canonical 对照提示"
                    "（须含 gates-canonical 字样——开局外发值防不了开局前改闸，"
                    "canonical 根才防，批三十九 RF-PKG-08）"
                )
            if missing or not has_hashline:
                fail(
                    f"交付包 {z.name}/{n} 不像收口重验脚本：缺硬串 {missing}"
                    + ("；缺 certutil 哈希自打印行（RF-PKG-08 第 -1 条：先对照开局外发的闸哈希再跑重验，批三十八）" if not has_hashline else "")
                    + "（空壳/装饰件按包装造假论处）"
                )
        for n in names:
            if not n.lower().endswith(".py"):
                continue
            body = zf.read(n).decode("utf-8", errors="ignore")
            # 批四十五 B-5：# 注释行剥除后再做 PoC 形态核——判定词/用法/目标全写注释的绕过手法
            body = "\n".join(ln for ln in body.splitlines() if not ln.lstrip().startswith("#"))
            has_verdict = ("漏洞成立" in body) or ("未复现" in body) or ("四态" in body)
            has_head = ("用法" in body) or ("判定" in body)
            has_target = ("http" in body.lower()) or ("base_url" in body.lower()) or ("target" in body.lower())
            if not (has_verdict and has_head and has_target):
                fail(
                    f"交付包 {z.name}/{n} 不像一键 PoC：缺判定词（漏洞成立/未复现/四态）、头部用法注释或目标构造"
                    "（RF-PKG-04 四段式：探测→全链→机械判定→四态结论；空壳 print 不构成 PoC，批三十八）"
                )
    # 批四十五 B-5：反向核——每份 finding 卷须有至少一个对应包（3 个 zip 全挤向同一 finding 的缺口）
    _miss_stems = [fs for fs in _stem_tokens if fs not in _matched]
    if _miss_stems:
        fail(
            f"{len(_miss_stems)} 份正位 finding 卷没有对应交付包（{'、'.join(_miss_stems[:3])}）——"
            "每漏洞一包须一一对应（批四十五 B-5）；复制无关 zip 凑数在此被拦"
        )
    notes.append(f"packs_ok({len(zips)} zips)")


@collect_errors
@collect_errors
def check_pdf_content_anchor(run_root: Path, notes: list[str]) -> None:
    """批六十二⑤（摸鱼洞「PDF 形状核撑体积」）：PDF 副本此前只查存在（RF-DOC-07）——
    11 行最小 PDF 壳（%PDF-1.4 + 空 page + xref）即可过「有 PDF」查，体积撑出来也是空的。
    era≥20261017 结构三核（全部 stdlib 可判，不引第三方解析器）：
    ①字节下限：PDF < 8KB = 壳（正常转出卷至少含字体子集与文本流）；
    ②页对象 ≥1 且含 Contents 流（/Contents 缺失 = 无正文页）；
    ③标题锚：解压 FlateDecode 流后卷 stem 的前 8 字（任一编码可判形态）须在流文本出现——
    DOCX 转出的 PDF 必含标题；判不出（流全加密/ exotic 编码）记 note 不硬拦（fail-open 只给真转出件让路）。"""
    import zlib as _z62

    m = effective_run_date(run_root)
    if not m or m.group(0) < "20261017":
        return
    reports = run_root / "reports"
    if not reports.is_dir():
        return
    for docx_p in _official_finding_docxs(run_root):
        pdf_p = docx_p.with_suffix(".pdf")
        if not pdf_p.is_file():
            continue  # 缺 PDF 归 RF-DOC-07 既有核
        raw = pdf_p.read_bytes()
        stem8 = re.sub(r"\s+", "", docx_p.stem)[:8]
        if len(raw) < 8192:
            fail(
                f"PDF 副本 {pdf_p.name} 仅 {len(raw)}B（<8KB）——形状壳撑体积（批六十二⑤）："
                "LibreOffice 转出的正式卷至少含字体子集与文本流；重新转出"
            )
            continue
        if b"/Type /Page" not in raw and b"/Type/Page" not in raw:
            fail(f"PDF 副本 {pdf_p.name} 无页对象——不是文档转出件（批六十二⑤）")
            continue
        # ③ 标题锚：解压流找卷名前缀
        _texts: list[str] = []
        for mm in re.finditer(rb"stream\r?\n(.*?)endstream", raw, re.S):
            try:
                _texts.append(_z62.decompress(mm.group(1)).decode("utf-8", errors="ignore"))
            except Exception:  # noqa: BLE001
                continue
        flow = "".join(_texts)
        if stem8 and stem8 not in flow.replace(" ", ""):
            # 文本流可能是十六进制/转义编码——解码不出就 note（真转出件常见），壳必无 Contents 大流
            if len(flow) > 2000:
                notes.append(f"pdf_title_anchor_unparsed({pdf_p.name}: 流已解压但标题未直出——编码形态，链审复核)")
            else:
                fail(
                    f"PDF 副本 {pdf_p.name} 文本流无卷名前缀「{stem8}」且流体量异常小——"
                    "与 DOCX 非同源（形状核撑体积，批六十二⑤）；重新 LibreOffice 转出"
                )
        else:
            notes.append(f"pdf_content_anchor_ok({pdf_p.name})")


@collect_errors
def check_volume_review(run_root: Path, notes: list[str]) -> None:
    """批六十四（用户令：分身交卷后曹操五样目验，不合格打回重做）。
    era≥20261017 close 硬核：每份正位 finding 卷须有 02-cao-cao/volume-review-<卷stem>.json——
    ①回执在场且 verdict=pass（reject=打回重做中，close 不放行；revised_out 须指向存在的 -rev 新卷）；
    ②回执 mtime 晚于被审卷（先审后改无效）；③五样 checks 全 result=pass（任一非 pass 视同 reject）。
    模板 templates/volume-review.json；五样=复现一致/九要素格式/图表现力/AI 味/残留标记。"""
    m = effective_run_date(run_root)
    if not m or m.group(0) < "20261017":
        return
    cc = run_root / "02-cao-cao"
    for docx_p in _official_finding_docxs(run_root):
        rv = cc / f"volume-review-{docx_p.stem}.json"
        if not rv.is_file():
            fail(
                f"正位卷 {docx_p.name} 缺曹操验卷回执 volume-review-{docx_p.stem}.json（批六十四）——"
                "分身交卷后曹操五样目验（复现一致/九要素格式/图表现力/AI 味/残留标记），"
                "回执落 02-cao-cao/ 且 verdict=pass 才放 close；模板 templates/volume-review.json"
            )
            continue
        data = load_json(rv)
        if not isinstance(data, dict):
            fail(f"验卷回执 {rv.name} 不是合法 JSON（批六十四）")
            continue
        verdict = str(data.get("verdict") or "").strip().lower()
        if verdict == "reject":
            items = data.get("reject_items") or []
            fail(
                f"卷 {docx_p.name} 被曹操验卷打回（reject{('：' + '；'.join(str(i)[:60] for i in items[:3])) if items else ''}）"
                "——分身按 reject_items 重做后曹操复审重落回执（批六十四）"
            )
            continue
        if verdict == "revised_out":
            _nxt = str(data.get("revised_volume") or "")
            if not _nxt or not (run_root / _nxt).is_file():
                fail(f"验卷回执 {rv.name} 标 revised_out 但指向的新卷不存在：{_nxt}（批六十四）")
            continue
        if verdict != "pass":
            fail(f"验卷回执 {rv.name} verdict 非法（{verdict or '缺'}）——只认 pass/reject/revised_out（批六十四）")
            continue
        checks = data.get("checks") if isinstance(data.get("checks"), dict) else {}
        bad = [k for k, v in checks.items() if not (isinstance(v, dict) and str(v.get("result") or "").lower() == "pass")]
        if bad:
            fail(f"验卷回执 {rv.name} verdict=pass 但五样存在非 pass：{','.join(bad)}——应改 verdict=reject 并列 reject_items（批六十四）")
        if rv.stat().st_mtime < docx_p.stat().st_mtime:
            fail(
                f"验卷回执 {rv.name} 早于被审卷 {docx_p.name}（mtime 时序）——先审后改无效，"
                "卷改动后曹操复审重落回执（批六十四）"
            )
        notes.append(f"volume_review_ok({docx_p.stem})")


@collect_errors
def check_baseline_temporal(run_root: Path, notes: list[str]) -> None:
    """批六十 G-03（r38/r37：RF-IMG-05② 基线时序零核——四改⑭只查图注词对，攻击后补拍
    「基线」图注一写就过）。轻核：同目录基线件（名含 baseline/基线/step1/攻击前）mtime
    须早于效果件（attack/效果/step2+）。era≥20261017 场生效；命中对≥1 才核。"""
    m = effective_run_date(run_root)
    if not m or m.group(0) < "20261017":
        return
    cap_dirs = [run_root / "run" / "captures", run_root / "captures"]
    _base = re.compile(r"baseline|基线|step1|攻击前|befor", re.I)
    _eff = re.compile(r"attack|效果|step[2-9]|after|impact", re.I)
    for d in cap_dirs:
        if not d.is_dir():
            continue
        b_files = [p for p in d.iterdir() if p.is_file() and _base.search(p.name)]
        e_files = [p for p in d.iterdir() if p.is_file() and _eff.search(p.name)]
        for b in b_files:
            bt = b.stat().st_mtime
            for e in e_files:
                if e.stat().st_mtime < bt:
                    fail(
                        f"基线时序倒挂：{b.name}（基线）mtime 晚于 {e.name}（效果）——"
                        "RF-IMG-05② 基线图须攻击前实拍，攻击后补拍配「基线」图注在此被拦"
                        "（批六十 G-03 轻核；确属文件整理搬动如实在卷内注明并 git 式留痕）"
                    )
        if b_files and e_files:
            notes.append(f"baseline_temporal_ok({len(b_files)}b/{len(e_files)}e)")


@collect_errors
def check_bypass_vector(run_root: Path, notes: list[str]) -> None:
    """批六十 G-14（r37：RF-SPEC-02 防御对照三件零核——绕过卷必交「之没防的防住了」对比）。
    finding 声明 bypass/绕过/WAFbypass 类（type 或 title 命中）时：卷内文本须含防御对照段
    （词：防御对照|对照组|waf|防火墙|拦截|不拦截 成组出现）。era≥20261017。"""
    m = effective_run_date(run_root)
    if not m or m.group(0) < "20261017":
        return
    rj = run_root / "reports" / "json"
    hits = []
    for jf in sorted(rj.glob("*.json")) if rj.is_dir() else []:
        data = load_json(jf)
        if not isinstance(data, dict):
            continue
        blob = json.dumps(data, ensure_ascii=False)
        if re.search(r"bypass|绕过|waf", blob, re.I):
            hits.append(jf.stem)
    if not hits:
        notes.append("bypass_vector_na(非绕过卷)")
        return
    # 批六十 G-14 修：finding 名与卷名不必强配对（bypass 词已确认在场，对全部正位卷核；
    # 旧配对逻辑 stem 对不上即静默跳过=漏拦）
    _any_ok = False
    for docx_p in _official_finding_docxs(run_root):
        txt = ""
        try:
            txt = docx_plain_text(docx_p)
        except Exception:  # noqa: BLE001
            continue
        _grp = re.search(r"(防御对照|对照组|阴性对照)", txt) and re.search(r"(拦截|不拦截|防护|waf|WAF|防火墙)", txt, re.I)
        if _grp:
            _any_ok = True
            notes.append(f"bypass_vector_ok({docx_p.stem})")
    if not _any_ok:
        fail(
            "绕过类 finding（bypass/绕过/WAF 命中）但全部正位卷缺防御对照三件（RF-SPEC-02：对照组拦截证据"
            "+实验组绕过证据+差异说明——「之没防的防住了」给审核看；批六十 G-14）"
        )


@collect_errors
def check_image_volume_binding(run_root: Path, notes: list[str]) -> None:
    """批六十三（用户令：录屏/截图细节审查——对照卷内复现步骤看复现的是不是对的）。
    现有链只核「图注↔画面」（claim 是拍图人自写，与卷脱钩）；本核加「图↔卷」一段：
    ①嵌图确认件的机读 key=value 行（RF-GATE-02 批四十起要求的 url=/marker= 类）逐值回卷内
    文本对账——对不上=图拍的与卷写的不是同一条链（拿别链合格图充数在此炸）；
    ②卷内复现步骤请求行 path 全集，须在嵌图确认件族文本至少命中一条（整套图与卷零交集=全错链）；
    ③老格式确认件无 key=value 记 note 不硬拦（存量兼容），写了就必须对。era≥20261017。"""
    m = effective_run_date(run_root)
    if not m or m.group(0) < "20261017":
        return
    docxs = [f for f in _official_finding_docxs(run_root) if not is_summary_docx(f.name)]
    if not docxs:
        return
    vr_dir = run_root / "run" / "vision-reviews"
    if not vr_dir.is_dir():
        return
    confirms: list[str] = []
    for name in sorted(list(vr_dir.glob("*.review.md")) + list(vr_dir.glob("*.gate.json"))):
        try:
            head = name.read_text(encoding="utf-8", errors="ignore")[:600]
        except OSError:
            continue
        if verdict_ok_in(head):
            try:
                confirms.append(name.read_text(encoding="utf-8", errors="ignore"))
            except OSError:
                continue
    if not confirms:
        return  # 零确认件由 evidence_ok 硬门负责，本核不重复拦
    _kv_pat = re.compile(r"(?m)^\s*[-*]?\s*(url|path|route|marker|total|count|endpoint)\s*[=:]\s*(\S{2,150})", re.I)
    blob = "\n".join(confirms)
    for docx_p in docxs:
        try:
            text = docx_plain_text(docx_p)
        except Exception:  # noqa: BLE001
            continue
        problems: list[str] = []
        # ① 确认件 key=value 逐值回卷
        kv_hits = 0
        for k, v in _kv_pat.findall(blob):
            v0 = v.split("?")[0] if k.lower() in ("url", "path", "route", "endpoint") else v
            kv_hits += 1
            if v0 not in text:
                problems.append(f"确认件 {k}={v0[:60]} 未出现在卷内文本")
        if kv_hits == 0:
            notes.append(f"image_volume_kv_absent({docx_p.stem}: 确认件族零机读 key=value 行——RF-GATE-02 批四十口径应带 url=/marker= 类锚，链审复核)")
        # ② 卷内请求行 path 至少命中确认件族一条
        vol_paths = [p.split("?")[0] for p in re.findall(r"(?im)^\s*(?:GET|POST|PUT|DELETE|PATCH)\s+(/\S+)", text)]
        if vol_paths and not any(p in blob for p in set(vol_paths)):
            problems.append(
                f"卷内复现步骤的请求行 path（{', '.join(sorted(set(vol_paths))[:3])}）"
                "未在任何嵌图确认件出现——图与卷零交集，疑似拿别链图充数"
            )
        if problems:
            fail(
                f"图与卷脱钩（批六十三 图↔复现步骤细节审查）：{docx_p.name}——"
                + "；".join(problems[:4])
                + "。证据图必须拍的就是卷内写的那条链：确认件 key=value 与卷内复现步骤/请求包逐值对得上"
                "（claim 只对画面不算数，要对卷）"
            )
        else:
            notes.append(f"image_volume_binding_ok({docx_p.stem})")


def check_h24_replays(run_root: Path, notes: list[str]) -> None:
    """批三十七（红队三轮 P1-9）：H-24 抽验落盘机械化——「主会话本场实测逐条跑通」此前纯自述。
    era≥20261015：有正位 finding 卷的场，run/h24-replay/ 须有 ≥卷数条实测记录，
    每条 = .cmd（原样命令全文，须为 --verify-close 重验或 curl/py 实探命令，批三十八落地核）+ 同名 .out（运行输出原件）。
    轻核：只核存在性与形态；内容真伪由用户按 verify.bat 抽验（RF-PKG-08），不假装闸能验内容。"""
    m = effective_run_date(run_root)
    if not m or m.group(0) < H22_STRICT_ERA:
        return
    reports = run_root / "reports"
    # 批四十五 B-11：子目录 docx 一并计数
    n_finding = sum(1 for f in _official_finding_docxs(run_root) if not is_summary_docx(f.name))
    if n_finding == 0:
        notes.append("h24_replays_skip(no finding docx)")
        return
    rd = run_root / "run" / "h24-replay"
    cmds = sorted(rd.glob("*.cmd")) if rd.is_dir() else []
    if not cmds:
        fail(
            f"有 {n_finding} 份正位 finding 卷但 run/h24-replay/ 无实测记录——H-24 三条抽验必须真跑"
            "（每条落 .cmd+.out 两件，批三十七）；「已逐条跑通」纯自述不算"
        )
        return
    if len(cmds) < n_finding:
        fail(f"run/h24-replay/ 仅 {len(cmds)} 条实测记录 < 正位卷 {n_finding} 份——每卷至少一条抽验落盘（批三十七）")
    # 批四十五 B-10①：探针/效果类命令须锚定本场真实 host（信封 target/URL + 捕获账
    # address_bar_urls 的 host）——reverify 类闸命令不含 host 属正常，豁免
    _hosts: set[str] = set()
    for _hv in (str(envelope(run_root).get(k) or "").strip() for k in ("target_identity", "target", "url", "base_url")):
        for _hm in re.finditer(r"https?://([^/\s:\"]+)", _hv):
            _hosts.add(_hm.group(1).lower())
    _idx10 = load_json(run_root / "run" / "captures-index.json") or {}
    _urls10 = _idx10.get("address_bar_urls") if isinstance(_idx10.get("address_bar_urls"), dict) else {}
    for _v in _urls10.values():
        if isinstance(_v, str):
            for _hm in re.finditer(r"https?://([^/\s:\"]+)", _v):
                _hosts.add(_hm.group(1).lower())
    for c in cmds:
        body = c.read_text(encoding="utf-8", errors="ignore")
        if len(body.strip()) < 10:
            fail(f"run/h24-replay/{c.name} 空壳（命令行 <10 字）——占位件按 H-21 伪造论处")
        # 批三十八（红队四轮 P2-A）：docstring 承诺落到实现——须是收口重验或可执行复现/验证命令
        is_reverify = ("hard_gate" in body and "--phase" in body) or "--verify-close" in body
        is_probe = any(k in body for k in ("curl ", "Invoke-WebRequest", "http://", "https://")) or body.strip().startswith(("py -3", "python", "node "))
        if not (is_reverify or is_probe):
            fail(f"run/h24-replay/{c.name} 不像实测命令（echo done 类占位）——须为 --verify-close 重验或 curl/py 实探命令（批三十八）")
        if not is_reverify and _hosts and re.search(r"https?://", body, re.I) and not any(h in body.lower() for h in _hosts):
            fail(
                f"run/h24-replay/{c.name} 不含信封/捕获账里的真实 host（{'、'.join(sorted(_hosts)[:3])}）"
                "——命令与本场目标无关（批四十五 B-10①；带 URL 的探针/效果命令须锚定本场 host，"
                "本地读回/脚本类命令不要求）"
            )
        out_p = c.with_suffix(".out")
        if not out_p.is_file() or out_p.stat().st_size < 10:
            fail(f"run/h24-replay/{c.name} 缺 .out 输出原件——只留命令不留运行结果不算实测（批三十七）")
    # 批四十五 B-10③：各条 .out 内容不得互相相同——复制同一输出充三类实测在此被拦
    _seen_out: dict[str, str] = {}
    for c in cmds:
        out_p = c.with_suffix(".out")
        if not out_p.is_file():
            continue
        _key = out_p.read_text(encoding="utf-8", errors="ignore").strip()
        if _key in _seen_out:
            fail(
                f"run/h24-replay/ 的 {_seen_out[_key]} 与 {out_p.name} 输出内容完全相同——"
                "复制输出充数（批四十五 B-10③）；环境探针/攻击效果/真值读回须各自真跑"
            )
        _seen_out[_key] = out_p.name
    # 批四十（红队六轮 P1-6，batch31 #5 兑现）：三条构成机械核——此前只查「≥卷数条+形态像命令」，
    # N 条 curl http://127.0.0.1/ 即全绿；「环境探针/攻击效果/真值读回」三类各 ≥1，
    # 且「效果」条的主段（URL/载荷核心串）须逐字出现在正位 DOCX 文本（命令与卷绑定，防拿无关探针凑数）。
    if _b39_era(run_root):
        probe_words = ("version", "health", "actuator", "env", "tasklist", "netstat", "java -", "dir ", "ls ", "端口")
        readback_words = ("cat ", "type ", "select ", "mysql", "redis", "grep ", "findstr", "读回", "marker", "tail ")
        n_probe = n_read = n_effect = 0
        docx_text = ""
        for f in sorted((run_root / "reports").glob("*.docx")):
            if is_summary_docx(f.name):
                continue
            try:
                docx_text += docx_plain_text(f)  # 批四十二：URL 跨 run 拆段假阴性（诚实卷被误 fail）
            except Exception:  # noqa: BLE001
                continue
        for c in cmds:
            body = c.read_text(encoding="utf-8", errors="ignore").lower()
            # 批五十六 F-r29-4：效果类优先——URL 命中正位 DOCX 的条目先归效果
            #（诚实效果条带输出过滤管道 curl…|findstr 曾被 readback 词表抢分类，四条全真跑仍报缺效果）
            _mu56 = re.search(r'https?://[^\s"\'<>]+', c.read_text(encoding="utf-8", errors="ignore"))
            _url56 = _mu56.group(0).split("?")[0] if _mu56 else ""
            if _url56 and docx_text and _url56 in docx_text:
                n_effect += 1
                continue
            if any(w in body for w in probe_words):
                n_probe += 1
            elif any(w in body for w in readback_words):
                n_read += 1
                # 批四十五 B-10②：读回类 .out 须含对应 .cmd 行中出现的 marker 词——
                # 读回输出与命令对不上的手写件在此被拦（抬高门槛不求语义执行）
                _cmd_raw = c.read_text(encoding="utf-8", errors="ignore")
                _out_p2 = c.with_suffix(".out")
                _out_txt = _out_p2.read_text(encoding="utf-8", errors="ignore") if _out_p2.is_file() else ""
                _toks = set(re.findall(r"\b[A-Z][A-Z0-9_\-]{3,}\b", _cmd_raw))
                if re.search(r"marker", _cmd_raw, re.I):
                    _toks.add("marker")
                if _toks and not any(t.lower() in _out_txt.lower() for t in _toks):
                    fail(
                        f"run/h24-replay/{c.name} 读回类命令的 .out 不含命令中出现的 marker 词"
                        f"（{'、'.join(sorted(_toks)[:4])}）——读回输出与命令对不上（批四十五 B-10②）"
                    )
                # 批四十二：含 http 的读回类命令同样做 DOCX 交叉——攻击效果命令带 select（SQL 注入类）
                # 会落本类，漏交叉=拿无关探针凑「效果」条的口子
                if "http" in body:
                    mu = re.search(r'https?://[^\s"\'<>]+', c.read_text(encoding="utf-8", errors="ignore"))
                    if mu and docx_text and mu.group(0).split("?")[0] not in docx_text:
                        fail(
                            f"run/h24-replay/{c.name} 含 URL 但其目标未出现在任何正位 DOCX 文本"
                            "——抽验命令与卷对不上（批四十 P1-6/批四十二扩）"
                        )
                    # 批六十二④（摸鱼洞「读回件锚」，era≥20261017）：读回 .out 的关键值须回卷内出现——
                    # 自编回放件（.cmd/.out 自洽小说）与卷完全脱钩在此炸：out 中引号内长串/数字结果段
                    # 若在卷内与 cmd 双双查无，判定为「与卷无关的回放件」
                    _m62d = effective_run_date(run_root)
                    if _m62d and _m62d.group(0) >= "20261017" and docx_text and _out_txt:
                        _hits62 = sum(1 for ln in _out_txt.splitlines() if len(ln.strip()) >= 8 and ln.strip()[:40] in docx_text)
                        if _hits62 == 0 and "总" not in _out_txt[:50]:
                            fail(
                                f"run/h24-replay/{_out_p2.name} 读回输出与卷零重合（批六十二④）——"
                                ".out 至少一行关键内容（≥8 字行首 40 字）须出现在正位卷文本："
                                "自编回放件与真值读回无法区分时按伪造嫌疑处理"
                            )
            else:
                n_effect += 1
                mu = re.search(r'https?://[^\s"\'<>]+', c.read_text(encoding="utf-8", errors="ignore"))
                if mu and docx_text and mu.group(0).split("?")[0] not in docx_text:
                    fail(
                        f"run/h24-replay/{c.name} 是攻击效果条但其目标 URL 未出现在任何正位 DOCX 文本"
                        "——抽验命令与卷对不上（拿无关探针凑 H-24 在此被拦，批四十 P1-6）"
                    )
        miss = (["环境探针"] * (n_probe == 0)) + (["攻击效果"] * (n_effect == 0)) + (["真值读回"] * (n_read == 0))
        if miss:
            fail(
                "H-24 抽验三条构成不齐（批四十 P1-6）：缺 " + "、".join(miss)
                + "——环境探针/攻击效果/真值读回各 ≥1（H-24 原文构成，batch31#5 兑现）；N 条同型 curl 凑数不算"
            )
    notes.append(f"h24_replays_ok({len(cmds)})")


def phase_close(run_root: Path) -> None:
    notes: list[str] = []
    env = envelope(run_root)
    # 2026-10-15 批二十五：信封 branch × 盘面矛盾交叉——website_only 场不该有 01-guo-jia/（website 花名册无郭嘉），
    # 信封误写会把源码场的五套硬账/三枪/九人目录检查全部静默跳过（fail-open），此前无拦。
    if is_website(env) and (run_root / "01-guo-jia").is_dir():
        fail(
            "信封 branch/input_scope_kind=website_only 却存在 01-guo-jia/ 目录——branch 写错会把源码场硬账静默跳过；"
            "核对信封后重跑（源码场应写 local_source/source_and_website）"
        )
    if not is_website(env) and (run_root / "01-guo-jia").is_dir():
        check_three_shots(run_root, notes)
        check_captures(run_root, notes)
        check_cao_chong(run_root, notes)
        check_sink_runtime(run_root, notes)
        check_component_cve(run_root, notes)
        check_cve_in_range_conclusion(run_root, notes)
        check_keyword_scan(run_root, notes)
        check_auto_chain_scan(run_root, notes)
        check_hybrid_discovery(run_root, notes)
        check_methodology_gap(run_root, notes)
    check_branch_material_cross(run_root)  # 批三十七 P0-2：源码材料谎报 website_only 对称拦（批四十一扩两键一致性核）
    check_era_sanity(run_root, notes)  # 批四十一：close 也挂（此前仅 env 非 website 路径——env 没跑过/website 场零防线）
    check_era_vs_closure_ledger(run_root, notes)  # 批四十五 B-3：era 外部锚（收口总账矛盾=目录改名降级，fail 挂起）
    check_in_run(run_root, notes)
    check_complex_video(run_root, notes)
    check_recording_integrity(run_root, notes)
    check_obfuscation(run_root, notes)
    check_verified_evidence(run_root, notes)
    check_severity_floor(run_root, notes)  # 批三十五 P1-6：H-26 级别下限（防自降级逃必录）
    check_bec_if_yujin(run_root, notes)
    check_source_roster(run_root, notes)
    check_sima_web_duty(run_root, notes, phase_close=True)
    check_pending_visual_not_empty(run_root, notes, phase_close=True)
    check_envelope_progress(run_root, notes)
    check_open_plan(run_root, notes)
    check_named_surfaces(run_root, notes)
    check_reports(run_root, notes)
    check_shadow_delivery_verdict(run_root)
    check_cors_audit(run_root, notes)
    check_sima_isolation(run_root, notes)
    run_credential_scan(run_root, notes)
    check_vision_report_images(run_root, notes)
    check_run_artifacts_consumption(run_root, notes)  # 批四十九（r18 R3-E）：确认件消费 + 派发回执闭环
    check_wugai_report_standard(run_root, notes)
    check_reports_after_receipt(run_root, notes)
    check_alarm_account(run_root, notes)
    check_runner_model(run_root, notes)
    check_verified_disposition(run_root, notes)
    check_tool_baseline(run_root, notes)
    check_finding_source_refs(run_root, notes)
    check_canonical_root(run_root, notes)  # 批三十九 P0-3：收口再比对 canonical（收口前改闸也炸）
    check_process_provenance(run_root, notes)  # 批三十九 P0-1：运行工件↔材料清单绑定（堵假服务）
    check_official_source_probe(run_root, notes)  # 批三十九 P0-2：官方源真下载外部锚（堵开局前注毒）
    check_dedup_route_compare(run_root, notes)  # 批三十九 P1-2：判重 route_compare 机械件
    check_visual_false_replay(run_root, notes)  # 批三十九 P1-3：无视觉场 curl GET 在线抽验
    check_closure_stats(run_root, notes)  # 批三十九 P2：low_coverage 亮灯 + simple 多步弱核（批四十扩降级理由/确认件/js 锚弱核）
    check_material_snapshot(run_root, notes)  # 批四十 P0-2b：目录材料快照账/waiver 二选一
    check_cross_session_reuse(run_root, notes)  # 批四十 P0-3：跨场素材摘要比对（整场复读核）
    check_dedup_origin_query(run_root, notes)  # 批四十 P1-4：原创声明查询义务 + 查询词弱核
    check_route_path_coverage(run_root, notes)  # 批四十 P1-5：接口清单 path 级覆盖核（batch31#7 升格）
    check_ledger_tool_trace(run_root, notes)
    check_suspected_closure(run_root, notes)  # 批三十六 P1-8：suspected-only 交叉拦
    check_visual_claim_consistency(run_root, notes)  # 批三十六 P2-13#1
    check_packs(run_root, notes)  # 批三十六 P2-13#3：交付包机械检查
    check_material_provenance(run_root, notes)  # 批三十七 P0-3：清单覆盖面+原档双账
    check_h24_replays(run_root, notes)  # 批三十七 P1-9：H-24 抽验落盘
    check_cve_replay(run_root, notes)  # 批三十八 P1-A：查询原件机械重放
    check_baseline_temporal(run_root, notes)  # 批六十 G-03：基线件时序核
    check_bypass_vector(run_root, notes)  # 批六十 G-14：绕过卷防御对照三件核
    check_pdf_content_anchor(run_root, notes)  # 批六十二⑤：PDF 副本内容锚
    check_volume_review(run_root, notes)  # 批六十四：曹操五样验卷回执
    check_image_volume_binding(run_root, notes)  # 批六十三：图↔卷内复现步骤细节审查
    ok("close", notes)
    stamp_test_session(run_root)
    write_closure_ledger(run_root)


@collect_errors
def check_runner_model(run_root: Path, notes: list[str]) -> None:
    # 2026-10-09 深挖条款第 18 条升格（用户口径「还是限制吧」）：信封必记运行模型从记号改硬闸。
    # 生效线 20261010：10-09 当天已开的在飞四场（sa-token/rustdesk/hutool/mcms，条文 09 点后落、它们 08 点开）
    # 不追溯；建议各自主会话主动补键，但闸不拦。
    m = effective_run_date(run_root)
    if not m or m.group(0) < "20261010":
        return
    # 2026-10-15 修复批十九：选取口径与 stamp M3 对齐——「第一个能解析出内容的」，
    # 防 run/envelope.json 坏档时检查读坏文件误 fail、盖章却写对地方（A3 修的另一半）
    ts = None
    data = None
    for cand in envelope_paths(run_root):
        if not cand.is_file():
            continue
        d = load_json(cand)
        if d:
            ts, data = cand, d
            break
    if ts is None:
        return  # 信封整体缺失由既有检查拦，这里不重复报
    if not isinstance(data, dict) or not data.get("runner_model"):
        fail("2026-10-09 起场次信封必须记 runner_model（主会话运行模型，如 glm-5.3 / glm-5.3-flash；换模型续场追加 runner_model_history）——模型问题画像靠它机械对账")
    notes.append("runner_model_ok")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-root", required=True)
    parser.add_argument("--phase", required=True, choices=("env", "verify", "close"))
    parser.add_argument(
        "--verify-close",
        action="store_true",
        help="重验收口（H-23/H-25 机械件，批三十四）：全量重跑 close 后比对既有回执防伪指纹"
        "（gate_sha256/scene_digest/tool_baseline_at_close），缺字段或不符 = 手写回执/收口后改动，fail",
    )
    args = parser.parse_args()
    # 批五十三（摸鱼 v2 新洞）：resolve() 绝对化——相对路径（--run-root .）使 Path.name==""
    # → era=99999999 早退，回拨核+run_date 双对账整段蒸发（旧日期目录实测过闸）
    run_root = Path(args.run_root).resolve()
    global PHASE, RUN_ROOT
    PHASE = args.phase
    if args.verify_close and args.phase != "close":
        print(json.dumps({"status": "failed", "reason": "--verify-close 必须搭配 --phase close"}, ensure_ascii=False, indent=2))
        raise SystemExit(2)
    if not run_root.is_dir():
        print(json.dumps({"status": "failed", "reason": f"run_root missing: {run_root}"}, ensure_ascii=False, indent=2))
        raise SystemExit(1)
    RUN_ROOT = run_root
    old_receipt = load_json(run_root / "run" / "hard-gate-close.json") if args.verify_close else None
    if args.phase == "env":
        phase_env(run_root)
    elif args.phase == "verify":
        phase_verify(run_root)
    else:
        phase_close(run_root)
        if args.verify_close:
            verify_close_receipt(run_root, old_receipt)


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except GateFailure:
        emit_failures()
    except Exception as exc:  # noqa: BLE001
        print(json.dumps({"status": "failed", "reason": str(exc)}, ensure_ascii=False, indent=2))
        sys.exit(1)
