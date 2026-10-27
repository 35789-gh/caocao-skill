#!/usr/bin/env python3
"""hybrid_discovery.py — 源码召回扫描（自包含内置版，无外部依赖）。

分桶顺序跟 Deep：PHP / JavaScript / Ruby 先正则；
Java / Python / Go / C# / Kotlin / Scala / Swift 先向量（本内置版无向量引擎，
自动落 lexical fallback 并在 manifest 落 vector_key_check，不做「已探测」假象）；
混栈 mixed。命中仍是 candidate_only，不是第六套硬账，不能顶 walker。

查询语义跟 v7 DISCOVERY_QUERIES 七条 + Deep 多出来的四句
（request_source / output / validation / resource）。
七条主查询按「输入信号 × 危险汇信号同窗共现」实现；auth_boundary 按
「敏感操作词在场而鉴权词缺席」实现；dangerous_terminal 按调度/导入/恢复词实现。

凭据值不进 jsonl：所有落盘字符串经 redact 递归脱敏。
"""
from __future__ import annotations

import sys

sys.dont_write_bytecode = True  # 禁 pyc 落包目录（包卫生）

import argparse
import json
import os
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from auto_chain_scan import redact_secret_text as REDACT_SECRET_TEXT  # noqa: E402

PKG_ROOT = Path(__file__).resolve().parent.parent
EMBEDDING_ENV = Path(
    os.environ.get("CAOCAO_EMBEDDING_ENV") or str(PKG_ROOT / "secrets" / "embedding.env")
)

REGEX_FIRST_LANGUAGES = {"php", "javascript", "ruby"}
VECTOR_FIRST_LANGUAGES = {"java", "python", "go", "csharp", "kotlin", "scala", "swift"}

TEXT_EXT = {
    ".php", ".inc", ".phtml", ".py", ".pyw", ".java", ".jsp", ".jspx",
    ".js", ".jsx", ".ts", ".tsx", ".vue", ".mjs", ".cjs",
    ".go", ".rb", ".rake", ".cs", ".kt", ".kts", ".scala", ".swift",
}
LANGUAGE_BY_SUFFIX = {
    ".php": "php", ".inc": "php", ".phtml": "php",
    ".py": "python", ".pyw": "python",
    ".java": "java", ".jsp": "java", ".jspx": "java",
    ".js": "javascript", ".jsx": "javascript", ".ts": "javascript",
    ".tsx": "javascript", ".vue": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".go": "go", ".rb": "ruby", ".rake": "ruby",
    ".cs": "csharp", ".kt": "kotlin", ".kts": "kotlin", ".scala": "scala", ".swift": "swift",
}
SKIP_DIR_NAMES = {
    ".git", "vendor", "node_modules", "dist", "build", "target",
    "__pycache__", ".idea", ".vscode", ".venv", "venv", ".gradle",
}
KEEP_READING_DIR_NAMES = {"include", "includes", "inc", "lib", "library", "classes", "class"}

DEEP_NOTE = (
    "召回顺序跟 Deep：PHP/JS/Ruby 先正则；Java/Python/Go/C#/Kotlin/Scala/Swift 先向量；"
    "混栈 mixed。命中只是 candidate，不能顶 walker。"
    "本内置版无向量引擎，vector_first 桶自动落 lexical fallback。"
)

# ---- 输入信号（跨语言通用 + 各栈特有）----
INPUT_RE = re.compile(
    r"(?:\$_(?:GET|POST|REQUEST|COOKIE|FILES)"
    r"|request\.(?:getParameter|getAttribute|getHeader|getInputStream|getParameterValues|getQueryString)"
    r"|@(?:PathVariable|RequestParam|RequestBody|RequestHeader|CookieValue|RequestPart|ModelAttribute)"
    r"|\b(?:req|request|params|query|body|payload|form|input)\b\s*(?:\[|\(|\.)"
    r"|\$_SERVER\[.[A-Z]+"
    r"|c\.(?:Param|FormFile|PostForm|Query|GetHeader)"
    r"|req\.(?:query|params|body|headers|files)"
    r"|file_get_contents\s*\(\s*['\"]php://input|json_decode\s*\(\s*\$"
    r")",
    re.I,
)
# ---- 危险汇信号（按查询分族）----
SINK_SQL_RE = re.compile(
    r"(?:->\s*(?:query|exec|execute|createCommand|raw)\s*\("
    r"|(?:executeQuery|executeUpdate|createQuery|createSQLQuery|createNativeQuery)\s*\("
    r"|(?:SELECT|INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM)\b[^;\n]{0,120}(?:\$\{|\"?\s*\.\s*\$|%\s*s|\+\s*\w+)"
    r"|\b(?:Db|db|PDO|mysqli)::?query"
    r"|db\.(?:raw|rawQuery|statement)\s*\("
    r"|order\s*by\s*\$\{|group\s*by\s*\$\{|\$\{(?:table|column|order|sort|field)\w*\}"
    r")",
    re.I,
)
SINK_FILE_RE = re.compile(
    r"(?:file_put_contents|file_get_contents|fopen|fwrite|move_uploaded_file"
    r"|\bFiles?\.(?:write|copy|move|delete|readAllBytes|newInputStream|newOutputStream)"
    r"|\b(?:unlink|rename|copy|mkdir|rmdir)\s*\("
    r"|ZipArchive|ZipInputStream|extractAll|extractTo\s*\("
    r"|\binclude\s*\(?\s*\$|\brequire\s*\(?\s*\$|include_once\s*\(?\s*\$|require_once\s*\(?\s*\$)",
    re.I,
)
SINK_CMD_RE = re.compile(
    r"(?:Runtime\.getRuntime\s*\(\s*\)\s*\.exec|ProcessBuilder"
    r"|\b(?:system|shell_exec|passthru|popen|proc_open|pcntl_exec)\s*\("
    r"|\bexec\s*\(\s*['\"]|subprocess\.(?:run|call|Popen|check_output)"
    r"|os\.(?:system|popen|execv?)\s*\(|\bchild_process\b|child_process"
    r"|\`\s*\$\{?\w"
    r")",
    re.I,
)
SINK_PARSER_RE = re.compile(
    r"(?:ObjectInputStream|readObject\s*\(|XMLDecoder|XStream|fromXML"
    r"|pickle\.loads?|yaml\.load\s*\(|unserialize\s*\("
    r"|SpelExpressionParser|ScriptEngine|GroovyShell|VelocityEngine|freemarker"
    r"|fastjson|JSON\.parseObject|readValue\s*\(|kryo|readUnshared"
    r")",
    re.I,
)
SINK_NET_RE = re.compile(
    r"(?:HttpURLConnection|OkHttpClient|RestTemplate|WebClient\.create|HttpClient"
    r"|\bcurl_exec|file_get_contents\s*\(\s*\$"
    r"|(?:requests|httpx|urllib)\.(?:get|post|request)\s*\("
    r"|new\s+URI\s*\("
    r"|sendRedirect\s*\(\s*\$"
    r")",
    re.I,
)
AUTH_ABSENT_RE = re.compile(
    r"\b(?:authorize|authorization|permission|accesscontrol|tenant|allowlist|whitelist"
    r"|sanitize|validate|verify|checkauth|islogin|getcurrentuser|preauthorize|filter)\b",
    re.I,
)
SENSITIVE_OP_RE = re.compile(
    r"(?:@(?:DeleteMapping|PutMapping|PostMapping)"
    r"|\b(?:delete|remove|drop|truncate|reset|pay|refund|approve|export|download|grant|assign)\w*\s*\("
    r"|\badmin\b|superuser|/user/|/order/|/system/)",
    re.I,
)
TERMINAL_RE = re.compile(
    r"(?:@(?:Scheduled|KafkaListener|RabbitListener|JmsListener|EnableScheduling)"
    r"|\bcrontab\b|TaskScheduler"
    r"|\b(?:import|restore|backup|migrate|seed)\w*\s*\("
    r"|quartz|xxl-job|XxlJob|delayqueue|blockingqueue"
    r"|Artisan::|artisan\s+\w+|console\s+command"
    r")",
    re.I,
)
COMMENT_ONLY_RE = re.compile(r"^(?:\s*(?://|#|/\*|\*|<!--|--)).*$", re.M)
NEGATIVE_CONTEXT_RE = re.compile(r"\b(?:example|sample|fixture|mock|dummy|demo|test)\b", re.I)

CORE_QUERIES: tuple[tuple[str, str, re.Pattern[str]], ...] = (
    ("input_to_sql", "user controlled input reaches SQL query, ORM dynamic SQL, table, column, or sort expression", SINK_SQL_RE),
    ("input_to_file", "request data reaches file write, upload, archive extraction, download, or path operation", SINK_FILE_RE),
    ("input_to_command", "request data reaches command execution, shell, process, script, or interpreter", SINK_CMD_RE),
    ("input_to_parser", "request data reaches deserialization, template rendering, dynamic code execution, or expression evaluation", SINK_PARSER_RE),
    ("input_to_network", "request data reaches an outbound URL request, HTTP client, redirect, or server-side fetch", SINK_NET_RE),
)

# Deep DISCOVERY_QUERIES 多出来的四句，Mini lexical 补面（保留原口径）。
DEEP_EXTRA_QUERIES: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    (
        "request_source",
        "external request data enters a handler through parameters, forms, bodies, cookies, headers, or uploads",
        (
            "parameter", "param", "form", "body", "cookie", "header", "upload",
            "getparameter", "requestmapping", "pathvariable", "querystring",
            "$_get", "$_post", "$_request", "$_files", "params", "query",
        ),
    ),
    (
        "output",
        "request-controlled data reaches HTML rendering, a template, a response, the DOM, innerHTML, or document output",
        (
            "innerhtml", "v-html", "dangerouslysetinnerhtml", "mark_safe",
            "echo", "printf", "print", "render", "template", "response",
            "writevalueasstring", "setcontenttype", "document.write", "html",
        ),
    ),
    (
        "validation",
        "request data passes through validation, filtering, sanitization, an allowlist, or a regular expression",
        (
            "validate", "validation", "valid", "sanitize", "sanitiz",
            "filter", "allowlist", "whitelist", "blacklist", "escape",
            "purifier", "xssfilter", "sqlfilter", "check", "verify", "pattern",
        ),
    ),
    (
        "resource",
        "request-controlled data controls a loop, decompression, archive expansion, allocation, or resource limit",
        (
            "zip", "unzip", "decompress", "gzip", "tar", "archive",
            "zipinputstream", "zipfile", "shutil", "extractall", "inflate",
            "alloc", "limit", "quota", "maxlength", "batch", "bulk",
        ),
    ),
)

MAX_HITS_PER_QUERY = 40
MAX_TOTAL_HITS = 300
MAX_FILES = 2000
MAX_FILE_BYTES = 400_000
CHUNK_LINES = 80
_TRUNCATED = {"scan": False}


def parse_jsonl(text: str) -> list[dict]:
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


def keyword_hits(blob: str, keywords: tuple[str, ...]) -> list[str]:
    low = blob.lower()
    return [kw for kw in keywords if kw in low]


def redact_object(obj):
    """递归脱敏所有字符串字段；凭据值不进 jsonl。"""
    if isinstance(obj, dict):
        return {k: redact_object(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [redact_object(v) for v in obj]
    if isinstance(obj, str):
        return REDACT_SECRET_TEXT(obj)
    return obj


def _skip_dir(name: str) -> bool:
    low = name.lower()
    if low in KEEP_READING_DIR_NAMES:
        return False
    return low in SKIP_DIR_NAMES


def embedding_key_status() -> dict:
    """内置版不打向量：不探测密钥、不产生「已探测」假象，如实记 not_checked。"""
    env_set = bool(os.environ.get("EMBEDDING_API_KEY"))
    file_present = EMBEDDING_ENV.is_file()
    return {
        "key_present": None,
        "verdict": "not_checked",
        "env_var": "set" if env_set else "unset",
        "env_file": "present" if file_present else "missing",
        "action": (
            "内置版无向量引擎，vector_first 桶已按 lexical fallback 完成；"
            "如需向量召回增强，自备 v7 包后在 tools.json v7_root 登记"
        ),
    }


def iter_targets(root: Path):
    """按 MAX_FILES 上限产出 (path, rel, language, text, lines)。"""
    files_seen = 0
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        try:
            rel_parts = path.relative_to(root).parts
        except ValueError:
            continue
        if any(_skip_dir(part) for part in rel_parts[:-1]):
            continue
        suffix = path.suffix.lower()
        if suffix not in TEXT_EXT:
            continue
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                continue
        except OSError:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        files_seen += 1
        if files_seen > MAX_FILES:
            _TRUNCATED["scan"] = True
            break
        rel = path.relative_to(root).as_posix()
        yield path, rel, LANGUAGE_BY_SUFFIX.get(suffix, "unknown"), text, text.splitlines()


def compact_window(window: list[str], pos: int, n: int = 160) -> str:
    """取命中附近内容做上下文（落盘前仍会整体 redact）。"""
    joined = "\n".join(window)
    begin = max(0, pos - 40)
    return joined[begin : begin + n].replace("\n", " / ")


def scan_root(root: Path) -> tuple[list[dict], dict]:
    """内置 lexical 扫描。返回 (hit_records, manifest_extra)。"""
    hits: list[dict] = []
    seen: set[tuple[str, str, int]] = set()
    per_query_count: dict[str, int] = {name: 0 for name, _i, _s in CORE_QUERIES}
    languages_seen: set[str] = set()
    files_scanned = 0

    for _path, rel, language, _text, lines in iter_targets(root):
        files_scanned += 1
        languages_seen.add(language)
        if not lines:
            continue
        for start in range(0, len(lines), CHUNK_LINES):
            window = lines[start : start + CHUNK_LINES]
            content = "\n".join(window)
            if not content.strip():
                continue
            nonempty = [ln for ln in window if ln.strip()]
            comment_only = bool(nonempty) and all(COMMENT_ONLY_RE.match(ln) for ln in nonempty)
            if comment_only or NEGATIVE_CONTEXT_RE.search(rel):
                continue
            has_input = bool(INPUT_RE.search(content))
            line_start = start + 1
            line_end = min(len(lines), start + CHUNK_LINES)
            if has_input:
                for name, intent, sink_re in CORE_QUERIES:
                    if per_query_count[name] >= MAX_HITS_PER_QUERY:
                        continue
                    m = sink_re.search(content)
                    if not m:
                        continue
                    key = (name, rel, line_start)
                    if key in seen:
                        continue
                    seen.add(key)
                    per_query_count[name] += 1
                    snippet = compact_window(window, m.start())
                    hits.append(
                        {
                            "schema_version": "1.0",
                            "candidate_only": True,
                            "record_type": "discovery_hit",
                            "query_name": name,
                            "intent": intent,
                            "language": language,
                            "file": rel,
                            "line": line_start,
                            "line_end": line_end,
                            "matched": snippet,
                            "status": "candidate",
                            "note": "输入信号×危险汇信号同窗共现；candidate，不是洞",
                        }
                    )
            # auth_boundary：敏感操作词在场而鉴权词整窗缺席
            if SENSITIVE_OP_RE.search(content) and not AUTH_ABSENT_RE.search(content):
                key = ("auth_boundary", rel, line_start)
                if key not in seen:
                    seen.add(key)
                    snippet = compact_window(window, 0)
                    hits.append(
                        {
                            "schema_version": "1.0",
                            "candidate_only": True,
                            "record_type": "discovery_hit",
                            "query_name": "auth_boundary",
                            "intent": "authentication, authorization, permission check, tenant boundary, or access control may be missing or bypassable",
                            "language": language,
                            "file": rel,
                            "line": line_start,
                            "line_end": line_end,
                            "matched": snippet,
                            "status": "candidate",
                            "note": "敏感操作信号在场而鉴权词缺席；candidate，不是洞",
                        }
                    )
            if TERMINAL_RE.search(content):
                key = ("dangerous_terminal", rel, line_start)
                if key not in seen:
                    seen.add(key)
                    snippet = compact_window(window, 0)
                    hits.append(
                        {
                            "schema_version": "1.0",
                            "candidate_only": True,
                            "record_type": "discovery_hit",
                            "query_name": "dangerous_terminal",
                            "intent": "scheduled task, queue, worker, callback, import, restore, configuration, or other dangerous terminal operation",
                            "language": language,
                            "file": rel,
                            "line": line_start,
                            "line_end": line_end,
                            "matched": snippet,
                            "status": "candidate",
                            "note": "调度/队列/导入恢复类终局操作信号；candidate，不是洞",
                        }
                    )
            # Deep 四句 lexical 补面（保留原口径）
            blob = f"{rel} {content}"
            for name, intent, keywords in DEEP_EXTRA_QUERIES:
                matched = keyword_hits(blob, keywords)
                if not matched:
                    continue
                key = (f"deep_{name}", rel, line_start)
                if key in seen:
                    continue
                seen.add(key)
                hits.append(
                    {
                        "schema_version": "1.0",
                        "candidate_only": True,
                        "record_type": "mini_deep_extra_lexical",
                        "query_name": name,
                        "intent": intent,
                        "language": language,
                        "file": rel,
                        "line": line_start,
                        "line_end": line_end,
                        "matched_keywords": matched,
                        "status": "candidate",
                        "note": "Deep 多出来的四句查询，lexical 补面；不能顶 walker",
                    }
                )
    hits.sort(key=lambda r: (str(r.get("query_name")), r.get("file", ""), r.get("line", 0)))
    if len(hits) > MAX_TOTAL_HITS:
        hits = hits[:MAX_TOTAL_HITS]
        _TRUNCATED["scan"] = True
    manifest_extra = {
        "files_scanned": files_scanned,
        "languages_seen": sorted(languages_seen),
        "per_query_counts": per_query_count,
    }
    return hits, manifest_extra


def build_manifest(languages_seen: list[str]) -> dict:
    by_lang: dict[str, str] = {}
    for lang in languages_seen:
        if lang in REGEX_FIRST_LANGUAGES:
            by_lang[lang] = "regex_first"
        elif lang in VECTOR_FIRST_LANGUAGES:
            by_lang[lang] = "vector_first"
    has_regex = any(v == "regex_first" for v in by_lang.values())
    has_vector = any(v == "vector_first" for v in by_lang.values())
    if has_regex and has_vector:
        strategy = "mixed"
    elif has_vector:
        strategy = "vector_first"
    else:
        strategy = "regex_first"
    manifest = {
        "schema_version": "1.0",
        "record_type": "hybrid_manifest",
        "engine": "builtin-lexical-1.0",
        "candidate_only": True,
        "strategy": strategy,
        "strategy_by_language": by_lang,
        "mini_unified": False,
        "vector_success": False,
        "vector_key_check": embedding_key_status(),
        "deep_extra_queries": [name for name, _intent, _kw in DEEP_EXTRA_QUERIES],
        "mini_note": DEEP_NOTE,
    }
    if _TRUNCATED["scan"]:
        manifest["lexical_truncated"] = True
        manifest["lexical_truncation_note"] = (
            f"lexical candidates truncated at MAX_FILES={MAX_FILES} / MAX_TOTAL_HITS={MAX_TOTAL_HITS}"
        )
    return manifest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True, help="源码根目录")
    parser.add_argument("--out", type=Path, help="JSONL 输出路径（缺省打 stdout）")
    args, _rest = parser.parse_known_args(argv)
    root = args.root.resolve()
    if not root.is_dir():
        print(
            json.dumps({"status": "failed", "reason": f"root missing: {root}"}, ensure_ascii=False),
            file=sys.stderr,
        )
        return 2
    hits, extra = scan_root(root)
    manifest = build_manifest(extra["languages_seen"])
    manifest["files_scanned"] = extra["files_scanned"]
    manifest["per_query_counts"] = extra["per_query_counts"]
    records = [manifest] + hits
    records = [redact_object(rec) for rec in records]
    lines = "".join(json.dumps(item, ensure_ascii=False) + "\n" for item in records)
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(lines, encoding="utf-8")
        print(
            json.dumps(
                {
                    "status": "ok",
                    "out": str(args.out),
                    "records": len(records),
                    "files_scanned": extra["files_scanned"],
                    "strategy": manifest["strategy"],
                    "truncated": bool(_TRUNCATED["scan"]),
                },
                ensure_ascii=False,
            )
        )
    else:
        print(lines, end="")
    return 0


if __name__ == "__main__":
    sys.exit(main())
