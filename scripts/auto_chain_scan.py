#!/usr/bin/env python3
"""Walk local source and pin source→sink *candidates*.

Not a finding. Not verified. Does not replace keyword-scan / js-collection /
sink-runtime / component-cve.

Reads include/ inc/ lib/ (bootstrap .inc is PHP). Skips vendor/node_modules/.git
only for walking, never because the folder is named include.
"""
from __future__ import annotations
import sys
sys.dont_write_bytecode = True  # 2026-10-13 新6: 禁 pyc 落包目录（包卫生）

import argparse
import ast
import json
import re
import sys
from pathlib import Path

SKIP_DIR_NAMES = {
    ".git",
    ".svn",
    ".hg",
    ".idea",
    ".vscode",
    "__pycache__",
    "node_modules",
    "vendor",
    "dist",
    "build",
    "target",
    "out",
    "coverage",
    ".next",
    ".nuxt",
}
# DeepAudit strips these from HTTP *entry* ledger. This walker still reads them.
KEEP_READING_DIR_NAMES = {
    "include",
    "includes",
    "inc",
    "lib",
    "library",
    "classes",
    "class",
}
TEXT_EXT = {
    ".php",
    ".inc",
    ".phtml",
    ".php5",
    ".php7",
    ".java",
    ".jsp",
    ".jspx",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".mjs",
    ".cjs",
    ".vue",
    ".py",
    ".pyw",
    ".go",
    ".rb",
    ".rake",
    ".rs",
    ".c",
    ".h",
    ".cc",
    ".cpp",
    ".cxx",
    ".hpp",
    ".cs",
    ".kt",
    ".kts",
    ".scala",
    ".xml",
    ".yml",
    ".yaml",
    ".ex",
    ".exs",
    ".erl",
    ".lua",
    ".swift",
    ".m",
    ".mm",
}
NEARBY_LINES = 80
MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_ITEMS = 2000
MAX_LEDGER_HITS = 2000
MAX_SECRET_ITEMS = 100
FILTER_SIGNAL_RE = re.compile(
    r"\b(?:authorize|authorization|permission|access|tenant|allowlist|whitelist|"
    r"sanitize|validate|verify|check|filter|normalize|htmlspecialchars|"
    r"addslashes|mysql_real_escape|mysqli_real_escape|bindParam|prepared)\b",
    re.I,
)
SECRET_RULES: tuple[tuple[str, str], ...] = (
    (r"(?i)(?:password|passwd|pwd)\s*=\s*[\"'][^\"']{4,}[\"']", "hardcoded_password"),
    (
        r"(?i)(?:api[_-]?key|secret|token|private[_-]?key)\s*=\s*[\"'][^\"']{8,}[\"']",
        "hardcoded_token",
    ),
    (
        r"(?i)(?:password|secret|token|api[_-]?key|private[_-]?key)\s*[\"']?\s*=>\s*[\"'][^\"']{4,}[\"']",
        "hardcoded_php_array",
    ),
    (r"-----BEGIN [A-Z ]*PRIVATE KEY-----", "private_key"),
)

SOURCE_RULES: tuple[tuple[str, str, str], ...] = (
    ("php_request", r"\$_(?:GET|POST|REQUEST|COOKIE|FILES)\s*\[", "php"),
    ("java_request", r"(?:@(?:PathVariable|RequestParam|RequestBody|RequestHeader|CookieValue|RequestPart|ModelAttribute)\b|\w+\.getParameter(?:Values)?\s*\()", "java"),
    ("js_request", r"\b(?:req\.(?:query|body|params|headers)|request\.(?:query|body|params)|URLSearchParams)\b", "js"),
    ("py_request", r"\b(?:request\.(?:args|form|json|values|files|GET|POST)|flask\.request|os\.environ|sys\.argv)\b", "py"),
    ("go_request", r"\b(?:r|req)\.(?:URL\.Query|FormValue|PostFormValue)\s*\(", "go"),
    ("rb_request", r"\bparams\s*\[", "rb"),
    ("rs_request", r"\b(?:web::Query|web::Json|Path<|Query<|Json<)\b", "rs"),
    ("c_request", r"\b(?:argv\s*\[|getenv\s*\(|recv\s*\(|fgets\s*\(|scanf(?:f)?\s*\()", "c"),
    ("cs_request", r"\b(?:Request\.(?:Query|Form|Headers)|HttpContext\.Request)\b", "cs"),
)
SINK_RULES: tuple[tuple[str, str, str], ...] = (
    ("php_include", r"\b(?:include|include_once|require|require_once)\s*(?:\(|\s)\s*\$[A-Za-z_]\w*", "php"),
    ("php_sql", r"(?:mysql_query|mysqli_query|mysqli_real_query|\$pdo->(?:query|exec)|->query\s*\()\s*\(", "php"),
    ("php_eval", r"\b(?:eval|assert|create_function)\s*\(", "php"),
    ("php_unserialize", r"\bunserialize\s*\(\s*\$", "php"),
    ("php_cmd", r"\b(?:exec|system|passthru|shell_exec|popen)\s*\(\s*\$", "php"),
    ("php_file", r"\b(?:file_get_contents|fopen|file_put_contents|readfile)\s*\(\s*\$", "php"),
    ("java_exec", r"(?:Runtime\.getRuntime\(\)\.exec|new\s+ProcessBuilder)\s*\(", "java"),
    ("java_reflect", r"\bClass\.forName\s*\(", "java"),
    ("java_spel", r"\b(?:ScriptEngine|SpelExpressionParser|ExpressionParser)\b", "java"),
    ("mybatis_dollar", r"\$\{\s*[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*\s*\}", "xml"),
    ("js_eval", r"\b(?:eval|new\s+Function)\s*\(", "js"),
    ("js_cmd", r"\b(?:child_process\.)?(?:exec|execSync|spawn|fork)\s*\(", "js"),
    ("py_cmd", r"(?:os\.system|subprocess\.(?:call|run|Popen)|pickle\.loads?)\s*\(", "py"),
    ("go_cmd", r"\bexec\.Command(?:Context)?\s*\(", "go"),
    ("go_sql", r"\.(?:Query|QueryContext|Exec|ExecContext)\s*\(", "go"),
    ("rb_cmd", r"\b(?:system|exec|Open3\.(?:capture|popen))\s*\(", "rb"),
    ("rs_cmd", r"\bCommand::new\s*\(", "rs"),
    ("c_cmd", r"\b(?:system|popen|_popen|strcpy|strcat|sprintf)\s*\(", "c"),
    ("cs_cmd", r"\b(?:Process\.Start|SqlCommand)\s*\(", "cs"),
)

SCAN_KEYS = (
    "php_request",
    "php_include",
    "php_sql",
    "php_eval",
    "php_unserialize",
    "java_request",
    "java_exec",
    "mybatis_dollar",
)

# 入口键 hits=0 且该语言有文件时，用粗子串交叉复核（防规则盲区静默）。
# mismatch = 疑似 walker 规则没认出这种入口写法，郭嘉必须 grep 复核后再下结论。
ENTRY_SCAN_KEY_BY_LANG = {
    "php": "php_request",
    "java": "java_request",
    "js": "js_request",
    "py": "py_request",
    "go": "go_request",
    "rb": "rb_request",
    "rs": "rs_request",
    "c": "c_request",
    "cs": "cs_request",
}
ENTRY_COARSE_SIGNALS = {
    "php": ("$_GET", "$_POST", "$_REQUEST", "$_COOKIE"),
    "java": (
        "@RequestBody", "@RequestParam", "@PathVariable", "@RequestHeader",
        "@CookieValue", "@RequestPart", "@ModelAttribute", "getParameter(",
        # 2026-10-16 修10：粗信号补 getParameterValues(——`request . getParameterValues(` 空格点号写法
        # 规则与粗信号双不认 → consistent_zero 假阴性
        "getParameterValues(",
    ),
    "js": ("req.query", "req.body", "req.params", "request.query", "request.body"),
    "py": ("request.args", "request.form", "request.json", "flask.request"),
    "go": ("FormValue(", "PostFormValue(", "URL.Query()"),
    "rb": ("params[",),
    "rs": ("web::Query", "web::Json", "Path<", "Query<", "Json<"),
    "c": ("argv[", "getenv(", "scanf("),
    "cs": ("Request.Query", "Request.Form", "HttpContext.Request"),
}
MAX_CROSS_CHECK_FILES = 2000

LANG_BY_EXT = {
    ".php": "php",
    ".inc": "php",
    ".phtml": "php",
    ".php5": "php",
    ".php7": "php",
    ".java": "java",
    ".jsp": "java",
    ".jspx": "java",
    ".js": "js",
    ".jsx": "js",
    ".ts": "js",
    ".tsx": "js",
    ".mjs": "js",
    ".cjs": "js",
    ".vue": "js",
    ".py": "py",
    ".pyw": "py",
    ".go": "go",
    ".rb": "rb",
    ".rake": "rb",
    ".rs": "rs",
    ".c": "c",
    ".h": "c",
    ".cc": "c",
    ".cpp": "c",
    ".cxx": "c",
    ".hpp": "c",
    ".cs": "cs",
    ".kt": "java",
    ".kts": "java",
    ".scala": "java",
    ".xml": "xml",
    ".yml": "xml",
    ".yaml": "xml",
    ".ex": "elixir",
    ".exs": "elixir",
    ".erl": "erlang",
    ".lua": "lua",
    ".swift": "swift",
    ".m": "objc",
    ".mm": "objc",
}

# Walker 短规则覆盖的语言。没在这里的仍走文件，记 coverage，不停工。
SHORT_RULE_LANGS = {
    "php",
    "java",
    "js",
    "py",
    "go",
    "rb",
    "rs",
    "c",
    "cs",
    "xml",
}


def _skip_dir(name: str) -> bool:
    low = name.lower()
    if low in KEEP_READING_DIR_NAMES:
        return False
    return low in SKIP_DIR_NAMES


def iter_source_files(root: Path):
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        try:
            rel_parts = path.relative_to(root).parts
        except ValueError:
            continue
        if any(_skip_dir(part) for part in rel_parts[:-1]):
            continue
        if path.suffix.lower() not in TEXT_EXT:
            continue
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                continue
        except OSError:
            continue
        yield path


def read_text(path: Path) -> str | None:
    try:
        raw = path.read_bytes()
    except OSError:
        return None
    if b"\x00" in raw[:4096]:
        return None
    for enc in ("utf-8", "gb18030", "latin-1"):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", errors="ignore")


def line_of(text: str, index: int) -> int:
    return text.count("\n", 0, index) + 1


def compact(s: str, n: int = 160) -> str:
    s = re.sub(r"\s+", " ", s).strip()
    return s[:n]


def nearby_window(text: str, line: int, radius: int = 8, n: int = 400) -> str:
    lines = text.splitlines()
    if not lines:
        return ""
    index = max(0, min(len(lines) - 1, line - 1))
    start = max(0, index - radius)
    end = min(len(lines), index + radius + 1)
    return compact("\n".join(lines[start:end]), n)


def redact_secret_match(kind: str) -> str:
    return f"[redacted {kind}]"


SECRET_VALUE_RE = re.compile(
    r"(?i)((?:password|passwd|pwd|secret|token|api[_-]?key|private[_-]?key)\s*"
    r"(?:=|=>)\s*)([\"'])[^\"']+\2"
)
PRIVATE_KEY_BLOCK_RE = re.compile(
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
    re.S,
)


def redact_secret_text(text: str) -> str:
    if not text:
        return text
    text = PRIVATE_KEY_BLOCK_RE.sub("[redacted private_key]", text)
    return SECRET_VALUE_RE.sub(r"\1\2[redacted]\2", text)


def redact_ledger(obj):
    """2026-10-16 修7：递归逐字段脱敏——只对每个字符串值单独跑 redact_secret_text。

    旧版 build_ledger 末行对整份 ledger 的 JSON 文本跑顶层 PRIVATE_KEY_BLOCK_RE
    （`.*?` + re.S）：半截 BEGIN 在 h1.js nearby、半截 END 在 h2.js nearby 时，
    顶层正则把两处之间的整块（含 h2 全部条目）吞成 [redacted private_key]——
    结果仍是合法 JSON、零告警、条目静默消失（半截标记可被故意撒进源码让扫描丢条目）。
    逐字段后：单字段内完整 BEGIN…END 块照旧脱敏；分置两字段的半截标记互不影响、不再吞块。
    """
    if isinstance(obj, dict):
        return {k: redact_ledger(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [redact_ledger(v) for v in obj]
    if isinstance(obj, str):
        return redact_secret_text(obj)
    return obj


def lang_ok(rule_lang: str, file_lang: str | None) -> bool:
    if file_lang is None:
        return False
    if rule_lang == "xml":
        return file_lang in {"xml", "java"}
    if rule_lang == "c":
        return file_lang in {"c"}
    return rule_lang == file_lang


def collect_hits(root: Path) -> tuple[list[dict], list[dict], list[dict], int, dict, list, list]:
    sources: list[dict] = []
    sinks: list[dict] = []
    secrets: list[dict] = []
    files_scanned = 0
    files_by_lang: dict[str, int] = {}
    src_re = [(k, re.compile(p, re.I), lang) for k, p, lang in SOURCE_RULES]
    snk_re = [(k, re.compile(p, re.I), lang) for k, p, lang in SINK_RULES]
    sec_re = [(re.compile(p), kind) for p, kind in SECRET_RULES]
    php_texts: list[tuple[str, str]] = []
    py_texts: list[tuple[str, str]] = []
    for path in iter_source_files(root):
        text = read_text(path)
        if text is None:
            continue
        files_scanned += 1
        rel = path.relative_to(root).as_posix()
        file_lang = LANG_BY_EXT.get(path.suffix.lower()) or "unknown"
        files_by_lang[file_lang] = files_by_lang.get(file_lang, 0) + 1
        if file_lang == "php":
            php_texts.append((rel, text))
        elif file_lang == "py":
            py_texts.append((rel, text))
        for kind, rx, lang in src_re:
            if not lang_ok(lang, file_lang):
                continue
            for m in rx.finditer(text):
                line_no = line_of(text, m.start())
                sources.append(
                    {
                        "file": rel,
                        "line": line_no,
                        "kind": kind,
                        "match": redact_secret_text(compact(m.group(0))),
                        "nearby": redact_secret_text(nearby_window(text, line_no)),
                    }
                )
        for kind, rx, lang in snk_re:
            if not lang_ok(lang, file_lang):
                continue
            for m in rx.finditer(text):
                line_no = line_of(text, m.start())
                sinks.append(
                    {
                        "file": rel,
                        "line": line_no,
                        "kind": kind,
                        "match": redact_secret_text(compact(m.group(0))),
                        "nearby": redact_secret_text(nearby_window(text, line_no)),
                    }
                )
        if len(secrets) < MAX_SECRET_ITEMS:
            for rx, kind in sec_re:
                if len(secrets) >= MAX_SECRET_ITEMS:
                    break
                for m in rx.finditer(text):
                    if len(secrets) >= MAX_SECRET_ITEMS:
                        break
                    line_no = line_of(text, m.start())
                    secrets.append(
                        {
                            "file": rel,
                            "line": line_no,
                            "kind": kind,
                            "match": redact_secret_match(kind),
                            "candidate_only": True,
                            "status": "candidate",
                            "note": "开局脱敏密钥候选；不能顶 close credential_scan，值不进司马懿",
                        }
                    )
    coverage = {
        "files_by_lang": files_by_lang,
        "languages_with_short_rules": sorted(SHORT_RULE_LANGS),
        "languages_without_rules": sorted(
            lang for lang in files_by_lang if lang not in SHORT_RULE_LANGS
        ),
        "note": (
            "没短规则的语言仍计入 files_scanned；本字段只表示没短规则，不是停工。"
            "没追完的链才写计划表 coverage_gap。methodology-gap.json 可选笔记。"
        ),
    }
    return sources, sinks, secrets, files_scanned, coverage, php_texts, py_texts


def pair_candidates(sources: list[dict], sinks: list[dict]) -> list[dict]:
    by_file: dict[str, list[dict]] = {}
    for s in sources:
        by_file.setdefault(s["file"], []).append(s)
    items: list[dict] = []
    for i, sink in enumerate(sinks, start=1):
        locals_ = by_file.get(sink["file"]) or []
        best = None
        best_dist = 10**9
        for src in locals_:
            dist = abs(int(src["line"]) - int(sink["line"]))
            if dist < best_dist:
                best_dist = dist
                best = src
        if best is not None and best_dist <= NEARBY_LINES:
            relation = "same_file_nearby"
            src = best
        elif best is not None:
            relation = "same_file"
            src = best
        else:
            relation = "sink_without_local_source"
            src = None
        blob = " ".join(
            [
                str((src or {}).get("nearby") or ""),
                str((src or {}).get("match") or ""),
                str(sink.get("nearby") or ""),
                str(sink.get("match") or ""),
            ]
        )
        item = {
            "id": f"AC-{i:03d}",
            "candidate_only": True,
            "status": "candidate",
            "file": sink["file"],
            "kind": sink.get("kind"),
            "sink": sink,
            "relation": relation,
            "filter_nearby": "hit" if FILTER_SIGNAL_RE.search(blob) else "none",
            "note": "程序钉的 source→sink 候选；不是 verified，不能顶关键字/JS/sink-runtime/CVE；filter_nearby 只是邻近过滤词，不是曹冲过滤账",
        }
        if src is not None:
            item["source"] = src
        items.append(item)
        if len(items) >= MAX_ITEMS:
            break
    return items


def _php_strip_line_comment(line: str) -> str:
    # 2026-10-13 C11 修：字符串内非 URL 的 // 旧版也被当注释剥掉——奇数引号（字符串未闭合跨行）时不剥，
    # 偶数引号行里 // 后跟 URL 形态（如 http://）也不剥
    if line.count('"') % 2 == 1 or line.count("'") % 2 == 1:
        return line
    return re.sub(r'(?<!:)//(?![^\s"\']*\.[a-z]{2,}/).*$', "", line)


def scan_php_concat_flows(rel: str, text: str) -> list[dict]:
    """Conservative same-file PHP concat / nearby file_put_contents. Candidate only."""
    lines = text.splitlines()
    items: list[dict] = []
    seen: set[tuple[str, int, str]] = set()

    def add(
        kind: str,
        line_number: int,
        source_expression: str,
        sink_name: str,
        sink_line: int | None = None,
        match: str = "",
    ) -> None:
        key = (kind, line_number, sink_name)
        if key in seen:
            return
        seen.add(key)
        sink_ln = sink_line or line_number
        items.append(
            {
                "candidate_only": True,
                "status": "candidate",
                "file": rel,
                "relation": "php_concatenation_reaches_local_sink",
                "kind": kind,
                "source": {
                    "file": rel,
                    "line": line_number,
                    "kind": "php_concat_var",
                    "match": redact_secret_text(compact(source_expression)),
                },
                "sink": {
                    "file": rel,
                    "line": sink_ln,
                    "kind": kind,
                    "match": redact_secret_text(compact(sink_name if not match else match)),
                },
                "filter_nearby": "hit"
                if FILTER_SIGNAL_RE.search(
                    " ".join([source_expression, sink_name, match])
                )
                else "none",
                "note": "程序钉的 PHP 同文件拼接流候选；不是 verified；filter_nearby 不是曹冲账",
            }
        )

    for index, original in enumerate(lines):
        line_number = index + 1
        line = _php_strip_line_comment(original)
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        sql_concat = re.search(
            r"\b(?:select|insert|update|delete)\b.*\.\s*\$[A-Za-z_]\w*"
            r"|\$[A-Za-z_]\w*\s*\.\s*.*\b(?:select|insert|update|delete)\b",
            line,
            re.IGNORECASE,
        )
        if sql_concat:
            variables = re.findall(r"\$[A-Za-z_]\w*", sql_concat.group(0))
            add(
                "php_sql_concat",
                line_number,
                variables[-1] if variables else "$var",
                "SQL query construction",
                match=sql_concat.group(0),
            )
        html_concat = re.search(
            r"</?[A-Za-z][^>]*>.*\.\s*\$[A-Za-z_]\w*"
            r"|\$[A-Za-z_]\w*\s*\.\s*.*</?[A-Za-z]",
            line,
            re.IGNORECASE,
        )
        if html_concat:
            variables = re.findall(r"\$[A-Za-z_]\w*", html_concat.group(0))
            add(
                "php_html_concat",
                line_number,
                variables[-1] if variables else "$var",
                "HTML response output",
                match=html_concat.group(0),
            )
        assignment = re.search(
            r"\$(?P<destination>[A-Za-z_]\w*)\s*=\s*(?P<expression>[^;]+);",
            line,
        )
        if not assignment:
            continue
        expression = assignment.group("expression")
        variables = re.findall(r"\$[A-Za-z_]\w*", expression)
        has_separator = bool(
            re.search(r"DIRECTORY_SEPARATOR|[\"'][\\/]\s*[\"']", expression)
        )
        if not variables or not has_separator:
            continue
        destination = assignment.group("destination")
        source_variable = variables[-1]
        sink_line = None
        sink_name = "path construction"
        for next_index in range(index + 1, min(len(lines), index + 6)):
            next_line = _php_strip_line_comment(lines[next_index])
            if re.search(
                rf"\bfile_put_contents\s*\(\s*\${re.escape(destination)}\b",
                next_line,
            ):
                sink_line = next_index + 1
                sink_name = "file_put_contents"
                break
        add(
            "php_path_concat",
            line_number,
            source_variable,
            sink_name,
            sink_line=sink_line,
            match=expression,
        )
    return items


def _py_dotted_name(node: ast.AST) -> str:
    parts: list[str] = []
    current = node
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        parts.append(current.id)
    return ".".join(reversed(parts))


def _scan_python_function_flows(function: ast.AST, content: str, lines: list[str], rel: str) -> list[dict]:
    tainted: dict[str, dict] = {}
    tainted_paths: dict[str, dict] = {}
    items: list[dict] = []
    seen: set[tuple[str, int, int]] = set()

    def source_detail(node: ast.AST) -> dict | None:
        is_request_value = False
        if isinstance(node, ast.Subscript):
            is_request_value = _py_dotted_name(node.value) in {
                "request.args",
                "request.form",
                "request.values",
                "request.json",
                "request.cookies",
                "request.headers",
            }
        elif isinstance(node, ast.Attribute):
            is_request_value = _py_dotted_name(node) in {
                "request.args",
                "request.form",
                "request.values",
                "request.json",
                "request.data",
            }
        elif isinstance(node, ast.Call):
            is_request_value = _py_dotted_name(node.func) in {
                "request.get_json",
                "request.get_data",
            }
        if not is_request_value:
            return None
        line_number = int(getattr(node, "lineno", 1) or 1)
        return {
            "line": line_number,
            "expression": (
                ast.get_source_segment(content, node)
                or (lines[line_number - 1].strip() if line_number <= len(lines) else "request")
            )[:240],
        }

    def taint_from(node: ast.AST | None) -> dict | None:
        if node is None:
            return None
        direct = source_detail(node)
        if direct:
            return direct
        if isinstance(node, ast.Name):
            return tainted.get(node.id)
        if isinstance(node, ast.BinOp):
            return taint_from(node.left) or taint_from(node.right)
        if isinstance(node, ast.JoinedStr):
            for value in node.values:
                if isinstance(value, ast.FormattedValue):
                    found = taint_from(value.value)
                    if found:
                        return found
            return None
        if isinstance(node, ast.Subscript):
            return taint_from(node.value)
        if isinstance(node, ast.Attribute):
            return taint_from(node.value)
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute):
                receiver = taint_from(node.func.value)
                if receiver:
                    return receiver
            for argument in node.args:
                found = taint_from(argument)
                if found:
                    return found
        return None

    def path_taint_from(node: ast.AST | None) -> dict | None:
        if node is None:
            return None
        if isinstance(node, ast.Name):
            return tainted_paths.get(node.id)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
            return taint_from(node.left) or taint_from(node.right) or path_taint_from(node.left)
        if isinstance(node, ast.Call):
            name = _py_dotted_name(node.func).lower()
            if name.endswith(".join") or name == "pathlib.path":
                for argument in node.args:
                    found = taint_from(argument) or path_taint_from(argument)
                    if found:
                        return found
        return taint_from(node)

    def target_names(node: ast.AST) -> list[str]:
        if isinstance(node, ast.Name):
            return [node.id]
        if isinstance(node, (ast.Tuple, ast.List)):
            return [name for child in node.elts for name in target_names(child)]
        return []

    def add_finding(kind: str, call: ast.Call, source: dict) -> None:
        sink_line = int(getattr(call, "lineno", 1) or 1)
        source_line = int(source.get("line") or sink_line)
        key = (kind, sink_line, source_line)
        if key in seen:
            return
        seen.add(key)
        sink_name = _py_dotted_name(call.func) or "call"
        items.append(
            {
                "candidate_only": True,
                "status": "candidate",
                "file": rel,
                "relation": "untrusted_request_value_reaches_local_sink",
                "kind": kind,
                "source": {
                    "file": rel,
                    "line": source_line,
                    "kind": "py_request_flow",
                    "match": redact_secret_text(compact(str(source.get("expression") or "request"))),
                },
                "sink": {
                    "file": rel,
                    "line": sink_line,
                    "kind": kind,
                    "match": compact(sink_name),
                },
                "filter_nearby": "hit"
                if FILTER_SIGNAL_RE.search(
                    " ".join(
                        [
                            str(source.get("expression") or ""),
                            sink_name,
                            " ".join(lines[max(0, source_line - 1) : min(len(lines), sink_line)]),
                        ]
                    )
                )
                else "none",
                "note": "程序钉的 Python 函数内 request→sink 候选；不是 verified；filter_nearby 不是曹冲账",
            }
        )

    def inspect_expression(node: ast.AST | None) -> None:
        if node is None:
            return
        if isinstance(node, ast.Call):
            sink_name = _py_dotted_name(node.func).lower()
            leaf = sink_name.rsplit(".", 1)[-1]
            arguments = list(node.args)
            value_source = next(
                (taint_from(argument) for argument in arguments if taint_from(argument)),
                None,
            )
            if leaf in {"query", "execute", "execute_query", "raw"} and value_source:
                add_finding("py_sql_flow", node, value_source)
            elif (
                leaf in {"urlopen", "urlretrieve"}
                or any(prefix in sink_name for prefix in ("requests.", "httpx.", "aiohttp."))
            ) and value_source:
                add_finding("py_ssrf_flow", node, value_source)
            elif leaf in {"system", "popen"} or "subprocess" in sink_name:
                if value_source:
                    add_finding("py_cmd_flow", node, value_source)
            elif leaf in {"loads", "load"} and "pickle" in sink_name and value_source:
                add_finding("py_pickle_flow", node, value_source)
            elif leaf in {"open", "send_file", "send_from_directory"}:
                path_source = next(
                    (path_taint_from(argument) for argument in arguments if path_taint_from(argument)),
                    None,
                )
                if path_source:
                    add_finding("py_path_flow", node, path_source)
            elif leaf in {"write_text", "write_bytes", "write"} and isinstance(node.func, ast.Attribute):
                path_source = path_taint_from(node.func.value)
                if path_source:
                    add_finding("py_path_flow", node, path_source)
        for child in ast.iter_child_nodes(node):
            inspect_expression(child)

    def inspect_statements(statements: list) -> None:
        for statement in statements:
            if isinstance(statement, ast.Assign):
                inspect_expression(statement.value)
                value_taint = taint_from(statement.value)
                value_path_taint = path_taint_from(statement.value)
                for target in statement.targets:
                    for name in target_names(target):
                        if value_taint:
                            tainted[name] = dict(value_taint)
                        else:
                            tainted.pop(name, None)
                        if value_path_taint:
                            tainted_paths[name] = dict(value_path_taint)
                        else:
                            tainted_paths.pop(name, None)
            elif isinstance(statement, ast.AnnAssign):
                inspect_expression(statement.value)
                value_taint = taint_from(statement.value)
                value_path_taint = path_taint_from(statement.value)
                for name in target_names(statement.target):
                    if value_taint:
                        tainted[name] = dict(value_taint)
                    else:
                        tainted.pop(name, None)
                    if value_path_taint:
                        tainted_paths[name] = dict(value_path_taint)
                    else:
                        tainted_paths.pop(name, None)
            elif isinstance(statement, (ast.If, ast.For, ast.AsyncFor, ast.While)):
                inspect_expression(getattr(statement, "test", None))
                inspect_expression(getattr(statement, "iter", None))
                inspect_statements(statement.body)
                inspect_statements(statement.orelse)
            elif isinstance(statement, (ast.With, ast.AsyncWith)):
                for item in statement.items:
                    inspect_expression(item.context_expr)
                inspect_statements(statement.body)
            elif isinstance(statement, ast.Try):
                inspect_statements(statement.body)
                for handler in statement.handlers:
                    inspect_statements(handler.body)
                inspect_statements(statement.orelse)
                inspect_statements(statement.finalbody)
            elif not isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                inspect_expression(statement)

    inspect_statements(list(getattr(function, "body", []) or []))
    return items


def scan_python_request_flows(rel: str, text: str, warnings: list[dict] | None = None) -> list[dict]:
    """Function-local request → sink. Does not execute project code. Candidate only."""

    def skip_file(reason: str) -> None:
        # 2026-10-16 修8：深嵌套合法 py（如 5000 层一元负号）递归爆栈——单文件放弃记 warning，不崩整场
        if warnings is not None:
            warnings.append(
                {
                    "file": rel,
                    "warning": reason,
                    "note": "单文件放弃（深嵌套递归爆栈），其余文件照扫；该文件候选损失须人工补看",
                }
            )

    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError) as _se:
        # 批四十九（r18 A-R2-01 第二通道）：深嵌套在 py3.14 抛 SyntaxError——此前静默 return
        # 整文件放弃连 scan_warnings 都不留，「跳过含真洞文件→账面干净」零痕迹；现照 RecursionError 同款记账
        skip_file(f"python ast.parse failed ({type(_se).__name__}); file skipped")
        return []
    except RecursionError:
        skip_file("python ast.parse hit recursion limit; file skipped")
        return []
    lines = text.splitlines()
    items: list[dict] = []
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            try:
                items.extend(_scan_python_function_flows(node, text, lines, rel))
            except RecursionError:
                skip_file("python flow scan hit recursion limit; file skipped")
                break
    return items


def count_kind(rows: list[dict], kind: str) -> int:
    return sum(1 for r in rows if r.get("kind") == kind)


def entry_zero_cross_check(root: Path, coverage: dict, sources: list[dict]) -> dict:
    """入口键 0 命中且该语言有文件 → 粗子串交叉复核。

    只在 walker 没钉到入口的语言上跑第二遍轻扫；mismatch 说明源码里有该形态
    入口但短规则没认出（规则盲区），郭嘉须 grep 复核，禁止默默绕开。
    """
    files_by_lang = (coverage or {}).get("files_by_lang") or {}
    hits_by_key: dict[str, int] = {}
    for src in sources:
        k = src.get("kind")
        hits_by_key[k] = hits_by_key.get(k, 0) + 1
    need = {
        lang: ENTRY_COARSE_SIGNALS[lang]
        for lang, key in ENTRY_SCAN_KEY_BY_LANG.items()
        if files_by_lang.get(lang, 0) > 0 and hits_by_key.get(key, 0) == 0
    }
    result: dict = {
        "note": "入口键 hits=0 且该语言有文件才触发；mismatch=疑似规则盲区，郭嘉必须 grep 复核后记 coverage_gap，禁止默默绕开",
        "languages": {},
    }
    if not need:
        return result
    ext_by_lang: dict[str, list[str]] = {}
    for ext, lang in LANG_BY_EXT.items():
        ext_by_lang.setdefault(lang, []).append(ext)
    scanned_files = 0
    for path in root.rglob("*"):
        if scanned_files >= MAX_CROSS_CHECK_FILES:
            break
        if not path.is_file():
            continue
        lang = LANG_BY_EXT.get(path.suffix.lower())
        if lang not in need:
            continue
        try:
            rel_parts = path.relative_to(root).parts
        except ValueError:
            continue
        if any(_skip_dir(part) for part in rel_parts[:-1]):
            continue
        text = read_text(path)
        if not text:
            continue
        scanned_files += 1
        row = result["languages"].setdefault(
            lang,
            {"files": files_by_lang.get(lang, 0), "walker_hits": 0, "coarse_hits": 0, "verdict": ""},
        )
        for sig in need[lang]:
            row["coarse_hits"] += text.count(sig)
    for lang, row in result["languages"].items():
        row["verdict"] = "tool_rule_mismatch" if row["coarse_hits"] > 0 else "consistent_zero"
    return result


def build_ledger(root: Path) -> dict:
    sources, sinks, secrets, files_scanned, coverage, php_texts, py_texts = collect_hits(root)
    items = pair_candidates(sources, sinks)
    flow_items: list[dict] = []
    scan_warnings: list[dict] = []
    for rel, text in php_texts:
        flow_items.extend(scan_php_concat_flows(rel, text))
    for rel, text in py_texts:
        flow_items.extend(scan_python_request_flows(rel, text, scan_warnings))
    next_id = len(items) + 1
    for flow in flow_items:
        if len(items) >= MAX_ITEMS:
            break
        flow["id"] = f"AC-{next_id:03d}"
        next_id += 1
        items.append(flow)
    secret_items: list[dict] = []
    for secret in secrets:
        if len(items) >= MAX_ITEMS:
            break
        row = {
            "id": f"AC-{next_id:03d}",
            "candidate_only": True,
            "status": "candidate",
            "file": secret["file"],
            "kind": secret["kind"],
            "relation": "hardcoded_secret_candidate",
            "filter_nearby": "none",
            "source": {
                "file": secret["file"],
                "line": secret["line"],
                "kind": secret["kind"],
                "match": redact_secret_match(secret["kind"]),
            },
            "sink": {
                "file": secret["file"],
                "line": secret["line"],
                "kind": secret["kind"],
                "match": redact_secret_match(secret["kind"]),
            },
            "note": "开局脱敏密钥候选；不是 verified，不能顶 close credential_scan，值不进司马懿",
        }
        next_id += 1
        secret_items.append(row)
        items.append(row)
    scans = {}
    for key in SCAN_KEYS:
        if key.endswith("_request") or key == "php_request" or key == "java_request":
            hits = count_kind(sources, key)
            searched = {
                "php_request": "$_GET/POST/REQUEST/COOKIE/FILES（含 include/*.inc）",
                "java_request": "@RequestParam/@RequestBody/@PathVariable/@RequestHeader/@CookieValue/@RequestPart/@ModelAttribute 注解或 xxx.getParameter()（任意变量名；@ 前不设 \\b，注解才匹配得上）",
            }.get(key, key)
        else:
            hits = count_kind(sinks, key)
            searched = {
                "php_include": "include/require $var（.inc 当 PHP，不因目录名 include 跳过）",
                "php_sql": "mysql_query/mysqli/pdo",
                "php_eval": "eval/assert/create_function",
                "php_unserialize": "unserialize($",
                "java_exec": "Runtime.exec / ProcessBuilder",
                "mybatis_dollar": "mapper xml ${}",
            }.get(key, key)
        scans[key] = {"searched": searched, "hits": hits}
    extra_keys = (
        "py_request",
        "go_request",
        "js_request",
        "rb_request",
        "rs_request",
        "c_request",
        "cs_request",
        "py_cmd",
        "go_cmd",
        "js_cmd",
        "rb_cmd",
        "rs_cmd",
        "c_cmd",
        "cs_cmd",
    )
    extra_search = {
        "py_request": "request.args/form/json / os.environ",
        "go_request": "URL.Query / FormValue",
        "js_request": "req.query/body/params",
        "rb_request": "params[",
        "rs_request": "axum/actix extractor",
        "c_request": "argv/getenv/recv",
        "cs_request": "Request.Query/Form",
        "py_cmd": "os.system / subprocess / pickle",
        "go_cmd": "exec.Command",
        "js_cmd": "child_process exec/spawn",
        "rb_cmd": "system/exec/Open3",
        "rs_cmd": "Command::new",
        "c_cmd": "system/popen/strcpy",
        "cs_cmd": "Process.Start / SqlCommand",
        "php_sql_concat": "PHP SQL 字面量与 $var 拼接（同文件）",
        "php_html_concat": "PHP HTML 字面量与 $var 拼接（同文件）",
        "php_path_concat": "PHP 路径拼接后邻近 file_put_contents",
        "py_sql_flow": "Python 函数内 request→SQL",
        "py_ssrf_flow": "Python 函数内 request→urlopen/requests",
        "py_cmd_flow": "Python 函数内 request→subprocess/os.system",
        "py_pickle_flow": "Python 函数内 request→pickle",
        "py_path_flow": "Python 函数内 request→open/path",
        "hardcoded_password": "password= 字面量（脱敏，只记位置）",
        "hardcoded_token": "api_key/secret/token= 字面量（脱敏）",
        "hardcoded_php_array": "PHP 数组凭据字面量（脱敏）",
        "private_key": "BEGIN PRIVATE KEY 块（脱敏）",
    }
    extra_keys = extra_keys + (
        "php_sql_concat",
        "php_html_concat",
        "php_path_concat",
        "py_sql_flow",
        "py_ssrf_flow",
        "py_cmd_flow",
        "py_pickle_flow",
        "py_path_flow",
        "hardcoded_password",
        "hardcoded_token",
        "hardcoded_php_array",
        "private_key",
    )
    for key in extra_keys:
        if key.endswith("_request"):
            pool = sources
        elif key.endswith("_flow") or key.endswith("_concat"):
            # 2026-10-16 修9：_flow/_concat hits 旧版从 items（MAX_ITEMS 截断后的残池）计数——
            # flow.php 实存 php_sql_concat 却报 0。改从截断前的 flow_items 全池计数，与 items 截断解耦
            pool = flow_items
        elif key.startswith("hardcoded_") or key == "private_key":
            pool = secrets
        else:
            pool = sinks
        scans[key] = {"searched": extra_search[key], "hits": count_kind(pool, key)}
    coverage["entry_zero_cross_check"] = entry_zero_cross_check(root, coverage, sources)
    ledger = {
        "kind": "auto_chain_scan",
        "candidate_only": True,
        "engine": "scripts/auto_chain_scan.py",
        "source_root": str(root),
        "files_scanned": files_scanned,
        "skipped_dirs": sorted(SKIP_DIR_NAMES),
        "kept_reading_dirs": sorted(KEEP_READING_DIR_NAMES),
        "coverage": coverage,
        "scans": scans,
        "sources": sources[:MAX_LEDGER_HITS],
        "sinks": sinks[:MAX_LEDGER_HITS],
        "secret_candidates": secrets[:MAX_SECRET_ITEMS],
        "items": items,
        "notes": (
            "自动链扫描 = 程序走源码钉 source 和 sink；近距配对 + PHP 同文件拼接流 + "
            "Python 函数内 request→sink。include/ 仍读。.inc 当 PHP。"
            "MAX_ITEMS=2000。hits 不是洞，status 只能 candidate。"
            "filter_nearby 只是邻近过滤词，不能顶曹冲过滤账。"
            "secret_candidates 脱敏，不能顶 close credential_scan，值不进司马懿。"
            "不能顶 keyword-scan / js-collection / sink-runtime / component-cve。"
            "没短规则的语言记 coverage.languages_without_rules，不停工。"
        ),
    }
    # 2026-10-16 修9：截断落账——被 MAX_ITEMS 挤掉的候选数（sinks 每条恰一 item，flow/secret 同理）
    items_truncated = max(0, len(sinks) + len(flow_items) + len(secrets) - len(items))
    if items_truncated:
        ledger["items_truncated"] = items_truncated
    # 2026-10-16 修8：单文件放弃（递归爆栈）的 warning 落账
    if scan_warnings:
        ledger["scan_warnings"] = scan_warnings
    # 2026-10-16 修7：顶层整文 redact 改递归逐字段——半截私钥标记跨字段不再吞块（见 redact_ledger）
    return redact_ledger(ledger)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args(argv)
    root = args.root.resolve()
    if not root.is_dir():
        print(json.dumps({"status": "failed", "reason": f"root missing: {root}"}, ensure_ascii=False), file=sys.stderr)
        return 2
    ledger = build_ledger(root)
    text = json.dumps(ledger, ensure_ascii=False, indent=2) + "\n"
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
