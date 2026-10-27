"""credential_scan.py — run_root 凭据值外泄机械闸（收口前必跑；包内置版，无外部依赖）。

从本场 run_root 各角色目录的 credentials-local.txt 提取凭据值（口令/万能密码/
API 密钥等），再扫描 run_root 内其余落盘文件；值出现在凭据账以外的任何文件
（候选索引标题、验证计划、交接摘要落盘件等）即为 violations。

边界与口径：
- snapshot/ 与 runtime/ 为原始材料与可丢弃运行环境，排除（原源码里的公开
  种子值不算外泄；本审计自己的产物里复述才算）。
- 回执不打印值本身，只打印 value_sha8（值哈希前 8 位）+ 文件 + 行号，避免
  扫描回执本身二次泄密。
- 无凭据账返回 status=no_credentials_declared（exit 3），按 needs_review 处
  理，不算干净。
- 干净 exit 0；有外泄 exit 2。本工具只证明「登记过的值没有落到账外文件」，
  不证明聊天正文干净（聊天不在磁盘扫描范围），正文纪律由角色卡与契约约束。
"""
import argparse
import hashlib
import json
import os
import re
import sys

KEYWORD_RE = re.compile(r"密码|口令|密钥|password|passwd|secret|token|api[_-]?key", re.IGNORECASE)
SPLIT_RE = re.compile(r"[:：]")
BAD_CHARS_RE = re.compile(r"[\s()（）\[\]【】{}、，,；;\"'`/\\=<>«»~^|*!?]")
PLACEHOLDER_VALUES = {"null", "none", "n/a", "unknown", "见", "credential_ref", "todo", "tbd"}

PRUNE_DIRS = {"snapshot", "runtime", ".git", "__pycache__", "node_modules", ".venv", "venv"}
BINARY_EXTS = {
    ".zip", ".jar", ".war", ".7z", ".gz", ".tar", ".rar", ".png", ".jpg", ".jpeg",
    ".gif", ".bmp", ".webp", ".ico", ".pdf", ".docx", ".xlsx", ".pptx", ".sqlite",
    ".db", ".wal", ".shm", ".class", ".exe", ".dll", ".woff", ".woff2", ".ttf",
    ".eot", ".mp4", ".mp3", ".wav", ".avi", ".bin", ".so", ".dylib",
}
CRED_FILENAME = "credentials-local.txt"
# 司马懿中性凭据目录（契约 D 允许位置）：不做外泄扫描对象，其 credentials-local.txt 仍作 declared 来源
SANCTIONED_SKIP_DIR = "run/access"


def rel_dir_under(path, run_root):
    return os.path.relpath(path, run_root).replace("\\", "/")


def sanctioned_skip(rel_dir):
    rel = rel_dir.rstrip("/")
    return rel == SANCTIONED_SKIP_DIR or rel.startswith(SANCTIONED_SKIP_DIR + "/")


def extract_values(path):
    """从凭据账提取 (ref, value)；值不含空白/成对符号，长度 6~128。"""
    out = []
    try:
        with open(str(path), "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except OSError as exc:
        out.append(("<unreadable:" + str(exc) + ">", None))
        return out
    for line in text.splitlines():
        if not KEYWORD_RE.search(line):
            continue
        parts = SPLIT_RE.split(line)
        if len(parts) < 2:
            continue
        ref = parts[0].strip().lstrip("-# ").strip()
        value = parts[-1].strip()
        if len(value) < 6 or len(value) > 128:
            continue
        if BAD_CHARS_RE.search(value):
            continue
        if value.lower() in PLACEHOLDER_VALUES:
            continue
        out.append((ref, value))
    return out


def sha8(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:8]


def scan(run_root, max_file_mb=5.0):
    run_root = os.path.abspath(run_root)
    cred_files = []
    for dirpath, dirnames, filenames in os.walk(run_root):
        dirnames[:] = [d for d in dirnames if d not in PRUNE_DIRS]
        for name in filenames:
            if name.lower() == CRED_FILENAME:
                cred_files.append(os.path.join(dirpath, name))

    declared = []  # (ref, value, cred_file_rel)
    unreadable = []
    for cf in cred_files:
        rel = os.path.relpath(cf, run_root).replace("\\", "/")
        for ref, value in extract_values(cf):
            if value is None:
                unreadable.append(ref)
                continue
            declared.append((ref, value, rel))

    violations = []
    files_scanned = 0
    skipped_binary = 0
    skipped_oversize = 0
    values = [(ref, v) for ref, v, _ in declared]
    limit = max_file_mb * 1024 * 1024
    cred_set = set(cred_files)
    for dirpath, dirnames, filenames in os.walk(run_root):
        if sanctioned_skip(rel_dir_under(dirpath, run_root)):
            dirnames[:] = []
            continue
        dirnames[:] = [d for d in dirnames if d not in PRUNE_DIRS]
        for name in filenames:
            full = os.path.join(dirpath, name)
            if full in cred_set or name.lower() == CRED_FILENAME:
                continue
            ext = os.path.splitext(name)[1].lower()
            if ext in BINARY_EXTS:
                skipped_binary += 1
                continue
            try:
                size = os.path.getsize(full)
            except OSError:
                continue
            if size > limit:
                skipped_oversize += 1
                continue
            try:
                with open(full, "r", encoding="utf-8", errors="replace") as fh:
                    text = fh.read()
            except OSError:
                continue
            files_scanned += 1
            for ref, value in values:
                if value and value in text:
                    hits = [
                        i + 1
                        for i, ln in enumerate(text.splitlines())
                        if value in ln
                    ][:10]
                    violations.append({
                        "file": os.path.relpath(full, run_root).replace("\\", "/"),
                        "ref": ref,
                        "value_sha8": sha8(value),
                        "lines": hits,
                    })
    violations.sort(key=lambda v: (v["file"], v["value_sha8"]))
    if not declared:
        status = "no_credentials_declared"
    elif violations:
        status = "violations"
    else:
        status = "clean"
    return {
        "schema": "credential-scan-v1",
        "run_root": run_root.replace("\\", "/"),
        "credential_files": sorted(
            os.path.relpath(c, run_root).replace("\\", "/") for c in cred_files
        ),
        "declared_value_count": len(declared),
        "unreadable_credential_files": len(unreadable),
        "files_scanned": files_scanned,
        "skipped_binary": skipped_binary,
        "skipped_oversize": skipped_oversize,
        "violations": violations,
        "status": status,
        "note": "聊天正文不在磁盘扫描范围；本回执不打印值本身。",
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-root", required=True, help="本场 run_root")
    parser.add_argument("--out", default="", help="回执 JSON 另存路径（不含值本身）")
    parser.add_argument("--max-file-mb", type=float, default=5.0)
    args = parser.parse_args(argv)
    if not os.path.isdir(args.run_root):
        print(json.dumps({"schema": "credential-scan-v1", "status": "error",
                          "error": "run_root not a directory: " + args.run_root},
                         ensure_ascii=False))
        return 1
    receipt = scan(args.run_root, args.max_file_mb)
    payload = json.dumps(receipt, ensure_ascii=False, indent=2)
    print(payload)
    if args.out:
        os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(payload + "\n")
    return {"clean": 0, "violations": 2, "no_credentials_declared": 3, "error": 1}[receipt["status"]]


if __name__ == "__main__":
    sys.exit(main())
