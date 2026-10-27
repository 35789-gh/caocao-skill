# -*- coding: utf-8 -*-
"""shotlock.py — 双会话拍图/录屏互斥锁（2026-10-12）

两个并行会话共抢四样东西（CDP 浏览器 9222 / CMDPHOTO 终端 / 屏幕置顶 / ffmpeg 全屏录制）。
拍图或录屏前先拿锁，拿不到=对方正在用屏幕，等待轮询；干完立即释放。

用法：
  拿锁（等不到就自动等，最多 --wait 秒）:
    py -3 shotlock.py acquire --owner A [--wait 900]
  释放:
    py -3 shotlock.py release --owner A

规则：
- 锁目录 E:\\Temp\\vis-lock\\，锁文件 lock.json（O_CREAT|O_EXCL 原子创建）
- stale 判定：读 lock.json 内 ts 字段（非文件 mtime），ts 距今 > 600 秒视为对方暴死未释放，
  自动接管（接管前写 takeover 记录）。残余：时钟回拨/伪造 ts 只能推迟接管——判定信任
  写锁方时钟，不改判定逻辑（2026-10-16 r16 口径与 README 对齐）
- 退出码：acquire 成功=0（拿到锁），失败=2（等超时）；release 成功=0
"""
import sys
sys.dont_write_bytecode = True  # 2026-10-13 新6: 禁 pyc 落包目录（包卫生）
import argparse, json, os, sys, time

LOCK_DIR = r'E:\Temp\vis-lock'
LOCK = os.path.join(LOCK_DIR, 'lock.json')
STALE_SEC = 600


def read_json(path):
    try:
        with open(path, encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return None


def read_lock():
    return read_json(LOCK)


def try_acquire(owner):
    os.makedirs(LOCK_DIR, exist_ok=True)
    try:
        fd = os.open(LOCK, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        os.write(fd, json.dumps({'owner': owner, 'ts': time.time()}).encode())
        os.close(fd)
        return True
    except FileExistsError:
        d = read_lock()
        if not d or time.time() - d.get('ts', 0) > STALE_SEC:
            # stale：对方暴死，接管。2026-10-13 C10 修竞态：旧版 open('w') 覆写——
            # 两个等待方同时判 stale 会都接管成功（正是要防的双会话场景）。
            # 现改为：先删旧锁（仅当内容未变），再走 O_EXCL 原子创建，创建失败=对方已接管
            old = (d or {}).get('owner', '?')
            try:
                if d is not None:
                    d2 = read_lock()
                    if d2 != d:
                        return False  # 锁已被别人处理，重新走正常等待
                    os.remove(LOCK)
                else:
                    # 2026-10-16 r16 修：损坏锁（read_lock() 为 None）视同 stale 删了重建。
                    # 旧版此处跳过 os.remove，O_EXCL 撞现存的损坏文件 → 永远拿不到锁死等满
                    # --wait。注意与「创建中的空锁文件」区分：空/读不到=别人 O_EXCL 刚建好
                    # 还没写内容的中间态，不动它（C10 防双持有口径保持，O_EXCL 兜底）；
                    # 非空且两次读到的原始字节一致才删。残余窗口=二次读与 remove 之间的
                    # 直线代码（微秒级，与 release 墓碑法同级）。
                    try:
                        with open(LOCK, 'rb') as f:
                            raw = f.read()
                    except OSError:
                        return False  # 读不到（可能刚被删/被接管），回等待循环
                    if not raw.strip():
                        return False  # 空文件=创建中，别动
                    try:
                        with open(LOCK, 'rb') as f:
                            raw2 = f.read()
                    except OSError:
                        return False
                    if raw2 != raw:
                        return False  # 内容已被别人处理（接管/重建）
                    try:
                        os.remove(LOCK)
                    except FileNotFoundError:
                        pass  # 并发删除容忍，继续走 O_EXCL 争
                fd = os.open(LOCK, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
                os.write(fd, json.dumps({'owner': owner, 'ts': time.time(), 'takeover_from': old}).encode())
                os.close(fd)
            except (FileNotFoundError, FileExistsError, OSError):
                return False  # 竞争失败，回到等待循环
            print(f'[shotlock] stale lock taken over from {old}')
            return True
        return False


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('action', choices=['acquire', 'release'])
    ap.add_argument('--owner', required=True)
    ap.add_argument('--wait', type=int, default=900)
    a = ap.parse_args()
    if a.action == 'release':
        d = read_lock()
        if d and d.get('owner') == a.owner:
            # 2026-10-16 r16 修 TOCTOU（release 与 stale 接管撞车误删新锁 → 双持有）：
            # 旧版 read→check→无条件 remove 非原子——A 锁龄超 600s 后 release，读到旧锁
            # 之后、remove 之前 B 完成 stale 接管写新锁，A 的 remove 删掉 B 的新锁 → C
            # 也能拿锁 → B/C 同时持锁。墓碑法：先 rename 原子摘下，再读墓碑验证 owner+ts
            # 仍属自己才删；已被接管则尽量 rename 回去（LOCK 已被第三方重新创建时
            # FileExistsError → 弃墓碑保新锁）。残余窗口=rename 与验证之间的直线代码
            # （微秒级，比旧版 read→remove 全程窗口收窄几个数量级）。
            tomb = LOCK + '.tomb'
            try:
                os.rename(LOCK, tomb)
            except FileNotFoundError:
                print('[shotlock] release skipped (lock file gone)')
                return 0
            except FileExistsError:
                try:
                    os.remove(tomb)  # 上次 release 中途暴死残留的墓碑，清掉重试
                    os.rename(LOCK, tomb)
                except OSError:
                    print('[shotlock] release skipped (tomb conflict)')
                    return 0
            t = read_json(tomb)
            if t == d:  # owner+ts 都一致 → 确属自己，可删
                try:
                    os.remove(tomb)
                except FileNotFoundError:
                    pass
                print(f'[shotlock] released by {a.owner}')
            else:
                holder = (t or {}).get('owner', '?')
                try:
                    os.rename(tomb, LOCK)  # 是别人的新锁，放回去
                    print(f'[shotlock] release skipped (lock taken over by {holder})')
                except FileExistsError:
                    # 放回目标已被第三方创建：弃墓碑保新锁
                    try:
                        os.remove(tomb)
                    except FileNotFoundError:
                        pass
                    print('[shotlock] release skipped (new lock exists, tomb dropped)')
            return 0
        print(f'[shotlock] release skipped (lock held by {d.get("owner") if d else "none"})')
        return 0
    t0 = time.time()
    while True:
        if try_acquire(a.owner):
            print(f'[shotlock] acquired by {a.owner}')
            return 0
        waited = int(time.time() - t0)
        if waited >= a.wait:
            # 2026-10-16 r16 修：损坏/消失的锁 read_lock() 为 None，旧版直接 .get 崩
            # AttributeError（exit 1 冒充成功语义）；补 or {} 确保超时路径稳定 exit 2
            print(f'[shotlock] TIMEOUT after {waited}s (holder: {(read_lock() or {}).get("owner")})')
            return 2
        holder = (read_lock() or {}).get('owner', '?')
        print(f'[shotlock] waiting for {holder}... ({waited}s/{a.wait}s)', flush=True)
        time.sleep(5)


if __name__ == '__main__':
    sys.exit(main())
