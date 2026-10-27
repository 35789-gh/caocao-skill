# -*- coding: utf-8 -*-
"""who9222.py — 浏览器占用实况探针（开工三查第 2 查）

回退到外部真浏览器+锁方案后，开工用浏览器前判断"是不是别人在用"：
  1. 查 9222 端口活不活（不活=浏览器未起，down）
  2. 活→列当前标签页 URL（空白/about:blank=idle；有页面=busy，列 URL 供判断归属）
  3. 顺带读 shotlock 锁主

用法: py -3 who9222.py
输出一行 JSON: {"9222":"down|idle|busy","pages":["url",...],"lock_owner":"A|B|null"}
判定建议：
  down  → 浏览器未起：拿锁后自己起（--remote-debugging-port=9222 独立 profile）
  idle  → 没人用：拿锁后直接连
  busy  → 有人在用（若锁 owner 不是自己批=对方没拿锁违规使用）→ 退避等待重查，别硬上
"""
import sys
sys.dont_write_bytecode = True  # 2026-10-13 新6: 禁 pyc 落包目录（包卫生）
import json, os, socket, urllib.request

LOCK = r'E:\Temp\vis-lock\lock.json'


def port_alive(host, port):
    try:
        with socket.create_connection((host, port), timeout=2):
            return True
    except Exception:
        return False


def main():
    state, pages = 'down', []
    if port_alive('127.0.0.1', 9222):
        try:
            with urllib.request.urlopen('http://127.0.0.1:9222/json', timeout=3) as r:
                d = json.load(r)
            # 2026-10-16 r16 修：/json 根必须是「非空、元素全为 dict 的列表」（真 Chrome
            # /json 恒返回目标数组）。空数组/非列表根 = 端口被非浏览器进程占用等异常形态
            # ——旧版会把它当 idle（「没人用直接连」必失败）；现与 404/非 JSON 同类按
            # err 处理。注：真 Chrome 空目标页的极端空数组会一并被判 err（保守取向）。
            if not isinstance(d, list) or not d or not all(isinstance(p, dict) for p in d):
                raise ValueError('unexpected-shape')
            pages = [p.get('url', '') for p in d if p.get('type') == 'page' and not p.get('url', '').startswith('devtools')]
            real = [u for u in pages if u and u not in ('about:blank', 'chrome://newtab/', '')]
            state = 'busy' if real else 'idle'
        except Exception as e:
            state, pages = 'err:' + str(e)[:40], []
    owner = None
    try:
        owner = json.load(open(LOCK, encoding='utf-8')).get('owner')
    except Exception:
        pass
    print(json.dumps({'9222': state, 'pages': pages[:5], 'lock_owner': owner}, ensure_ascii=False))


if __name__ == '__main__':
    main()
