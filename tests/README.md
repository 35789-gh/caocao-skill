# tests/（批四十立）

本包轻量回归 = `py -3 scripts/selftest.py`（编译 + canonical 一致性 + era 分层两态冒烟），改闸后必跑。

更重的行为回归靶子在包外（历史资产，勿重复建设）：
- `E:\DeepAudit\` 下的 java-audit-fixture 系目录（2026-10-15 批三十八 84/84 行为测试用）。
- 老卷真实 run_root（v7 `library/projects/`）可当存量场不追溯口径的对照样本。

新 fixture 建议按「最小 website 场四相（env→verify→close→verify-close）」脚本化进 selftest，
别再让行为测试躺在临时目录里易失（红队六轮 P2-10 判例）。
