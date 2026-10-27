# Mini 报告（步 11 才读）

第一条 `verified` 或第一批 3 条证据齐的失败/否证时读本文，不要在链审阶段读。**版式/嵌图/录屏/交付包全部现行口径认 `protocol/report-format.md`（规则 ID 引用），本页只管必交清单与触发。**

## 必交

- test-summary.docx + 同名 JSON（收口时在 reports/ 生成供闸核对；close 通过后移除或落 run/ 归档区）
- 每条 `verified` finding 独立 DOCX（reports/ 正位）+ JSON（收 `reports/json/`，不裸露正位）+ 证据目录。**finding 同名 JSON 不复述凭据实值**（credential_scan 递归扫含 `reports/json/`；复现包实值只进 DOCX）
- **交付 zip 必带一键 PoC 脚本，PoC 只加不减**（报告/录屏手动步骤不得因 PoC 省略；录屏末尾必加 PoC 收尾演示、必带运行前后对比）——细则认 `protocol/report-format.md` RF-PKG-04/05、RF-VID-16（2026-10-14 判例同步，沿革认 CHANGELOG）
- 源码收口另交曹操终审 JSON（可短）；正式 DOCX 只许分身 `report_layout`
- 未测/未闭环链在 test-summary 列 `coverage_gap`，不要藏。危险 sink 所在模块没起（IoT `${}`、BPM `Class.forName` 等）必须写成缺口，禁当「源码没有这类洞」；第三方版本命中但端点没起（jimureport CVE 等）同样写缺口，禁用没查公开库当「没有历史 CVE」

已存在的 `reports/<name>.docx` 不覆盖，冲突写 `reports/revisions/`。**正位最终只留正式 finding DOCX**；结案壳/工具壳废稿移 `reports/discarded/`，禁占正位、真卷只躺 revisions；`revisions/` 里的 finding 同样必须是正式通报。

**不出正式 finding DOCX 的洞类**：CORS（只进 `cors-audit/`）；源码场 swagger / `v3/api-docs` / knife4j / `doc.html` 接口地图（当地图用；黑盒匿名拿到全量地图才允许出信息泄露卷）；源码场传输加密硬编码密钥 / 可逆混淆 / 「解密失败静默放行明文」（内部对照料照用；明文直发实测 30001 不得按绕过出卷）；默认面板/端点泄露洞类（Druid 监控台、Actuator/heapdump、监控台默认口令、MCP 等框架端点默认泄露——还测、留档，不上对外提交清单，认 SKILL H-12）。

## 正式卷骨架（细则认 report-format RF-ELEM）

每条可交 verified（实测口径**中危及以上**）独立 DOCX = 正式通报（九要素正文 + 标准件，顺序与块内容认 `protocol/report-format.md` 第一节/第二节 + `~/.zcode/rules/vuln-report-format.md` 改号全套——**骨架 + 细则两层都过才算出卷**）。低危 verified 不出正式卷（levels 判 below_medium，闭环事实留 finding JSON，处置进 eliminations 段，不计可交、不向用户提——认 rules「不写」行）。禁用结案表/身份键表/BEC 台账顶通报；缺「我」、缺 `目标网站URL`（= 人打开的站；白盒场填项目官网，本地复现口只进复现步骤 Host）、缺全角＃、缺可复制整包 = 不合格。`test-summary.docx` 才允许总览表。

**重写线桥接**：老卷按新标重写的流水线场次，九要素之外另加「重放复测记录」段与「本场实测命令原文」段（位置与格式认 `v7 包 rewrite-pipeline-202610 长文（经 v7_root 解析）` §一——文件在 v7 包，本包未复制）；只读本库的分身在重写场据此补段，防漏。

## 身份

`run_id` / `target_identity` / `snapshot_id` 只进信封和角色 JSON，**不进** finding DOCX。8 块正文不许脱敏（RF-DOC-08）。卷内禁内部角色名与内部账指针（RF-DOC-09）。

## 触发

禁止等用户说「生成报告」；禁止步 6 一写完就出报告。步 10 对比可极短：只比身份键是否撞旧场；旧 finding 正文仍按 SKILL 收口才打开。

分身按触发当回合出正式 DOCX，**不要**等 close。本场结束/对外交付前主会话必须：

```text
py -3 <本包>/scripts/hard_gate.py --run-root <run_root> --phase close
```

`status=failed` 不得当本场结束。过关只认脚本写出的 `run/hard-gate-close.json`，手写 close-summary 不算。无合格正位 `reports/*.docx`（ZIP 头 + finding 8 块）或无 `02-cao-cao-shadow/` = failed。源码九人目录缺一不可（没活 not-needed；撞过滤的曹冲禁假 not-needed）。`cors-audit/` 必须有 Origin+ACAO 实测。网站也要 JS 清单。已有 verified 必须曹操签字。收口 credential_scan 必须 **clean**（空账和外泄都 failed）。用户叫停或缺目标停工不要跑 close 冒充交付。司马懿假「无网站」、只打第一段、欠图工单未关、信封假 not_started = close failed。
