# 曹操砍单（相对 v7；沿革认 CHANGELOG）

v7 活包一行未改。本文件说明本包**故意不做**的手续（相对 v7 的省手续口径）。

## 哈希

| v7 | Mini |
|---|---|
| `required_skill_reads[].sha256` 必填 | 删。读卡写文件名 |
| dispatch 嵌 launch/read_ack 哈希 | 删。文件在即可 |
| DEC / handoff `reviewed_inputs[].sha256` | 删。只列路径 |
| `applicability_review.sha256` | 删 |
| 链锁嵌上一条 verification sha256 | 删。记 chain_id + 占用者 + 时间 |
| 角色自己算 JSON sha256 再填回去 | 删。脚本的事 |
| 凭据 manifest 每改刷指纹当交付 | 删。收口扫一次外泄 |
| SendMessage 带协议文件哈希 | 删 |

留下：材料 sha256 一次（`scripts/material_hash.py`）；收口 `credential_scan` 必须 clean（空账不算过）。作业由 `scripts/hard_gate.py` 认真文件/真端口/真回包，填表过关不算；手写 close-summary 不算过门。

## 方法论（已装箱）

| 文件 | Mini |
|---|---|
| v7 `references/php-methodology.md` | 同源拷回（2026-10-15 复核批加消歧头、修两处引用，冲突以 SKILL 为准）。见到 PHP / `.inc` / `include $var` 才读；网站场不读 |
| v7 `references/deterministic-regex-and-java.md` | 拷回（**含一处修正分叉**：`SOURCE_JAVA_REQUEST_V5` 正则去掉 `@` 前的 `\b`、补 `ModelAttribute`/`getParameterValues`——修订分叉；见 CHANGELOG）。见到 Java/Spring 或解释确定性正则才读。命中仍是 candidate |

这两份**不是**每个子代理常驻。不因此把 v7 整棵 `references/`、`07-tools/`、五份契约灌进来。walker（`auto_chain_scan.py`）只钉候选，不代替方法论正文，也不能把命中写成 verified。

**没有装箱长文不砍能力。** Go/Python/Rust 等没有 PHP/Java 老师傅文 ≠ 不挖：walker 短规则 + PHP 拼接流 + Python 函数内污染继续扫；没规则走文件 + 追链四本（入口/链路/反证/覆盖，不是第六个 JSON）。walker 账 `languages_without_rules` ≠ 计划表 `coverage_gap`；`methodology-gap.json` 可选笔记。禁止把「CUT-LIST 没这份文件」当能力上限，也不要把 PHP 文里的 Doctor/哈希/`website-only-two-role` 当 Mini 还要做的手续。

**召回跟 Deep 分桶。** `scripts/hybrid_discovery.py` 调 v7 `07-tools/hybrid_discovery.py`（不复制、不抹平）：PHP/JS/Ruby `regex_first`；Java/Python/Go/C#/Kotlin/Scala/Swift `vector_first`；混栈 `mixed`。Mini 另补四句 lexical，不改 strategy。命中仍是 candidate，不能顶 walker；向量没起来走 lexical 不算硬闸 fail。不是第六套硬账。

## 加载（本包布局）

| v7 always_load | 本包 |
|---|---|
| 五份契约全文 | 不进子代理，口径压进 SKILL |
| agent-orchestration 41KB / current-run-validation 53KB | 不加载；检查器用 lite |
| compact-core / closed-loop 全文 | 闸页（gates.md）各一表 |
| 曹操卡 38KB / 郭嘉 25KB | 小卡（roles/*.md，按需读一张） |
| 宿主启动规则整本每轮 | 子代理不读；主会话按宿主约定读（视觉门/闭环/原图仍生效） |
| v7 `references/` 其余 19 份 | 不整包复制；PHP/Java 两份按需装箱 |
| v7 `protocol/` 约 30 份契约 | 不进子代理；口径压进 SKILL + protocol 四页（gates / report / **report-format** / website） |
| v7 `07-tools/` | 不复制进本包；需要时调 v7 路径。Mini 自带 walker + 召回包装，只出 candidate |

## 编制 / 产物

- 开局只两人；源码九人整轮现身，没活的人收口前 not-needed 小 JSON（禁止开局预填）
- 第一份 verified 立刻报告（不设场次 token 封顶、不按额度切段停）
- 正式 DOCX 仍只许分身；finding 通报仍九要素（8 块 + 软件与厂商信息），不改结案表；正位废稿必须挪走
- 撞过滤仍要曹冲过滤账，假 not-needed 不算现身；CORS 仍要实测（Origin+ACAO）；网站仍要 JS 清单
- close 只认脚本回执；禁工单空转代替主会话截图；禁司马懿「local_source 无网站」假 not-needed / 只打 native 未登录；禁信封永远 not_started 却 close；禁验证计划 pending /「等窗口」却 close；禁聚合只起登录壳、点名 IoT/pay/积木报表不入账；禁 swagger/菜单/链审 grep 顶关键字账或 JS 清单；禁用关键字/JS/swagger 顶自动链扫描或把 walker 命中写 verified；禁为对检查器哈希改卷

## 不砍的含义

11 步、双拓扑、司马懿隔离、视觉三态、闸分层、类型闭环、CORS 独立目录实测、凭据内部两落点（正式正文写实值）、分身出正式 DOCX、曹冲过滤账、危险 sink 模块必起、第三方版本必须查 CVE、司马懿两段黑盒、欠图未关不得 close、信封进度必须回填、计划 pending 不得 close、点名模块必须入账拉起、作业机械闸（`hard_gate.py`）。
复杂/高危链必录视频（口径集中 `protocol/report-format.md` RF-VID）；有混淆须解混淆 + 追密钥 + 完整可控账才算采集完成。
关键字定位、JS 路径、自动链扫描、sink-runtime、第三方 CVE 五套互不顶；召回层不能顶这五套；无 PHP/Java 长文时 walker 短规则继续扫，不把缺长文当停工。

