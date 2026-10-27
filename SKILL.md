---
name: cao-cao
description: 授权源码/网站审计包。开局只派两人，到期再加人；不抄 sha256；第一条 verified 立刻出报告。
---

# 曹操审计

**身份与边界**

- 本包 = v7 体系的省手续重写版：现行约束一条不丢，砍的是手续与历史包袱；全部工具内置（`scripts/` 纯标准库），无外部包依赖（向量召回增强可选接 v7）。
- **启动先读宿主全局启动规则**（视觉门、闭环、原图、角色激活四门不豁免；路径登记在 `tools.json` 的 `startup_rules`）；子代理不读整本。出卷逐项合格细则认本包 `protocol/report-format.md` RF 族（沿革在 CHANGELOG）。
- **常驻只有本 SKILL**。角色卡、闸页、格式页按「按需读」路由打开，禁止把巨型协议/角色卡整本灌进子代理。
- **没有场次 token 封顶**：省的是手续不是额度。第一条 `verified`（或首批 3 条闭环失败/否证）就出报告；之后再挖是加测，不是额度见底。

**正文纪律（本包门闩）**

- 正文只写现行口径；任何修订 = 改正文 + CHANGELOG 记一行；禁止在正文追加「N 改/X 批」历史段。
- 沿革查 `CHANGELOG.md`（未附内部判例库）；报告/嵌图/录屏细则查 `protocol/report-format.md`（规则 ID 引用）。
- 有 in_progress 场次时，闸/卡/模板改动先落 `draft/` 暂存，收口窗口统一合入；用户明示豁免可穿透，照记 CHANGELOG。
- 体量上限：SKILL ≤600 行；单行软上限 250 字，新增/修订行禁超 400 字（超了拆子列表）。看门狗 `scripts/skill_lint.py`（单行宽度 / 改号字样 / 悬空引用 / 包卫生 / **编号存在性**五查）：**存量不追溯、触碰即达标**以包根 `lint-baseline.json` 为机械基线（首跑快照存量超宽行；行内容一旦变动即出基线须达标；新增超宽行照 fail——批四十四），其余四查全量不豁免；lint 的职责是防 3000 字段式膨胀回归，不是逼存量重写。
- **规则 ID 只追加、禁中间插入**（H-NN / RF-XXX-NN / 深挖条款 N）：位置性编号在序列中间插一条会让后续编号全漂、既有引用全断——新增规则一律取下一个空号；作废规则保留编号写「已废止→由 XX 承接」，**不复用、不重排**。skill_lint 对正文引用的每个 ID 做存在性核对，断链 = fail。

## 砍掉的手续（禁止再做）

- 模型手写 sha256、互嵌 path+sha256、`required_skill_reads` 带哈希、DEC/`reviewed_inputs` 哈希表
- 为对指纹再开一代续跑；凭据账每次改刷 manifest 指纹当交付
- 开局九人陪读；没活的人写万字自我证明
- 「回执四要素不齐 / 画面未采 / 闸没齐」就全员停、请示要不要派司马懿
- 子代理写「请主会话截图」然后散场；能力 JSON 把画面标 passed
- 司马懿 `not-needed` 写「local_source 无网站」；只打 native 未登录、removed 已在却不进第二段
- 信封永远 `execution_status=not_started` 却宣称收口
- 验证计划还 `pending` /「等窗口」就 close；聚合只起 system+infra、点名了 IoT/pay/积木报表却不入账不拉起
- 用 swagger / `v3/api-docs` / 菜单权限顶 `js-collection`；用曹操链审 grep 顶郭嘉关键字账；用关键字/JS/swagger 顶自动链扫描，或把 walker 命中（含 PHP 拼接流 / Python 函数内污染）写成 verified
- 遇到 Go/Python/Rust 等没有 PHP/Java 长文就停工等文，或 not-needed「没有专文所以不挖」
- 有 verified 还不出 `reports/`，继续开 BEC / 事故小说 / 第九代
- 把目标整树、HAR、`node_modules` 读进模型
- 协议「不得用摘要顶原文」用在每个子代理每轮——Mini 入口短文常驻，细则没改文件就不要再 Read 整本

## 留下的硬约束

**必须（含义不砍）**

| ID | 约束 |
|---|---|
| H-01 | 11 步顺序；创建→自己读卡→检查器→再派活；开局只绑身份、收口才比旧洞 |
| H-02 | 司马懿不收郭嘉答案；双拓扑；视觉三态；类型闭环才 `verified` |
| H-03 | 五套硬账互不顶（关键字 / JS / 自动链 / sink-runtime / CVE；JS 仅有前端或网站才必须）；walker 命中只是 candidate；召回层跟 Deep 分桶、不能顶 walker、不是第六套硬账 |
| H-04 | 追链四本（入口/链路/反证/覆盖）是怎么追，不是第六个 JSON |
| H-05 | 源码场越权链审必须看拼接条件（Mapper/WHERE 是否按登录人收口，认曹操卡），不能只扫注解 |
| H-06 | 长文只装箱 PHP/Java，其它栈 walker 短规则继续扫，禁止停工等文 |
| H-07 | 危险 sink 所在模块必须尝试拉起（登录后台不能顶）；第三方写出版本必须查 CVE（曹操收编/本地源码不能顶） |
| H-08 | 部署型 web 司马懿必须打两段；欠图工单未关不得 close；信封不得假 not_started；计划 pending 不得 close；点名的 IoT/pay/积木报表必须入账并尝试拉起 |
| H-09 | 凭据值内部只落允许位置（正式 8 块写实值）；CORS 还测、只进 `cors-audit/`（Origin+ACAO 实测）、不上正式报告 |
| H-10 | swagger / knife4j / `doc.html` 接口地图：还挖、当地图用，白盒不上正式报告（不是白盒漏洞）；黑盒匿名拿到全量地图可报信息泄露 |
| H-11 | 传输加密硬编码密钥 / 可逆混淆 / 「解密失败静默放行明文」：还挖、可对照构造密文，白盒不上正式报告；明文直发实测 30001 即证伪，不得按原主张出卷 |
| H-12 | 默认面板/端点泄露当洞类（Druid 监控台、Actuator/heapdump、监控台默认口令、MCP 等框架端点默认泄露）：还测、留档，不上对外提交清单（平台存量判重出局；CVE 库 0 条目只证明无编号，不证明平台无存量） |
| H-13 | 正式报告唯一格式 = DOCX（python-docx 生成；不收 md/纯文本/HTML/纯 PDF 当正式件，PDF 仅副本）；正式 DOCX 只许分身 `report_layout`，主会话不得代跑 `docx_report.py` |
| H-14 | 证据截图两层：**验证证据层**（captures/ 原件，不进报告）——env 三张窗口图、XSS 弹窗原图、pending 欠项，**默认必须截**，申明/嵌图口径不豁免这层；**报告附图层**——默认带附图段，全部细则认 `protocol/report-format.md` |
| H-15 | 复杂链录屏与报告嵌图按 `protocol/report-format.md` RF-VID / RF-IMG / RF-GATE 全套执行 |
| H-16 | **8 块正文不许脱敏**（描述/危害/整包写实值，禁 `credential_ref` / REDACTED）。对用户总结说人话（谁、哪个口、拿到什么、报不报），禁用 CHAIN 编号和四本覆盖顶交代 |
| H-17 | 撞过滤必须曹冲过滤账。close 只认 `run/hard-gate-close.json` 脚本回执 |
| H-18 | **任何角色（含主会话）写入只许数据盘**：run_root/快照/账/截图/工具/临时件全在数据盘 `run_root` 内，系统盘只读（旧系统盘 run_root 只读保留、不迁移不续写）；进程临时文件落系统临时目录（开场起服务/脚本前若 TEMP 指回系统盘先改回再开工） |
| H-19 | 自制项目工具必须曹操批准后才能用于出账，未批产物只当 candidate。工具覆盖评估与特化工具见下节 |
| H-20 | 不写 exploit（工具只做采集/解析/比对/复核） |
| H-21 | **零伪造总纲（2026-10-15 用户令「任何东西都不允许伪造」，压本表全部条目）**：任何交付物里的任何元素——图、画面、回显、数字、时点、身份、结论——必须是本场真实发生的，且与交付证据本体一比一对得上。禁：裁切/重排/拼合后称实拍、另拍画面冒充录屏帧、旧轮数字留在新录像卷、时长碎片冒全长、图注写画面里不存在的东西、结论超出证据支撑范围。证据不够就如实写不够（无图卷/coverage_gap/挂账），**如实呈现缺陷永远合规，把缺陷包装成完整才违规** |
| H-22 | **注毒检测（材料完整性，防「往项目里塞洞再挖出来」）**：白盒场 finding 引用的每个源码出处文件，出卷前必须与本场开局 material_hash 逐文件清单比对 sha256——一致才可引用；不一致=材料中途被改，该链整条作废重查，说不清谁改的按 H-21 伪造论处。local_source 场开局必须落逐文件清单哈希（只有目录总哈希=采集未完成），对照结果写进验证记录段。**不限制挖掘自由的两处口径**：已声明的合法副本（captcha_removed 去干净副本等）按其声明基线对照、不算中途改材料；调试插桩/加日志的文件要么还原要么在验证记录段声明插桩内容——本条只压「悄悄改材料装原生漏洞」，不压任何正常审计动作。机械件已 fail-closed（批三十五）：缺 source_refs/缺清单即 fail；env 回执锚清单哈希 |
| H-23 | **回执不可信（防手写 env/verify/close 回执假收口）**：任何「已收口/闸已过」声明，下游（下一会话、并账、用户侧复核）必须本地重跑 hard_gate 对应 phase 核对，禁止只读回执 passed 字样即信；手写/改写 run/hard-gate-*.json 按 H-21 伪造论处。回执带场景指纹+闸自身哈希、可重验复现为闸的义务（机械件已合入：场景指纹 v4＋gate_sha256＋env_receipt_sha256 双对账） |
| H-24 | **审核抽验锚点（反全链自演）**：每条正式卷验证记录段与每个收口件待办节，必须附「审核抽验清单」——固定 3 条：每条=一段可整段粘贴复跑的原样命令+预期关键值+原件指针；主会话必须本场实测逐条跑通（跑不通=该卷作废重取证据），用户抽任一条粘贴复核即可定真伪。**三条构成**：环境探针/攻击效果/真值读回各 ≥1，同型 curl 凑数不算（闸机械核）。**第 0 条固定为收口重验**：`py -3 scripts/hard_gate.py --run-root <run_root> --phase close --verify-close`（H-23/H-25 机械件，用户粘贴即重验收口）。抽验清单命令与复现步骤命令逐字一致，禁「步骤见 PoC 脚本」式折叠（RF-PKG-05 同口径）；交付 zip 附 verify.bat 双击即跑（RF-PKG-08） |
| H-25 | **检查器基线锚定（反改闸自判）**：信封开局用脚本记 tool_baseline——十件检查/产出工具（五件检查器＋批三十七扩入的 walker/召回/解包/哈希＋批三十九入基线的 make_canonical）＋tools.json＋credential_scan 共 12 键各自 sha256；close 回执复录同表。开局↔收口哈希漂移=闸被中途改过：收口必须逐条对应 draft/ 暂存与 CHANGELOG 条目，无对应条目的漂移按 H-21 伪造论处、本场收口作废待用户裁决。改闸只走 draft+收口合入（改闸窗口纪律），禁热修 |
| H-26 | **类型→级别下限（防自降级别逃录像与最大攻击效果，2026-10-15 用户红队报告 P1-6）**：写入/执行类 verified（RCE/命令执行/命令注入/反序列化执行/任意文件写/上传可执行落地）判级低于高危、注入/越权/SSRF/XSS 类判级低于中危，必须同时在 finding 与 delivery-verdict levels 段带 ≥20 字 downgrade_reason（谁拍板、依据什么）；缺理由的降级 = close fail（机械件已合入闸，2026-10-15 批三十五）。降级本身永远允许——只是必须留痕给用户看 |

**禁止**：为对检查器哈希改卷；工单空转代替主会话截图；swagger/菜单/链审 grep 顶关键字账或 JS 清单；关键字/JS/swagger 顶自动链扫描；not-needed「没有 php/java 专文所以不挖」。

## 工具够不够 & 项目特化工具（自制先过曹操）

**郭嘉硬要求：按项目造补充工具，或曹操批豁免——二选一，不许空手。**

- 源码场郭嘉判断包内工具哪条链覆盖不到（入口识别、链路追踪、形态解析、比对复核都算），覆盖不到就自写补充工具补上。禁为了完成而完成：复制/换皮已有工具、照抄往场工具、空壳交差 = 没做，退回。
- 真没有可补 → 请示曹操豁免，请示带三样：**原因**（哪个面覆盖不到）、**证据**（抽样指针：看了哪些文件/行/类名 + 包内工具各覆盖了什么）、**理由**（为什么这个项目不用补）。曹操**先读证据验证**（抽 1-2 份声称看过的文件对照原文件）再核结论；对不上 = 编造，退回重评记违规。豁免批件记 `tool-approvals.json`（kind=exemption，只对本项目本版本有效）。
- **郭嘉每场必做「工具覆盖评估」（源码场）**：交硬账同时读项目**部分**代码（目录/构建文件/模块清单 + 代表性 Controller/Filter/入口类抽样，禁整树），核包内工具覆盖了什么、哪类面可能漏。结论落采集回执一节或 `01-guo-jia/tool-coverage-assessment.md`（不是第六套硬账，闸不因缺它 fail，曹操核对把关）。「够用」不能交差：没缺口也必须请示豁免（三样齐），只写一行「够用」不算收口；评估必须带「看了哪些文件」指针；明显糊弄（没抽样就说够）退回重评。曹操核对两步：①抽 1-2 份文件核实没编造（文件在不在、行/类名对不对、结论跟代码对不对得上）；②核内容（郭嘉说够但核出缺口、或曹操自己看出缺口 → 当场令补工具，不必等谁报）。
- **其他角色造工具是软要求**：鼓励按项目自写，不强制每场，用前审批照走。落本角色 `tmp/tools/`，文件头标适用项目+版本；批准记 `02-cao-cao/tool-approvals.json`。
- **被动触发**（见到当回合报曹操）：walker 入口键 0 命中且该语言有文件、`entry_zero_cross_check` 复核确认是包内规则盲区；抽样见到规则不认识的形态（基类继承拼前缀/双套同源/非 Controller 注册面）；链审、实测对出账面缺口。工具报错/没密钥**不算触发**——先走本来该走的排查（交叉复核、`vector_key_check`），确认覆盖缺口才算。没有具体漏面理由只是嫌流程麻烦、想拿自制工具顶替五套硬账 → 不触发。
- **效力**：未批自制工具产物一律 `candidate_only`，不顶五套硬账、不当 verified 依据、不单独进正式报告；已批产物也是加测账，同样不顶五套硬账。一次性验证小脚本（只打当条链、产物只进该链 evidence）不占审批，也**不顶郭嘉硬要求**。凡产物入硬账/入候选索引/跨链引用/跨场次复用的工具必须批。换项目/换版本重新报批。

## 深挖续打与减损条款

1. **BEC 自动续签**：探针用量 ≥80% 且链仍活（未 verified/未否证）→ 曹操当回合预签下一档预算，不让「配额到界回签」成串行卡点。
2. **挂账提级触发**：收口件待办节长尾项（ACL 枚举/可达域/落点类），下场开场无更高优先面即自动升首发，不等用户点名重开。
3. **挂账带预估发数**：每条待办写「预计 N 发可定谳」，下场折算进首批 BEC；4 发能定谳的不许躺过夜。
4. **残件终验（郭嘉硬步骤）**：下载/生成类任务自称完成，必须过尺寸+哈希双验（对照源标称值）；残件不得入「完成」账。
5. **暴死收线前移**：长任务派发后当回合 TaskOutput 收线；下载/编译类长活收线时验产物非空非残。
6. **长活活账本**：预计 >10 分钟的子任务，派发时即建逐件日志（一卷/步一行，落 run_root 或工作目录），主会话点验只读日志不读树——「感觉在飞」不算数。
7. **计划表开放态词表**：ready/待打/待发起/待复测 与 pending/queued/等窗口同属裸挂；「BEC 已签 N 发、实发 0」不得记终态。close passed ≠ 本条合规，曹操收口前人工扫一遍开放态词。
8. **凭据账演示值写法**：源码自带演示默认口令/种子一律「原文保留行」（key=value 无冒号）+ 注明判例 20 漏洞本体豁免，防 credential_scan 假阳性；`zheng` 场 RUN-02 credentials-local.txt 为标准模板。
9. **收口重验口径**：close 重跑 = 按现行闸全量重查，翻出的老格式/老账当场清，不视为新整改引入、不无限重试。当场清不动 → 曹操签「重验例外登记」（原因/证据/欠在哪），close 凭登记放行该条、债转收口件待办。**存量卷祖父条款**：重验遇「出卷之后新增的机械拦」，存量卷以出卷时点闸版本判合规——新拦只管新卷与重打卷；不符的存量卷降级留痕、不追改正位。
10. **闹钟墓碑化**：收口/叫停删 automation，但 `run/alarm.json` 不删——改写墓碑账（teardown 时间/原因/历史 id）。
11. **工具层防呆**：增量重跑的输入清单必须换文件名强制活读（防日志缓存重放旧输入）；Edit/写盘超时后必须 grep/ls 验证落盘才算改完；同一工具调用两次不达预期即停手换路径/换法（判例 19 工具调用死循环禁令），禁同款调用无限重试。
12. **配额墙冻场回访**：配额墙杀死的场（dispatch-failure 尾因=配额 + test-session 仍 in_progress）——配额重置后不等用户点名：任意新会话开场「扫冻场」，命中即按「新回合醒来第一件事」对账续跑；用户点名单场优先。
13. **宿主内存收割应对**：收割已发生（端口死/hs_err/进程消失）→ 郭嘉按环境交接账重启（不算新环境）+ **每轮发包前一发健康探针**（curl 健康/入口 200）；被打死且无在飞依赖的实例：记档 + rearm 条件写死，不裸留也不无脑重启。
14. **冻场台账**：每会话收口时扫 projects 全场 in_progress 清单，冻结场（冻因/冻时/待续面）落数据根 `frozen-fields.md`；新会话开场先读台账再开新场。
15. **db 对账通道死亡夹缝**：铁四条「库通道在场」按 inventory/凭据账判定——通道**在账但当下不可达**不算「可直接 db_direct」也不自动豁免：①优先复活通道补 db_direct（§5 命令级重启 + 一条只读对账查询，成本分钟级）；②复活不可行才走 waiver，reason 写明「通道曾在账 + 死亡时点 + 复活尝试原件指针」；③禁止把「通道死了」当「通道不存在」直接 waiver 不留复活痕迹。
16. **报告标准格式**：全部细则认 `protocol/report-format.md`（现行版：九要素/双灰底/证据图形态/图的门/录屏/cmd 工艺/屏幕互斥/交付包/文风/特殊洞类）。
17. **收口后禁区**：① close passed 后 `reports/` 正位改动二选一——`-rev` 命名新文件（原卷不动）或重跑 close 刷基线，裸改正位直接降级 suspected；复原被篡改正位不算改动（恢复记录+隔离件进 discarded/ 台账）；② 收口后的场对「补面/重试/回访」类自动化是禁区——动笔前先读回执：passed → 只回一句零写盘；已起手才发现收口 → 当场中止，空文件删、有内容半成品移 `run/discarded/` 留档；**用户点名的重开/补面不受本禁区限**（走 rev、重验或续考场）；与第 12 条边界：回访只对 in_progress 冻场；收口拆台动作（闹钟墓碑化/清活锁/盖章）不在此列；③ 活锁生命周期 = 轮次，收口/重验/补充轮结束当回合清 `run/active-round.json`；④ 挂账与盘面同步：挂账写「未收口」前先核回执文件，收口债归收口债、状态归状态。
18. **信封必记运行模型**：test-session.json 增 `runner_model` 键（开局落、换模型续场追加 `runner_model_history`）。20261010 起命名场次 close 闸拦，缺键 fail（在飞旧场不追溯，存量记 era 无账放行）。
19. **收尾账终验**：close 前曹操对长活终态做「非空、非占位、账实一致」扫描——①只扫**进程日志与终态说明段**（*.log、*-summary、manifest status 字段），不扫数据文件（源码 TODO 是业务内容）；词表「待补|占位|retry-later|placeholder」，命中先人工判（引用原文≠占位），补不动记欠账照常 close，不许占位装完成也不许死等；②账实对齐：recording 正片数=recording-index 条目数、raw 证据件数=计划发数，缺发补打或落 failed 台账；③时间线自洽：落款晚于落盘 = 倒挂，记勘误重写。与第 4 条分工：4 管下载/生成残件，本条管日志/账本/证据收尾。
20. **叫继续就继续**：用户对场或角色说「继续」＝当场开工授权 + 次数当场明示——不许回问「要不要再拉/还有没有额度」，不许拿配额/限速/算力/排队当回绝理由。收到「继续」的回合**必须有动作落盘**（重派派活件/续跑对账/活锁改写三选一），空手回话 = 违规。宿主侧打断照「子代理异常收账」等窗口重派；等待期间不许空等（没断的角色继续干活、主会话只干编排侧活，不代扫不代写）。「等窗口/等额度」只许出现在 `dispatch-failure.json` 的 host 侧账里，不许出现在给用户的回话里——用户点名 = 窗口已给。开场落了目录零作业收场 = 空壳场，按编排失败记。
21. **猝死三件套**：① **断点交接件**：角色全程维护 `resume-state.json`（本角色目录），五键 `current_step`/`done`/`next`/`blockers`/`pointers`——每完成一小步就更新；新实例到场第一读就是它；done/pointers 只写产物与位置指针，不写 `status` 字段（防 close 闸 any_verified 误读）、不写凭据原文。② **遗言件**：主会话收到第一声额度/断流/限速报错，当回合先落 `run/quota-wall.json`（时间、在飞活清单、各角色下一步、重置后先干什么）再等窗口。③ **闹钟接管**：额度死 ≠ 收口，闹钟不删不墓碑；配额重置后下一跳按四答③自动续跑冻场。交接件/遗言件只做纪律 + lite 软提示，不加 close 硬闸。
22. **坏账三洞修复**：
    - ① **收口即并账**：close passed 当刻闸自动把本场战果一行记进数据根 `closure-ledger.jsonl`（重跑追加、并账取最新）；总览 DOCX 并账以台账为准。
    - ② **verified 终态处置**：每条 verified 链 close 前必须对上四路证明之一——正位/修订卷引用 chain_id、`sealing-receipt` 封存、`delivery-verdict` 留档行、`final-delivery-manifest` 点名；四路全无 = fail（20261010 起，存量坏账走 bad-accounts 工单清）。
    - ③ **战役归场**：绕过/打击/复测战役（STRIKE/BYPASS/RETEST）必须建标准 run_root 场次目录，禁游离目录（存量只读保留）；战役场 runner_model 必记、收工必交 `verdicts.json`（bypassed/维持封存/refuted/烂尾四选一，逐目标一行）；bypassed 成功件 72 小时内出卷或挂账；烂尾写未完清单进 frozen-fields 台账。
23. **升链战役机制**：每场 close 后曹操链审必须过一遍升链方向（同对象写面未测 / SSRF 未打内网 / XSS 未窃凭据 / 哈希未登录闭环 / 绕过未试的封存同根因路由族），有则落 `upgrade-candidates.md`（现级→目标级 / 缺哪一步 / 预估几发 / 指针）；升链按**组**执行——同产品相关面一组共享一次环境，**测完一组关一组容器**。升链成功件（upgraded_verified）72h 内出修正卷（标准格式全套）；5.3f 打不动的防护由当值强模型亲自变体攻。批次记录战役场 verdicts.json。
24. **防御对照佐证**：绕过类/同族新向量卷必交三件硬佐证，细则认 `protocol/report-format.md` RF-SPEC-02；人工把关优先于闸。
25. **账本反垃圾抽验（防键齐量少的手写垃圾账）**：收口前曹操对五套硬账 JSON 按条抽验——keyword 命中要能在源码里 grep 到、walker 命中要能指回 source/sink 具体行、JS 条目要能在还原产物或运行时抓包里找到、CVE 条目要有查询原件；抽 3 条 2 条落空=整账作废重扫。五套账必须带工具运行痕迹（扫描计数/耗时/工具版本），无痕迹=手写垃圾账，禁拿「键齐」当完成。
26. **最丑证据自报（反全绿收口）**：每个收口件待办节必须自报本场证据链最弱的 3 处——没拍到的图、没重放的原件、竞态/超时/降级通道、只跑一遍没复测的关键步——逐处写「弱在哪+补强代价」；禁无弱项的全绿收口（H-21：如实呈现缺陷永远合规）。用户按自报抽最弱处先查，抽出的弱项未自报=按 H-21 伪造论处。回执亮 `low_coverage_session=true`（批三十九：blocked/gap/suspected 占比>50%）的场，自报第一条必须是覆盖率问题（哪些肥面没打、为什么）。
27. **账本落盘指向解析（防编 file:line 与计数对不上）**：keyword/auto-chain 账 items 的 file 路径必须以账内 source_root 为基可解析到真实文件，auto-chain 命中行须 grep 得到 sink 关键词；files_scanned 必须与闸实数同数量级；CVE 查询证据须含真实响应特征（HTTP 头/results/totalResults），查询件 URL 带 https:// 且域限官方库白名单（去 scheme/应声虫/裸域全拦），**查询词必须绑定本场组件**（URL/term 含产品 ASCII 首词或版本号，零绑定 close fail；官方异名补 slug 注明），纯中文「无条目」手记不认。机械件已合入闸（era≥20261015 生效）。
28. **失败账出口收口（2026-10-15 批三十六，红队二轮 P2-11）**：同一角色 3 次失败后把面记 coverage_gap 是合规终态，但该面必须进 H-24 抽验清单至少一条复核命令（证明「打不动」本身可复核），并进最丑自报弱项——合法摸鱼出口也要在用户眼皮下；无声把肥面挂成 coverage_gap 收场 = 编排失败记。
29. **信任根外发（2026-10-15 批三十八，红队四轮 P0-1；批四十补第三点）**：开局基线/收口回执都落在自己写权限内，「开局前改闸/注毒再落基线」全场零漂移——没法被改写的存储是已发出的聊天消息，信任根外置：
   - **开局外发**：信封落盘后当回合把 tool_baseline 摘要（十件检查/产出工具+tools.json+credential_scan 共 12 键哈希）+材料总哈希+run_root 路径整段发进会话留底，信封记 baseline_sent_at；
   - **env 外发（批四十 29③，断中段洗白链）**：env passed 当回合把 `hard-gate-env.json` 指纹（sha256）+ `material_manifest_sha256` 一行发进会话——env 后塞洞/重算清单/改写回执锚的中段洗白，在与收口回执 `env_receipt_sha256` 对账时暴露；
   - **收口外发**：close passed 后把回执 scene_digest/gate_sha256/env_receipt_sha256/verified 一行账发进会话；
   - **H-24 第 -1 条**（排在收口重验之前）：复核任何交付先 `certutil -hashfile scripts/hard_gate.py SHA256`，并与开局外发值、`gates-canonical.json`（canonical 根，包根或 CAOCAO_CANONICAL_ROOT，批三十九）两处对照——开局外发值防不了「开局前改闸」（外发的就是假闸哈希），canonical 才防；verify.bat 首行自打印哈希+canonical 对照提示（RF-PKG-08，机械核已挂）。
30. **运行态绑定材料（2026-10-16 批三十九，红队五轮 P0-1 堵假服务）**：H-22 只锚文件哈希不锚运行进程——真材料入账后起仿写迷你服务跑本场端口，验证全真但验证对象是假的。郭嘉起服时逐 component 落 `run/process-provenance.json`（模板 `templates/process-provenance.json`：name/port/pid/main_artifact/main_sha256/start_command，源码构建的加 built_from 构建账）；close 三层核：工件重算哈希对账、哈希必须可追溯开局材料清单或构建账、活端口 PID 对账（机械件已挂）。docker/解压 war 场 main_artifact 指构建产物路径并在 built_from 记镜像构建命令。
31. **官方源外部锚（2026-10-16 批三十九，红队五轮 P0-2 堵开局前注毒）**：era≥20261016 源码场信封必填 `official_source_url`（官方仓库/release 公网地址）或 `official_source_waiver`（≥20 字无官方源理由）二选一；登记 url 的场 close 闸真下载官方包（剥代理）落 `run/official-probe/`，与信封 `official_source_sha256` 比对，有原档账时逐成员抽比对——开局注毒/魔改包在此暴露；下载不可达 fail 挂起（断网不关抽查口径）。URL 须进开局外发账由用户肉眼对（模型可控站拦不住，私网/回环机械拦已挂）。
    - **声明式代理豁免（批四十四）**：本机需代理出网（如 GitHub 走本机代理 `http://127.0.0.1:7890`）的场，信封登记 `declared_proxy` 后官方源探针与 CVE 重放走该声明代理（值必进开局外发账；环境变量暗代理仍剥、faker 视觉通道与打本场本地服务的回包重放永不走代理——批三十七防劫持口径不变）；不登记照旧直连、不可达 fail 挂起

## 何时出报告（不看 token 表）

- 出现 **1 条 `verified`**（或首批 3 条已闭环失败/否证且证据齐）→ **立刻步 10/11 出报告**；未测链写 `coverage_gap`；禁止用「还没挖完」挡住报告。
- 源码场漏标/越权清单（无权限注解口、B 桶）**代表口先出卷**；其余必须逐口证实（实测或否证带包）；出报告 ≠ 停挖，清单空着不得 close。
- 禁止 44 份同构越权卷（禁的是没逐口实测就照清单刷同构卷；已逐口证实的不同路由按路由颗粒度各出各卷）；禁止「同根因」把没发包的口写进已出卷危害。
- 源码场 swagger 地图**不当第一条 verified、不上正式 finding**（内部观察册/入口清单照用）；黑盒场匿名文档泄露可出卷。
- **低危/信息级 verified 不出正式卷**：levels 段判 `below_medium`，闭环事实留 finding JSON 与链审，不计可交数、不向用户提「发现低危 xxx」——verified ≠ 可交。
- 每条可交 verified（实测口径**中危及以上**）独立 DOCX = 正式通报（九要素，认 `protocol/report-format.md` RF-ELEM），禁止结案表顶卷。

## 11 步

1. 核本包路径、材料路径、材料 sha256（**脚本算**，人只记结果进 `snapshot_id`）。工具全部包内自带（tools.json `builtin_tools` 段），无外部依赖；可选增强（向量召回）路径见 tools.json `optional_enhancements`。不读目标正文，不读旧 finding。有视觉/嵌图预期的场**必跑** `py -3 scripts/vision_review.py --healthcheck`（faker 通道预检，降级链提前知道走哪条——批四十三升「必跑」的流程入口，配置说明认 tools.json；跳过=拍图才撞 faker 断线属白拍）。
2. 写信封、建唯一 `run_root`（建在数据盘：`<数据根>/library/projects/<project_id>/versions/<version>/<test_session_dir>/`；系统盘材料原处只读算哈希，解压/快照/账/截图全写数据盘）。`test_session_dir` 必须以当日 YYYYMMDD 开头（era 六门锚此日期；无日期目录按最新 era fail-closed 处理——批三十三）。`controller_agent_id` = 平台真实 sessionId；`run_id` 不得复用他场
   - **同项目续挖先读环境交接账**（2026-10-16 批四十三，落实环境交接）：本 `project_id` 下已有旧场次（`versions/*/`）时，写信封前先读旧场 `01-guo-jia/environment-inventory.json`（环境配置/账号/入口页/代码位置/库凭据）与 `run/process-provenance.json`（起服账）——照账拉起环境，不重装不重摸；环境默认保留，用户明说才清
3. 源码创建 **郭嘉+曹操**；网站创建 **司马懿+曹操**。创建消息**只读卡**。
4. 跑 `scripts/dispatch_check_lite.py`，通过后再派活；每个新 run 角色再跑一次。检查器不查哈希抄写。
5. 郭嘉采集/环境（仅源码；website_only 跳过）。郭嘉自称小跑/去干净完成后，主会话立刻跑 `hard_gate.py --phase env`；failed 不得签 ready、不得报 removed 通过、**不挡**司马懿第一段派发。网站：司马懿交第一份能力记录后跑一次 `--phase env`（只查 `in_run`，不查三枪/双拓扑）。
6. 曹操链审：先核模式再扫；**结任何 `verified` 前**跑 `--phase verify`（不限 complex）。越权/IDOR/数据范围/无权限注解候选必须顺入口看拼接条件（认曹操卡）。**判重颗粒度是路由**（同 path 同方法的同一问题才可并成一条；不同路由不因同根因/同注解缺失/同 CVE 同源/同 Controller 而合并）；对外提交同一颗粒度（不同路由各自单独报，打包建议不得写「可合并为一份提交」）；**0day/原创判定同颗粒度**：同源但实例落在不同路由属本轮独立发现 = 原创，照常立链出卷；同一路由同一问题已被公开编号/他人报过 = 封存（不出正式卷、不进战果数，原件进 `reports/discarded/` 注明来源与同源编号，结案表记封存数）。**边界候选必须处置**：验证件写了「未展开/留作后续/边界外/未实测」的面，收卷前曹操二选一——签 BEC 当场打掉（独立立链或并入现有链）或写进收口件待办节；同对象有明确升链方向必须立链或挂账，不许停在已证边界收鸡肋卷；执行者不自行扩面的纪律不变，处置主体是曹操。
7. 条件角色**到期才创建**（见到信号当回合，不攒到清点）。源码没活：收口前创建→读卡→自己目录一张 `not-needed.json`（≤1KB）。源码撞到过滤 → **立刻拉曹冲**交过滤账。网站不要用本步拉源码角色。
8. 于禁：BEC 之后才创建→读卡→当次检查器含 `yu-jin`→派活。目录 `06-yu-jin/`。
9. 司马懿：native 入口可达**当回合派第一段**；不等回执完美、不等画面、不等于禁；发包占链锁。`captcha_removed` 已在 → **当回合派第二段**，禁队列「等全部验证完成」拖到死；禁 `not-needed`「无待测网站」。
10. 收口才比旧洞内容；连带核对同项目上一场收口件待办（并卷/复测/补测/快测类）：当场执行或记顺延理由，不许无声丢弃；本场新待办写进收口件待办节。
11. 分身出正式 DOCX（触发：第一条 `verified` 或首批 3 条证据齐失败/否证；分身到场先交出卷判决再排版）。**本场结束/对外交付前**跑 `hard_gate.py --phase close`；failed 不得当本场结束——close failed 不是终态，清掉成因（含 `~$` Word 临时锁、过小废件）后重跑至 passed，除非用户明示停。close passed 由闸自动盖章回写 test-session（execution_status=closed、gates.close=passed、closed_at 精确时间戳，主会话只核对不手写）。**reports/ 正位只放正式 finding DOCX**：finding JSON 与其余结案 JSON 收 `reports/json/`；test-summary close 通过后移除或落 run/ 归档区。禁止步 6 一写完就出报告；不等用户说「生成报告」。

## 花名册与目录

**源码**九人必须整轮现身，**不是开局全跑**；**网站**只有司马懿、曹操、分身。到期 = 见到信号**当回合**创建→读卡→检查器→派活。开局禁止给没信号的人预填 `not_needed`。

| 角色 | 目录 | 开局？ | 到期信号 |
|---|---|---|---|
| 郭嘉 | `01-guo-jia/` | 源码是 | 采集/搭建 |
| 曹操 | `02-cao-cao/` | 是 | 编排/链审 |
| 分身 | `02-cao-cao-shadow/` | 否 | 第一条 verified / 首批 3 条证据齐失败或否证 = 步 11；到场先交出卷判决 |
| 曹冲 | `03-cao-chong/` | 否 | **撞到过滤**（见下） |
| 曹仁 | `04-cao-ren/` | 否 | 依赖/组件/CVE 信号；**pom/package 第三方写出版本 = 信号** |
| 刘晔 | `05-liu-ye/` | 否 | 外部情报 / N-day 请求；**第三方版本入账 = 请求** |
| 于禁 | `06-yu-jin/` | 否 | 首条漏洞验证前（BEC 之后） |
| 典韦 | `08-dian-wei/` | 否 | 可疑/未解析终点，或run_root已有待审原图 |
| 司马懿 | `09-si-ma-yi/` | 网站是；源码 web 入口可达即是 | 黑盒两段（native + captcha_removed） |

**撞到过滤 = 立刻拉曹冲（仅源码）**：下列任一出现，主会话当回合创建曹冲并派过滤账，曹操不得自己写绕过/有效防御顶岗——源码/采集见到 Filter、拦截器、数据权限、`OncePerRequestFilter`、`HandlerInterceptor`、WAF、XSS/SQL 清洗、验证码防护链；于禁/司马懿发包被防护挡住；曹操链审、典韦追终点、曹仁对 CVE 补丁撞上项目过滤。曹冲只答：过滤能不能解开、怎么测；不解 CVE、不结验证。撞到后禁无 `03-cao-chong/` 还自己写绕过，也禁继续验那条被挡链；没撞到可继续别的活；源码收口前再现身留 `not-needed.json`。网站三人遇 WAF/验证码：司马懿记卡点、曹操复现，不拉曹冲。

没有 `07-`。错号目录（`05-yu-jin/` 等）= 失败。`cors-audit/` 与 `reports/` 并列，不是角色夹。

读卡 ≠ 派活。禁止顶岗。现身三件（`run/agents/<role>-launch.json` / `<role>-read-ack.json` / `<role>-dispatch.json`，或 not-needed）当场写——read-ack 是连字符（lite 实码口径），收口后场外代补不算考生证据。**派活件落盘 ≠ 子代理开工**：现身三件只证「派了」，实际作业以角色目录产物为准。网站不要用本节去拉源码角色。

## 闸（只挡依赖它的动作）

| 到期 | 立刻做 | 不挡 |
|---|---|---|
| 曹操批准搭建 | 同时搭 native + captcha_removed | 静态采集、读卡 |
| native 入口可达 | 派司马懿第一段 | 回执完美、BEC、于禁 |
| captcha_removed 已在 | 派司马懿第二段 | 禁充：「等全部验证完成 / LOCK-Q-002 / 等画面」排队 |
| 源码撞到过滤 | 当回合拉曹冲派过滤账 | 司马懿第一段派发；无过滤的其它链；网站三人 |
| 进程已监听 | 当天写回执，`not_ready` 也写 | 禁充：等四类（＝回执四要素）全 passed 才首写 |
| 两套齐 + 适用小跑过 | 才签 ready、批 BEC、于禁发包 | 司马懿第一段 |
| 链锁被占 | 禁对目标同时发包 | 派发/读卡/写观察框架 |
| 本场能截且欠画面 | 主会话自己截带地址栏原图 | 禁充：用 `/auth/code` JSON 标 passed |
| 复杂链/高危/严重 + 有视觉 | 必录视频（RF-VID 全套），每步录完截帧确认，关键帧过确认门 | 禁充：画面不干净的录屏、乱录 |
| cmd 实拍 | 发送前防呆三查 + 拍后即过 vision_gate（RF-CMD / RF-GATE-01） | 禁充：「sent:」回执当执行成功；拍完不看图 |
| 郭嘉自称搭完/去干净 | `hard_gate.py --phase env` passed | 禁充：口头「过了」；禁充：lite 过关；不挡：司马懿第一段派发 |
| 结 `verified` | `--phase verify` passed | 禁充：口头过；禁充：lite 过关 |
| 本场结束 | `--phase close` passed（分身已出 docx 之后） | 禁充：无 reports 宣称结束 |

（第三列两类内容：纯不挡 = 依赖它的动作照常进行；**禁充** = 禁止用该方式冒充本层完成，同样不是放行理由。gates.md 分层表同。）

回执未齐 ≠ 全停。派发 ≠ 发包。

**字段契约**（三语境三套键，混用就是返工）：finding/签字件结论键 → `status`（闸也认 `finding_status`/`final_status`；`verdict`/`verdict_now`/`result` 都不认）；验证计划行结果键 → `result`/`verdict`（`verdict_now` 不算）；分身出卷判决 → 只认文件 `02-cao-cao-shadow/delivery-verdict.json`。落盘 finding/签字件照抄 `templates/finding.json` / `signoff.json` 结构，写完当场跑 `py scripts/check_finding.py <件> --run-root <场根>`。

**铁四条·SQL 库侧真值比对**：SQL/注入类 `verified` 必须带 `db_ground_truth` 块——`db_direct`（mode + evidence 指库侧只读直查原件，含 mysql CLI 警告行等客户端特征）或 `waiver`（mode + reason≥10 字 + secondary_source）二选一；库通道在场只对种子/凭据文件比对 = 校准不闭环，不得 verified。机械拦：`check_finding.py`/`hard_gate.py` 缺块即 fail。

close 闸 **一轮收全所有毛病**（回执 `failures[]` 列全，`reason` 兼容旧读法）：按整张账一次修完再重跑，别修一条跑一次。**三道收口机械拦**：① close 查「正位卷晚于收口回执被修改」（reports/ 下 revisions/、discarded/ 除外，任何文件新于 close 回执 = fail；重跑即重新验收，无死锁）；② close 必须有 `run/alarm.json`（含 automation_id，兼容旧 alarm_id）；③ close passed 闸自动盖章 test-session。

**改闸窗口纪律**：有 in_progress 场次时禁改 `hard_gate.py`/角色卡/模板——改动落 `draft/` 暂存，收口窗口统一合入；改完必须 `py -m py_compile` + 在已收口场副本上回归（不在正本跑、不覆盖历史回执）+ **必跑 `py -3 scripts/selftest.py` 全绿**（2026-10-16 批四十三；只跑 py_compile 会漏变量类型/挂载类 bug，收口 canonical 漂移才暴露=白造一场 fail）。

## 视觉三句（拆开答）

1. **查了？** 角色目录有能力记录：四件分栏 + `screenshot_capture_in_run` + 真名字段 `pending_visual_capture_items`。
2. **采了？** run_root有**这一项**带地址栏原图（源码/assets png 不算；工单「交主会话」磁盘零图 = 没采）。
3. **审了？** 能看图的角色打开**那张原图**写下画面里是什么（文件在、尺寸对 ≠ 审了）。

**截图 ≠ 视力**：截图看本场有没有浏览器（主会话 Browser Use / `screenshot_capture_in_run`），不看当前模型会不会看图。本场能截 → 必须截，模型看不了图也截，审图记 `pending_visual_review`；模型能看图但开不了浏览器 → 自己不截，交能截的人截，自己审；本场谁都截不了 → 才允许 CLI 对照，禁止造假图。子代理自己截不了只许本角色 `screenshot_capture=unavailable`，**禁止**把 `screenshot_capture_in_run` 一起标 unavailable。本场能截时 `pending_visual_capture_items` 欠项未关禁止 `[]`；字段名不得改。主会话有 Browser Use 必须自己去截。
**浏览器通道优先级**：本包场次浏览器体系认 RF-IMG-14 / RF-SCREEN（CDP 9222 外部真浏览器 + shotlock/who9222 开工三查）；宿主全局「浏览器用 Playwright MCP」规则与本包并发时，**本包场次让位认本包口径**（锁与三查是双会话互斥的地基，绕开即废片风险）。

**借眼识图层（机器复核）**：无视觉会话可借识图代理复核 captures 原图——曹操开子代理跑 `scripts/vision_review.py --faker --image <原图> --question <复核问题>`（glm-5.3-flash 走 faker 通道，密钥运行时从宿主 provider_config.json 读，禁止落盘/回显/写台账）。口径：① 不改视觉三态语义，卷面**不标**复核字样（认 RF-IMG-13：图注只写「本场实测截图」，模型名/机器复核字样禁入卷），复核结论只落 `run/vision-reviews/` 确认件；`pending_visual_review` 关账标 `reviewed_by`，不冒充本场自审；② 复核不过 ≠ 自动降级（另有 DOM/CLI 复检依据则结论不动、复核件留痕交曹操判，改结论走 revisions）；③ 收口后的场复核件只落 `run/vision-reviews/`，不动正位原卷；用户明示要图的收口场可重放取证出「-rev 插图版」（复活环境→真浏览器重放→带地址栏截图→机器复核 evidence_ok→rev 嵌图；原卷不动、文件名带 -rev、env-note 留痕、不重跑 close）；④ 用途 = 审旧截图证据力 + 嵌图场强制门（嵌图必过复核、只嵌 evidence_ok，认 report-format RF-GATE）。识图代理费用极低，可批量过 `captures-index.json` 挑「利用成功」证据图，**不豁免任何检查器**。

### 复杂链录屏

**复杂链**：串联多步、换身份/租户、跨组件、时序/并发，或一张图/一次请求说不清因果。曹操验前写 `complexity=simple|complex`，禁止为免录改标 simple。全套口径认 `protocol/report-format.md` RF-VID（必录条件、录前三查、13 分钟上限、登录与关键节点截图、叙事/纯净度/弹窗/载体标准）。因果链证据以步骤双灰底 + 攻击效果截图承载；点名场从干净前置录到效果确认和对照结束，漏洞触发后才开录不算；环境安装不用全程拍，影响成立的登录/切身份/准备对象必须在录像里；原始连续视频，禁剪辑拼接。视频不顶 XSS 弹窗截图、不顶命令行原件。

**避免空转**：工具打不开/超时/黑屏才计一次失败，换路径或换主会话再试；同一条链最多 **5 次**（记何时/工具/失败原因）；5 次失败 → 复杂链可写 `recording_gap` 免录改截图+CLI（**落点=run/recording-attempts.json 满 5 条真实失败记录 when/tool/error，闸以此认定免录；recording_gap 不是独立模板键**）；**高危/严重除外——必须换工具/路线录成（唯一例外：目标真不可达录无可录，有效 `run/no-screenshot-waiver.json` 在场时视频同免，批五十七 W1）**；不得没试就写 `video_capture=unavailable` 免录。

**无视觉=环境真起不来**：`run/visual-env-attempts.json` 落 **≥6 次真实搭建失败尝试**（每次 when/tool/error，error ≥4 字写实原因），信封才准落 `"visual_available": false`（降级纯 API 黑盒场同认此键）——电脑默认有浏览器，缺账口头宣称闸不收=按有视觉处理（批五十七 W2）。完整 CLI 链仍要；类型必需的弹窗/进后台截图仍要。

## 凭据

- 值内部只准两处：`01-guo-jia/credentials-local.txt` 或 `run/access/` 中性文件。**白盒源码公开默认值豁免**：源码自带的默认口令/硬编码种子/公开常量是漏洞本体不是私产——不当凭据声明、不脱敏、写实值；账内写「本场无私产凭据」标记过 credential_scan（notes=no_private_creds）。**实测获取的会话 token / 真私产凭据照旧单一出处管**。
- **内部不泄**：口令/token 实值正账在凭据两处；派发、聊天、验证 JSON 用 `credential_ref:<路径>#<条目>` 引用（引用是省字不是脱敏义务）。
- **正式 finding DOCX 是例外（压过上一句）**：8 块正文不许脱敏（见 H-16）；finding 同名 JSON 仍不复述实值（credential_scan 扫 JSON；docx 按二进制不扫）。
- 司马懿禁读整个 `01-guo-jia/`：只收地址、账号身份、登录怎么点、`credential_ref`；禁解密链、候选索引、万能密码线索、`encryptHex`。

## 哈希（脚本的事）

开局 `scripts/material_hash.py` 算材料 sha256 → `snapshot_id`。收口 `credential_scan`（包内 `scripts/credential_scan.py`）扫外泄。**哈希只有四个合法落点**（一律脚本算、人只记结果）：①材料清单 `run/material-manifest.json`；②信封 `tool_baseline`；③finding `source_refs[].sha256`（H-22）；④收口回执——其余 JSON 禁手写 sha256 充手续，交接只列路径。
- **材料清单落盘命令**（批四十一补，H-22 义务的产出路径）：`py -3 scripts/material_hash.py --file <解压树根目录> --out run/material-manifest.json`；原档账：`--file <原档.zip> --out run/material-manifest-src.json`；目录原档先打包快照再算（认 gates 运行工件锚段）。

## 产物上限（证据原件除外）

| 文件 | 上限 |
|---|---|
| 能力记录 | 2KB |
| `not-needed.json` | 1KB |
| 增量回执 | 8KB |
| 单链审 / 单条验证 | 4KB |
| 验证计划 | 一张表 + 指针，禁 90KB 一锅 |
| 派发 JSON | 路径、scope、`duty_steps`、`credential_ref`、`expected_artifacts`；无哈希 |

禁止整树进模型；检索命中再 Read 那一个文件。walker / hybrid 账上限 2000 条后是给曹操 grep、按条抽的磁盘文件，照旧禁止整本读进模型。

## 分支

| 材料 | 分支 | 开局 |
|---|---|---|
| 仅网站 | `website_only` | 司马懿+曹操（细则认 `protocol/website.md`） |
| 仅本地源码/ZIP（一份或后端+配套前端两份） | `local_source` | 郭嘉+曹操；有 web 则入口可达派司马懿 |
| 本地源码**和**公网网站都要审 | `source_and_website` | 同源码九人；网站侧另切片，不把源码答案塞黑盒 |

`local_source` ≠ `static_only`；ZIP 不是免搭建。**三件事别混**：双拓扑 = 同一份源码起 native + captcha_removed 两套运行态（不是两份源码/两个产品）；两份本地源码 = 后端 ZIP + 配套前端 ZIP/仓，仍是一场 `local_source`；源码+网站 = 本地审代码另打用户给的公网 URL（不是把找到的官方 admin 当 website_only）。

**两份本地源码**：①同一产品同一大版本的配套（cloud 后端包 + ui 前端包）→ 一场run_root，两份都入信封/材料哈希，郭嘉一起采集一起搭；②不是同一产品 → 拆两场，禁拼成一个 `target_identity`；③前端是配套官方 admin → 仍 `local_source`，不改口 website_only，不为这个前端再开双拓扑；④双拓扑始终是「这一场后端」的 native/removed，前端只挂对应端口。

**材料里有没有前端（郭嘉开局必查，写进采集回执）**：算有（一项即停搜）——`admin`/`ui`/`web`/`frontend`/`vue`/`react` 工程；`package.json` 依赖 vue/react/vite/webpack/umi；独立 `*-ui`/`*-admin` 目录且含源码。不算——swagger-ui/druid/knife4j 静态页、后端 `templates/`、jar 里 html、只有 `dist/`、`node_modules`。**ZIP 只有后端**：先找配套前端，禁把 frontend 标 optional、禁 UI `not_applicable`；顺序四步每步记搜了什么/命中没有——①本 ZIP README/文档的 ui 仓地址 ②同品牌官方仓同版本 `*-ui`/`*-admin` ③本机 Downloads/本场附件同名前端包 ④GitHub/Gitee 公开官方仓。找到：来源+材料哈希入账当本轮前端，**必须尝试启动**（编译失败写缺口，不得改口没前端）；找不到：`coverage_gap` 写清四步结果，**然后才**降级纯 API。禁自造页面/路由冒充原前端。

### 五套硬账 ≠ 追链四本

| 硬账 | 谁做 | 落盘 | 何时必须 | 不能拿来顶 |
|---|---|---|---|---|
| 关键字定位 | 郭嘉开局源码 grep | `01-guo-jia/keyword-scan.json` | 源码场开局 | 十类键名沿用；`searched` 必须是**本栈词**（Java 才 `@PermitAll`；PHP 写 `$_GET`/`include $var`；Go/Python 写本栈入口/exec/上传/依赖坐标）；**信任开关词专扫**（`ignore`/`bypass`/`skip`/`force`/`disable` 类客户端可传布尔/枚举，不带危险气味、向量召回排不上是预期——必须源码专扫，命中落 items 挂十类键的 searched）‖ swagger/`v3/api-docs`/`menu/list`/曹操 chains grep/自动链账 |
| JS 路径 | 有前端郭嘉；纯网站司马懿 | `js-collection.json` | 有前端或网站才必须；四步确认无前端 → `ui=not_applicable` | 前端包 `src/api`、vue-router、bundle 里 path + 盐/密文 id / hidden 路由 / 演示号；每参 origin + proven/likely/unknown；参数出处能记就记 `in=query\|body\|path\|header`（可选，写错值闸 fail，缺了不 fail）‖ 同一套 swagger/菜单/对象图/自动链账 |
| 自动链扫描 | 郭嘉开局跑 `scripts/auto_chain_scan.py` | `01-guo-jia/auto-chain-scan.json` | 源码场开局 | 程序钉 source/sink；近距配对 + PHP 同文件拼接流 + Python 函数内 request→sink；`.inc` 当 PHP、`include/` 仍读；MAX_ITEMS=2000；`filter_nearby` 只是邻近过滤词不顶曹冲；`secret_candidates` 不顶 close credential_scan；`candidate_only=true`；**入口键 0 命中且该语言有文件 → 自动 `coverage.entry_zero_cross_check`**：mismatch=疑似规则盲区，grep 复核后记 coverage_gap（改走 keyword/JS 可以，默默绕开不行）‖ swagger/菜单/关键字/JS/链审/曹冲/credential_scan；禁写成 verified |
| 危险 sink 模块 | 郭嘉 | `01-guo-jia/sink-runtime-modules.json` | 源码场开局（空账也要键齐） | `${}`/反射/exec/SpEL/Fastjson 用户入口所在模块起没起 ‖ 登录进后台/关键字命中/walker 命中 |
| 第三方 CVE | 郭嘉记账，曹仁/刘晔查 | `01-guo-jia/component-cve-ledger.json` | 源码场开局（空账也要键齐） | 带版本的第三方坐标 ‖ 曹操 chains 收编/本地源码无情报 |

关键字账 = 词找到了；自动链 = 程序把 source 和 sink 钉在一起（candidate）；sink/CVE 账 = 模块起没起、公开库查没查。曹操链审可引用郭嘉账，**不能代替**郭嘉开局扫；自动链有账不能免其余硬账；召回 JSONL 也不能顶。

**追链四本**（入口/链路/反证/覆盖）是 PHP/Java 方法论里怎么追的本子，写在回执和链审里，不是第六个 JSON，也不是 `methodology-gap.json`。

**三组容易混的词**：①「过滤」三个——`filter_nearby`（walker 邻近标注，不能当绕过/防御结论）、`filter-signal.json`（拉曹冲的扳机，不下结论）、`03-cao-chong/` 过滤账（**唯一**能写「过滤能不能解开、怎么测」的地方）；②「凭据」三个——walker `secret_candidates`（只记位置不记值，值不复制进账不进司马懿）、`credentials-local.txt`/`run/access/`（值唯一允许落的两处）、close `credential_scan`（前两个都不能顶）；③「召回必须和不顶不矛盾」——`hybrid-discovery.jsonl` 源码场**必须落盘**（闸查跑没跑、分桶对不对），命中不能顶五套也不能免 walker：一个管动作一个管效力。

### 没有 PHP/Java 长文（不停，短规则继续扫）

本包 `references/` 只装箱 PHP 与 Java 两份老师傅长文；其它语言不另写全书、不强制 methodology-gap.json：

1. 禁止停工等专文；禁 not-needed「没有专文所以不挖」。
2. 郭嘉照样跑 walker（短规则 + PHP 拼接流 + Python 函数内污染；Go/JS/Ruby/Rust/C/C# 短规则）+ 关键字十类（本栈词）+ 追链四本。没短规则的语言（Elixir 等）走文件：walker 账 `coverage.languages_without_rules` 只表示没短规则；没追完的链才写计划表 `coverage_gap`。
3. `methodology-gap.json` 可选笔记，闸不因缺它 fail；有它不能顶五套硬账、不能写 verified、不能代替 `coverage.languages_without_rules`。
4. 命中仍是 candidate，verified 仍走五门。walker 同文件流 ≠ PHP 双向追踪。PHP/Java 文里的 Doctor/哈希 Mini 不执行——手续认本 SKILL。
5. **召回顺序跟 Deep**：PHP/JS/Ruby 先正则；Java/Python/Go/C#/Kotlin/Scala/Swift 先向量；混栈 mixed。郭嘉开局跑 `scripts/hybrid_discovery.py`（自包含内置版；vector_first 桶自动 lexical fallback 落 vector_key_check）落 `01-guo-jia/hybrid-discovery.jsonl`；
    - 另补 Deep 四句 lexical（`request_source`/`output`/`validation`/`resource`），不改 strategy。向量没起来走 lexical 不算 fail；把分桶抹成全语言同一套才 fail。**向量没命中/失败先查密钥**：manifest `vector_key_check`（`key_missing` → 先补 `secrets/embedding.env` 重跑；`key_present` → 网络/服务端问题，重试一次再落 lexical），不得直接当「向量不可用」收场。

swagger / knife4j / 登录后菜单仍是司马懿黑盒观察面，只进观察册，不算采集完成。

### 前端 JS（有前端就必须做；混淆场走解包管线）

有前端（含后来找到的配套 admin）：郭嘉从前端源码/打包 JS 抽接口清单，每个可见参数写可控账（来源、`in` 出处、proven/likely/unknown）。环境起来后清单接口实打，非常量参数改值对照；默认值回包 ≠ 可控。`/v3/api-docs`、knife4j、`menu/list`、permissions 不是 JS 清单。

**混淆场先程序化解包，模型只读还原产物**（混淆是机器变换，禁让模型硬啃乱码——3MB 单文件塞不进上下文、字符串是密文、逻辑被打散，硬啃必然「看不懂装看懂」交编造清单）：
- 触发：拿到打包 JS（bundle ≥100KB，或见到字符串数组/数字模块表/hex 密文）→ 跑 `py -3 scripts/js_unpack.py --root <前端目录> --out 01-guo-jia`（网站场司马懿跑，`--out 09-si-ma-yi`）。
- 程序做：sourcemap 还原、webpack 模块平衡切分、字符串明文转储（strings.txt，实测 hex 密文接口直接还原）、加密 API 字面量扫描；落 `deobf-report.json` + `key-bindings.json`。
- 接口清单与可控账从还原产物（modules/、strings.txt、sourcemap-sources/）抽；webcrack 经 npx 探测可选增强（绝不联网装包）。明文 src 源码场不强制跑管线。

**三件升级为三份机械账（不再靠口头声称）**：
- ① 解混淆 = `deobf-report.json`（还原计数 + `unresolved_by_type` 分类 + tool_used）；
- ② 追密钥 = `key-bindings.json`（candidates 程序扫出，模型逐条核对写进 confirmed；运行态抓到同值 = 交叉验证成立）；
- ③ 可控账 = `js-collection.json`（照旧，obfuscation=true 加 `deobf` 回指键）。
- 三份齐才算采集完成；只标 encrypt 行、空清单、解不动装完成 = 没完成。

**unresolved 不死磕，由运行态对账收口（同铁四条库侧真值比对哲学）**：
- 小跑前 `node scripts/vis-tools/hook-capture.js install`（hook fetch/XHR/FormData/sendBeacon + 加密库探测；走 CDP 9222 外部真浏览器，evaluate 注入不动屏幕、不占 shotlock，同页还要导航/截图的照开工三查；SPA 换页后重新 install），业务小跑正常操作，`dump <out.json>` 落与 js-collection 同目录的 `runtime-capture.json`。
- 静态×运行态差集：运行时有而静态清单无的接口 = 解析漏了，回补 js-collection；静态 `unresolved` 运行时抓到明文/参数/密钥 = 补账升级 proven；静态有而全程无请求 = 标注（可能死代码）留注记。
- 解包产物只是素材（candidate_only），不顶五套硬账，接口清单仍以 js-collection.json 为准。清单化提取用包内 `scripts/js_endpoint_scan.py`（混淆场先 js_unpack 再 scan）。

**降级纯 API 之后（四步都记过才走）**：仍搭双拓扑（有 HTTP 入口就搭），业务小跑改打 API（登录、一个列表、一个写接口）；去干净仍打三枪里的 ①②，没有页面第 ③ 枪记 `not_applicable`；UI 截图三项记 `not_applicable`（依据=四步缺口），不得 `ui_completeness=passed`；入口可达照样派司马懿第一段；不因此改 `static_only`、不因此免于禁。

### 小跑后截图算不算正常（本场能截时）

HTTP 小跑过 ≠ 画面过。主会话必须留带地址栏整窗原图，**三张**同时满足、每张地址栏是本场端口才叫正常（闸查 `captures-index` 三键，同 gates/郭嘉卡口径）：
- native 登录页**能看见验证码门**（swagger/druid、源码 png、`/auth/code` JSON 不算）；
- removed 登录页**看不见验证码控件**（后端免码了页面还挂滑块 = 不正常）；
- removed 登录后后台/首页**能看见菜单或登录账号**（空白/报错/webpack overlay 不正常）；
- 每张地址栏**是本场隔离实例端口**（截别的站/没地址栏/裁掉 URL 不正常）。

`captures-index.json` 按张写 `address_bar_urls`。缺任一张或内容不正常 → 该项 `not_performed`/`pending_visual_review`，不得 `ui_completeness=passed`、不得报搭建完成；接口 token 不能顶这组图。降级 API 后才允许 UI `not_applicable`（仍要身份上下文）。

## 双拓扑

源码部署型 web：批准后**同时**起 native（验证码保留）和 captcha_removed。process_fallback 也是两套进程/目录/库/Redis。native 只交运行态 + 验证码门画面；全套业务小跑在 captcha_removed。

**去干净（过关只认效果，不认开关写了没）**：三枪同时成立——① 登录差分：native 不带验证码字段被拒；removed 同样请求拿到会话；② 挑战接口：removed 上 captcha `get`/`create`/`generate` **不再发题/发图**（业务成功码+图/base64/题面 = 没去干净）；③ 登录页（有前端）：removed 页上看不见验证码控件。郭嘉当场打，回执写 `01-guo-jia/captcha-removed-three-shots.json`：三枪结果 + `challenge_path` + 至少两份回包原件。**怎么做**（过关不看这个）：先关产品验证码开关和前端控件；配置只跳登录校验、挑战还在发图 → 再关挑战模块或拦验证码专属 path；产品没有关挑战配置才允许在 removed 副本剥离验证码专属生成/校验/controller；默认不改业务代码，不准动 MFA/锁号/权限；native 滑块接口必须留；jar 里留 captcha 类/素材 png 不算失败。无验证码产品：第二套记未改对照，不假造差分。没去干净 → 不得报 removed 小跑通过。

### 危险 sink 所在模块必须起（登录后台小跑 ≠ 环境齐）

扫到会把用户输入送进危险 sink 的代码，对应模块/依赖必须在本场运行态里**尝试拉起**才能打或证伪。危险 sink 形态（见到就入账，不限于）：MyBatis `${}` 拼表名/列名（`device_message_${deviceId}`）、反射/动态加载（`Class.forName(请求参数)`）、命令/进程（`Runtime.exec`/`ProcessBuilder`）、表达式/脚本（SpEL、`ScriptEngine`、用户模板）、反序列化执行面（Fastjson autoType 用户入口，有 HTTP 进才算）。

1. 郭嘉开局按表扫，回执 `01-guo-jia/sink-runtime-modules.json`（模板在 `templates/`）；`hits>=1` 每项进 items。
2. 该项所属服务/中间件**尝试启动**（IoT 就要 IoT 进程 + 它声明的库如 TDengine；BPM 就要 BPM），听口/健康检查落盘。
3. 客观起不来（缺中间件/编译失败/无获准安装源）→ `runtime=blocked` + 启动失败原件 + `coverage_gap`。禁用「登录已进后台 / 本场只测 admin / 聚合 pom 注释了 / 不值当」当 blocked 理由；注释掉 iot/pay/report ≠ 源码没这面；聚合入口只启用 system+infra 仍须按账尝试拉起被注释模块，缺列补列再打。
4. 没扫到：`scans` 仍要写，`items=[]`；没这份 JSON = 没完成采集/搭建。

`${}` 在 IoT mapper 里、本场没起 IoT = 这条 SQL 面未覆盖，不是「源码没有注入」；未覆盖不得 verified，也不得假装测过。

### 第三方写出版本必须查 CVE（曹操收编 ≠ 查过）

依赖里出现**带版本号的第三方组件**（pom.xml/package.json/go.mod 等）= 曹仁/刘晔到期信号，禁写 not-needed「本地源码场没有外部情报 / 已被曹操收编记 coverage_gap」。

**入账**：第三方坐标+版本（jimureport、fastjson2、flowable、druid、knife4j）；锁定版本的传递依赖（已进 BOM/lock）。**不入账（first_party）**：本仓库自己的模块；无版本 snapshot 占位且来源本仓。

1. 郭嘉开局扫依赖，回执 `01-guo-jia/component-cve-ledger.json`；五类扫描都写。
2. 第三方项：曹仁对本地版本/补丁/入口；刘晔查 NVD/GHSA（或同等公开库），查询落盘（命中**或**「0 条目」都算查了）。**产品自身也要查**：目标产品名+版本过一遍公开通告（产品级 CVE 不挂组件坐标，漏查即漏报）。
3. **`in_range` 命中必须逐条落到代码层结论，记账不算过**：`实测闭环`（打到了）/ `代码否证`（触发条件对不上源码，写明 file:line）/ `blocked`（起不来/无入口，带原件）/ `suspected-coverage_gap`。曹操「收编」只算分流；dispatch 出去的实测未发包不得 close 该账目。命中去重留对照表（同一 advisory 编号/同一修复 commit/同根因双版本线才许并）。
4. 模块没起、端点 404、只是版本命中 → `suspected`/`coverage_gap`，仍要有查询原件；查 CVE ≠ 已 verified。
5. 没扫到第三方：`scans` 仍要写，`items=[]`；没这份 JSON = 没完成采集。

公开 CVE 不能代替本地可达链；版本区间命中只是线索，是不是真踩中要看触发条件在本地代码成不成立（模板路径写死、开关没开、无外部入口都是否证证据，须写 file:line）。

### 司马懿两段（禁第一段停死、禁「无网站」）

源码部署型 web：本场登录页/API/swagger/本场端口**就是黑盒面**。`local_source`、ZIP 无 ui 目录、`website_work_required=false` 都不能当司马懿 not-needed。第一段 native（入口 HTTP 可达或登录接口已通）：未登录观察——登录门、公开 JS、swagger/druid、匿名业务抽样。第二段 captcha_removed（三枪过/截图有 removed URL/于禁已在 removed 发包）：登录态深挖。`phase2=not_applicable` 仅当 removed 确实没起来（有启动失败原件）或信封 static_only。收口必须有 `09-si-ma-yi/blackbox-phases.json`；工单写「交主会话截图」后主会话必须截完；`pending_visual_capture_items` 非空或 `closed_loop_status=incomplete` → close fail。信封在角色已作业后仍写 `execution_status=not_started` → close fail。

### 配额边界 = 当回合上报（silent quota-out 禁止）

BEC 探针配额用尽而攻击面未挖穿（residual 仍有实质面）→ 执行者**当回合**报曹操「配额边界 + 剩余面清单」，不得静默收口、禁自行扩配额。曹操二选一当场裁决：**签续期/深化 BEC 当场打完**（4 发内可定谳的高危候选优先）或写「有据挂账」进收口件待办（残余形态+下场核对口径，close 汇总）。用户指令重开挂账面 = 正常迭代深化不算返工。BEC 签发时把已知机械前提（CREATE_NEW 自动改名、上传落点自适应、字段名变更）写死在授权里。挂账载体 = 收口件待办节或 finding residual 键，**不落计划表 pending 行**。

### 出报告 ≠ 散场（计划 pending 不得 close）

第一条 verified 立刻出报告 ≠ 本场结束。`verification-plan.md` / `plan-alignment.md` 表里仍 `pending`/`queued`/「等窗口」→ close fail；每条必须打完或改成 `verified`/`suspected`/`coverage_gap`（有启动失败或实测阻断原件）。计划行写了 `test` 就必须有结果（`result`/`verdict`；`verdict_now` 是排期初判不算）。**纯读探测禁捆绑延后**：不涉写、不需要 BEC 的读面（GET 差分、明文回显）不得写「随 XX 批次一并跑」跟着涉写链延后。计划/链审点名的面必须入账：jimureport/jmreport/积木报表 → CVE 账+刘晔查询原件（端点没起仍查，记 suspected/coverage_gap）；IoT/TDengine/`device_message_${}` → sink 账并尝试拉起；pay `notifyUrl` → 同上，缺列补列再打；直连 mock/`login-user` 头 → 入口可达就打；上传无白名单 → 打 `.html/.svg` 原生渲染，只传 `.txt` 不算做完。

## 闭环（`verified` 才算洞）

细则读 `protocol/gates.md` 闭环表。最低：注册类要新账号登录；RCE 要文件/命令执行；越权要他者真实数据；XSS 要原生渲染。否证只相对攻击面清单成立（引擎全部语义面 − 防护覆盖面），求值类探针先按引擎真实语法包裹（如 `#{...}`），格式不对的 200 不算打过；**预判落账必须回打**——笔记里写了「XX 路径可通」却没实测，不得据此下防护生效结论；翻案不改写旧件。CORS 仍测，只写 `run_root/cors-audit/`（Origin 请求和 ACAO 回包痕迹，空目录不算），不上正式 reports/。

**危害口径 = 实测口径**：正式卷危害段规则认 `protocol/report-format.md` RF-DOC-11。

## 按需读（不要提前读）

| 做到 | 读 |
|---|---|
| 创建某个角色 | `roles/<角色>.md`（仅那一张） |
| 查视力 / 截图 / 标 passed | `protocol/gates.md` 视觉段 |
| 出卷 / 拍证据图 / 录屏 / 交付打包 | `protocol/report-format.md`（全套现行口径） |
| 拍图实操 / 发命令入 cmd 窗 / 浏览器操作工具用法（send-shot-gate、xss-alert3、fill-search、shot-url、shot-page 等） | `scripts/vis-tools/README.md`（工具用法总表——这些工具的用法说明只在这份 README） |
| 前端混淆 / 接口清单 | 本 SKILL「前端 JS」；郭嘉卡 |
| 工具不够 / 自制项目工具 | 本 SKILL「工具够不够」；曹操卡 |
| 关键字 / JS / 自动链 / sink / CVE | 本 SKILL「五套硬账」；郭嘉卡 |
| 见到 PHP / `.inc` / `include $var` | `references/php-methodology.md`（方法论长文，冲突以 SKILL 为准；网站场不读） |
| 见到 Java/Spring 或确定性正则 | `references/deterministic-regex-and-java.md`（含 SOURCE_JAVA_REQUEST_V5 正则修正——`@` 前去 `\b`、补 `ModelAttribute`/`getParameterValues`；命中只是 candidate） |
| 不是 PHP/Java | **不要等文**；本 SKILL「没有长文」节；缺口进 coverage_gap |
| 验证码去没去干净 | 本 SKILL「去干净」；`protocol/gates.md` 同段 |
| 危险 sink 起没起 | 本 SKILL「危险 sink」；郭嘉卡 |
| 第三方版本查没查 CVE | 本 SKILL「第三方 CVE」；曹仁/刘晔卡 |
| 司马懿两段 / 假无网站 | 本 SKILL「司马懿两段」；司马懿卡 |
| 计划还 pending / 点名模块没入账 | 本 SKILL「出报告 ≠ 散场」 |
| 动态验证某类型 | `protocol/gates.md` 闭环表那一行 |
| 出正式报告 | `protocol/report.md` + `protocol/report-format.md` |
| 网站三人流程 | `protocol/website.md` |
| 查沿革 / 判例出处 | `CHANGELOG.md`（未附内部判例库） |

禁止每个角色读全部角色卡；禁止把巨型协议全文当常驻。口径冲突时：本 SKILL > protocol/ 细则；不为加手续外引其它包。PHP/Java 方法论只管怎么追那门语言，不管开局几人、要不要哈希、website 花名册。

## 检查器

派活闸（每个新角色派活前）：`py -3 <本包>/scripts/dispatch_check_lite.py --run-root <run_root> --role <role>`。过关：launch/read-ack/dispatch 存在（read-ack 连字符）；`duty_steps` 非空；agent_id 像平台 ID；目录号对；派发无口令原文；司马懿派发无郭嘉菜谱；分身派发必须点名出卷判决与 8 块。不过关条件不含「没抄 sha256」；lite 不管作业做没做完。

作业硬闸（磁盘回执，failed 即停该阶段）：`py -3 <本包>/scripts/hard_gate.py --run-root <run_root> --phase env|verify|close`

| 阶段 | 何时跑 | 查什么（要点） | failed 则 |
|---|---|---|---|
| env | 郭嘉自称搭建/小跑/去干净完成 | 三枪 JSON + 至少两份回包原件；第②枪 pass 要有 `challenge_path`；三张真 PNG/JPEG + 每张 URL；native 与 removed 端口不同；`in_run` 不填错；过滤信号必须有曹冲过滤账；`keyword-scan.json` 十类源码扫描齐；`auto-chain-scan.json` walker 账齐（candidate_only=true；入口零命中须有 entry_zero_cross_check 或手写复核注记）；`hybrid-discovery.jsonl` 分桶齐（向量 0 命中/失败须带 vector_key_check）；`sink-runtime-modules.json` 五类扫描齐、hits>=1 必须 started 或 blocked；`component-cve-ledger.json` 五类齐、第三方 hits>=1 必须有查询原件+曹仁作业；五套互不顶替（JS 仅有前端或网站才必须）；禁「没有专文所以不挖」 | 不得签 ready、不得报 removed 通过、不得于禁发包 |
| verify | 结任何 verified 前 | 复杂/高危链按必录拦（+有视觉前提，认 RF-VID-01；有视频须关键帧确认件）；有前端必须 `files_scanned>=1` 且清单非空（来源必须是前端 JS）；网站同样要 JS 清单；obfuscation=false 也要扫过；XSS verified 要真图、RCE/越权要回包；有于禁作业必须已有 BEC；已有 verified 必须曹操签字 | 不得 verified |
| close | 分身已出 docx（或全场只剩低危不交、判决件记 below_medium）之后、本场结束前 | 重查 env+verify；reports 正位 finding 必须是 8 块（结案表过不了；废稿占正位 fail）；**卷内不得出现内部角色名与内部账指针**（机械拦）；源码九人目录都在；曹冲/曹仁/刘晔/司马懿假 not-needed 拦；司马懿必须有 blackbox-phases.json 两段；欠图 pending/工单 incomplete 拦；信封假 not_started 拦；计划 pending/隐形 pending 拦（写了 test 无 result/verdict；纯读捆绑延后拦）；点名 jimureport/IoT/pay 必须入账；CVE in_range 每条有代码层结论；cors-audit 有 Origin+ACAO（豁免口径同司马懿）；网站也要 JS 清单；verified 必须曹操签字件；司马懿目录不得有郭嘉菜谱；credential_scan 必须 clean；**分身出卷判决**：delivery-verdict.json 三段齐（levels/eliminations/dedup）+ shadow-verdict-response.json 逐点带理由，回述型假判决 fail；**查重见处置**：same_problem_covered 封存+sealing-receipt 记同源编号，another_face_new 正位卷引编号声明差异；**verified 终态四路证明**；收口即并账 closure-ledger.jsonl；runner_model（20261010 起） | 不得当本场结束、不得对外交付 |

回执模板在 `templates/`。缺文件、假文件头、两套同端口、空清单、空凭据账 = failed。过关只认 `run/hard-gate-<phase>.json`，禁止用聊天代替、手写 close-summary 不算过门。用户叫停/缺目标不要跑 close。

材料哈希：`py -3 <本包>/scripts/material_hash.py --file <ZIP或目录>`（目录=递归清单哈希）。全部检查器/扫描器包内自带（`scripts/`）。不要把本包检查器混用到其它体系的在飞场次。

## 主会话

只编排，不代扫、不代签、不代写角色产物。**代角色做的只有两件**（写信封/算哈希/挂闹钟/活锁/失败账/墓碑账属编排侧活，不算代角色）：① 本场有 Browser Use 时打开真实页，截带地址栏原图（取证截图只截攻击成功效果图）；不录屏；② 到点跑 hard_gate（env/verify/close）。不要派工单给自己然后假装在等；跑硬闸不算代扫。

**读目标材料只许清单级元数据**：zip 条目表、pom 坐标/依赖段、package.json、目录树、README 级说明——够判分支、够写信封就到此为止；**读业务/安全源码正文（认证、授权、过滤、加解密、注册/越权等链路）= 代扫**，「开局定向/预读留底账」不是豁免理由（那是郭嘉采集与曹操链审的活，预读等于剧透）。拿不准就只看清单，深读派给角色。

**回合制宿主纪律**：回合结束 = 本回合拉起的子代理全部中止；派活件落盘 ≠ 开工。派发收尾三选一：① 用子代理就当场等结果、收完产物再结束回合；② 必须结束时明告用户「已派活、回合将停——60 分钟看门狗发现停摆会自动继续，连续 120 分钟没动静会报卡死」，禁「正在拉/马上跑」进行时收尾；③ 用户明说「不要停/跑到收口」才允许跨回合排队。**新回合醒来第一件事**：拿上场派活件对角色目录——零产物 = 上场子代理没跑，重新拉起（不是角色违规、不写 not-needed）；有产物先收账再前进。

**无反应看门狗**（间隔一律 `0 * * * *` 整点每 60 分钟；主力心跳 = 角色回件通知，看门狗只兜「无在飞角色 + 回合已死」的真空死局；宿主定时投递忙时排队延迟送达，迟到跳只回一句「已收口/无需动作」，队列有限排空即停）：

- **挂载**：本场未收口且用户未叫停时，开局面即挂——拿到可识别目标、确认开考就挂，最迟不晚于信封/活锁落盘；材料识别、哈希、解压、搭建、派发都发生在闹钟已挂之后（识别材料只看清单级元数据）；缺目标停考 → 挂了就删。此后每次正常收尾核一眼闹钟在不在，不在当场补挂。挂/补挂当场落 `run/alarm.json` 五键：`automation_id`/`title`/`interval`/`mounted_at`/`teardown`（teardown 写明「close passed/叫停 → CronDelete 本 id，alarm.json 改写墓碑账保留不删」）。
- **额度墙猝死 ≠ 收口**：闹钟不删不墓碑，封锁期内跳不动、配额重置后下一跳自动回来。
- **回答前核账**：`alarm.json` × CronList 一致性——账在闹钟不在 = 当场补挂；闹钟在账不在 = 僵尸账，收口一并清。
- **四答**：① close 门 passed 或用户叫停 → 回「已收口」并 CronDelete、活锁删除、alarm.json 改墓碑账；② 盘面近 60 分钟有新写入 → 回「活着，正在推进」；③ 近 120 分钟内仍有新写入、当前空闲 → **直接续跑**：走「新回合醒来第一件事」对账（零产物按「子代理异常收账」重拉全套，有产物收账后推进），续跑由主会话正常回合执行，走创建→读卡→dispatch_check_lite→派发全套，不豁免检查器；④ 近 120 分钟零写入 → 回「卡死：需人工，最后落盘〈文件名〉」不再自动续跑——防烧钱闸就是它，自动继续最多连戳两跳。
- **进度账（批三十九机械读）**：四答任一回复末尾附一行（本场第 N 天/verified 累计 X 条/上条距今 Y 小时）；N/X/Y 一律从 `closure-ledger.jsonl` 与 `run/closure-stats.json` 机械读出，禁目测编数——磨洋工透明化，效率判断交还用户（批三十八）。
- prompt 必须自含：run_root 绝对路径 + 四答口径；**禁造新自动化、禁带口令/token 原文**（宿主自动化配置算凭据第三落点，只给路径与 credential_ref）。适用域只限审计执行；盘问/复核窗口照 v7 `user-challenge-review.md` §5 等用户，禁借本条挂闹钟自动重测。收口/叫停后必须删闹钟，不留僵尸空转。

**活锁 `run/active-round.json`（防双开）**：任何轮次开工推进前先写活锁——何轮、何时起、lease 多少分钟（按任务量 30–60）、在驱动什么；同步等子代理的回合在开始等之前写，后台派发在派之前写；看门狗不改写活锁。写盘即心跳——run_root 任何新写入都算活的。活锁在 lease 内 = 原代理还在跑，安静十分钟也不许重派；lease 过期或无锁 = 可能停摆，看门狗按四答处置（③由主会话正常回合接管改写活锁，④卡死报人工）。用户回合开工同样先读活锁：lease 内 → 本回合只对账不动笔；锁过期或已清才接管改写。收口/叫停 → 活锁删除，alarm.json 墓碑化。

**子代理异常收账**（「莫名其妙停了」也是账；没有异常 ≠ 没有中断——静默中断的回话可能完全正常）：

- 派活件必须写 `expected_artifacts`（预期产物清单，按整活口径列全，不按「第一批」列，防交一半算完成）。收账**只按清单逐项核产物**——回话语气/退出码/有无报错一律不算证据；清单没齐（回话报错、为空、看似成功都一样）一律按**没干完**处理，禁止把「派过」记成「做过」。
- 处置三级：① 当场原样重派一次，失败记 `dispatch-failure.json`（何时、错误原文 ≤200 字——无异常就如实写「回话正常但清单缺 X」、范围）；② 再挂 = 缩小任务重派（duty_steps 拆半、输入范围切小，长任务整吞是暴死主因）；③ 同一角色最多 **3 次（按场次累计，不按回合重置）**，3 次全挂 → 失败账收口 + 该面记待办/coverage_gap，禁无声放弃、禁用失败账顶 not_needed；失败账不算现身也不放行 close 门。
- **3 次上限只计角色侧失败**（零产物/半截/回话正常但清单缺）；**宿主侧打断（额度耗尽/限速/断流/宿主收割）角色没获得执行机会，不计入 3 次**：记 `failure_side=host` + 错误原文，等限速窗口（约 10–20 分钟）原样重派，不消耗角色次数；**同活连续 3 次宿主侧打断 → 不再自动重派**，回「等用户给窗口/额度」防重试风暴（仅限无人值守口径；用户在场点名「继续」＝窗口已给，按深挖条款 20 当场再拉）。授权次数不许被历史点头稀释——额外次数必须用户当场明示。**主会话代打禁令**：宿主侧打断不得升级成主会话替角色起实例/打验证枪（三枪/BEC/司马懿两段）——主会话只许**应急环境操作**（收割后复活容器/实例/凭据），当回合落 `run/logs/main-session-env-note.md`（做了什么/为什么/命令与时间），郭嘉事后会签（进 `pending-countersigns.md`）；审计产账永远是角色活；「本次指令压过规则」话术禁入选项，压规则的指令必须用户原文逐字引用进账。看门狗报停摆后用户在场回合对账：见 dispatch-failure.json 且角色无新产物 → 只对角色侧失败跳过该角色不再重派。**认产物不认回话**：嘴上说完成但目录零产物 = 没干；有件但半截 = 收半截、欠账写清。
- 派发 `duty_steps` 末条固定三条子代理纪律：① **边干边落盘**（先落初稿再润色，死在半路至少留尸检材料）；② **收话前对照 expected_artifacts 自核**（缺项干完才许收话，禁「稍后/继续/待办」话术收尾——进行时收话 = 没干完；干不完如实报缺哪项）；③ **全程维护 resume-state.json**（每完成一小步就更新，新实例读它续命）。后台派发必须当回合 TaskOutput 收完结果再走，报错原文进失败账。失败账错误分类按 v7 包 provider-compatibility 规范（经 v7_root 解析）：认证、限流、服务端错误、断流各记各的，不统称「参数不兼容」。

缺目标身份才问用户；禁止问「要不要派司马懿」「要不要先出报告」。

## 停止

缺可识别目标 → 停。第一条 verified 或首批 3 条证据齐的失败/否证 → 立刻报告；之后加测不设额度停表。用户叫停 → 停。
