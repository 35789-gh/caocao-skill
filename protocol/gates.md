# Mini 闸页（按需读，不要每轮整本灌子代理）

SKILL 已写过人话，这里只放表。读完办事，不要扩写成论文。**报告/嵌图/录屏细则不在本页，认 `protocol/report-format.md`。**

## 视觉

四件分开记：`image_read` / `screenshot_capture` / `video_capture` / `video_review`，各 `available|unavailable|unknown`（**本 agent**）。另记 `screenshot_capture_in_run`（本场有没有人能截，主会话 Browser Use 算）。

`visual_capability` = 本角色本回合能不能对画面下结论。能看图 ≠ 能截图；子代理 skill 列表出现 Browser Use ≠ 子代理能开浏览器。

查了 ≠ 采了 ≠ 审了：

- 查了 = 本段能力记录在角色目录
- 采了 = 该项带地址栏原图在run_root（不是源码 png，不是 `/auth/code` JSON；**分层注记**：此为验证证据层 pending 项定义——报告附图层前端位置/证据图不按此口径，认 report-format RF-IMG，勿拿本条拦报告前端图）
- 审了 = 能看图的角色打开那张原图写了画面内容

`pending_visual_capture_items` 字段名锁死。本场能截且仍欠 native 验证码门 / 进后台 / XSS 弹窗时禁止 `[]`。禁改名（`pending_visual_capture`、`visual_pending_capture_items`、`visual_items_referred_to_main_session` 等都不认）。

`screenshot_capture` = 本角色能不能截；`screenshot_capture_in_run` = 本场有没有人能截。子代理没浏览器不得把 `in_run` 写成 unavailable。主会话有 Browser Use → 主会话截；子代理只把欠项写入 pending，等原图再交验收。

**截图 ≠ 视力**：截图看本场有没有浏览器，不看当前模型会不会看图。没 `image_read` 仍要截（本场能截时）；没浏览器才不截，不准造假图。无 `image_read` 只禁本角色审图，不禁 HTTP，不免除启动前端和页面登录。

**派发禁预写 `cli_only`（视觉门落点，批四十六入包）**：给子代理的 duty_steps 禁止预写 `cli_only` 之类「本场只走命令行」的预设——本场视觉能力由 capability.json 如实记录（`evidence_mode` 的 `cli_only` 枚举只描述已发生的事实，不得当派发指令用）；曹操核对见预写即退回重派。

**复杂链录屏**：必录条件、录前三查、5 次免录口径认 report-format RF-VID-01/02。像必须进 `run/recording-index.json` 对应该 id 且 `full_span=true`，run_root里随便一个 mp4 不算。本角色录不了交主会话，不算失败。工具失败记 `run/recording-attempts.json` 的 `by_chain[<id>]`（每条 when/tool/error）；禁没试就填 `video_capture=unavailable` 免录；禁为免录把多步链标 simple。视频不顶 XSS 弹窗截图。

**无前端判定**：ZIP 里没有 admin/ui 工程 ≠ 本轮无前端。必须先按 SKILL 四步找配套前端；搜完仍无才允许 UI `not_applicable`。没找就 N/A = 违规。

**小跑后截图正常**（验证证据层，独立于报告附图层）：本场能截时至少三张带地址栏整窗原图（native 登录页见验证码门；removed 登录页不见验证码控件；removed 登录后后台菜单或账号可见；地址栏必须是本场端口）。`captures-index.json` 按张写 `address_bar_urls`（http(s)），只写 `address_bar=true` 不够。缺图、停在登录框、removed 仍有滑块、swagger/druid、源码 png、`/auth/code` JSON 都不算正常，不得 `ui_completeness=passed`。

**JS 清单参数出处 `in`**：可选字段；写了就必须是 `query|body|path|header` 之一，别的值 close fail；老账没这字段不 fail。

**混淆解包三份账**：混淆判定双通道任一命中即查——① `js-collection.json` 的 `obfuscation=true`（主判，老字段，不依赖新工具）；② 场内 `deobf-report.json` 的 `obfuscation_any=true`（程序判定）。源码场账在 `01-guo-jia/`、网站场在 `09-si-ma-yi/`。
- 命中后 verify/close 查三份账齐：同目录 `deobf-report.json` + `key-bindings.json` + js-collection 的 `deobf` 回指键；**js-collection 写 obfuscation=true 而 deobf-report 缺失 = 采集未完成**（禁用「没跑工具」躲账）。
- `unresolved_by_type` 非空时还须有 `runtime-capture.json` + `runtime_capture.diffset_conclusion` 差集结论（运行态多出的接口已回补 / unresolved 已升级 / 静态孤项已标注，三选一全覆盖）。
- `needs_dynamic_decoder` 分类本身不是 fail，解不动装完成才是 fail。明文 src 场（`obfuscation=false` 且无 deobf-report）与老账（本批前开场的）不追溯。
- 闸脚本本轮未加机械拦，由曹操链审把关（同自制工具审批模式），挂 hard_gate 收口窗口。

**验证码去干净**：过关只认效果。removed 上当场三枪——① 登录不带码拿到会话；② 打 captcha `get`/`create`/`generate` 不再发题/发图；③ 有前端则页面无控件。只关登录开关、第②枪仍吐图 = 没去干净，不得报 removed 小跑通过。怎么做：先配置，配置不够再拦验证码 path；配置不是验收。native 滑块还在是正确的；jar 里留 captcha 类不算失败。
**无验证码产品豁免**（认 SKILL「第二套记未改对照，不假造差分」）：three-shots 回执填 `no_captcha_product=true` + 三枪全 `not_applicable` + `product_basis`（≥10 字源码/配置依据）+ evidence ≥1 份未改对照回包（removed 登录成功回包），闸放行；缺 basis/evidence 仍 fail，禁编 challenge_path 拿 404 充 pass。

**关键字定位**：`01-guo-jia/keyword-scan.json` 必须有十类源码扫描。键名可沿用，`searched` 必须是**本栈**源码词。禁 swagger / `v3/api-docs` / `menu/list` / 曹操 `chains/` grep 顶。命中 `${}` 等还要 sink-runtime；命中第三方版本还要 CVE 账。**信任开关词专扫**（`ignore`/`bypass`/`skip`/`force`/`disable` 类客户端可传布尔/枚举）——不带危险气味、向量召回排不上是预期，不等于扫过了；命中落 `items`（file:line），不新增第十一类键，挂十类键的 `searched`。

**自动链扫描**：`01-guo-jia/auto-chain-scan.json` 必须由 `scripts/auto_chain_scan.py` 写出。`.inc` 当 PHP；`include/` 仍读。近距配对 + PHP 拼接流 + Python 函数内污染。MAX_ITEMS=2000。`filter_nearby` 不顶曹冲；密钥候选账不顶 close credential_scan；`candidate_only=true` 禁 verified；不能顶关键字/JS/sink/CVE，有它也不免那四套。**入口键零命中且该语言有文件 → 必须有 `coverage.entry_zero_cross_check` 或手写复核注记**（mismatch=grep 复核后记 coverage_gap；改走 keyword/JS 可以，默默绕开不行）。网站跳过。

**召回层**：`01-guo-jia/hybrid-discovery.jsonl` 必须由 `scripts/hybrid_discovery.py` 写出。顺序跟 Deep：PHP/JS/Ruby `regex_first`；Java/Python/Go/C#/Kotlin/Scala/Swift `vector_first`；混栈 `mixed`。禁抹成全语言同一套（`regex_after_no_vector` / `mini_unified`）。命中 `candidate_only` 不能顶 walker。向量没起来不算 fail，但 0 命中/失败须带 `vector_key_check`（先查 `secrets/embedding.env` 密钥再下结论，`key_missing` 先补再重跑）。网站跳过。

**没有 PHP/Java 长文**：不停工。walker 短规则继续钉候选；没规则也走文件，walker 账记 `languages_without_rules`；没追完才写计划表 `coverage_gap`。不得 not-needed「没有专文所以不挖」。`methodology-gap.json` 可选笔记。PHP/Java 文里的 Doctor/哈希 Mini 不执行。追链四本不是磁盘硬账。

**危险 sink 模块**：`01-guo-jia/sink-runtime-modules.json` 必须有五类扫描。`hits>=1` 对应模块要 `started`（听口原件）或 `blocked`（启动失败原件 + 缺口）。登录进后台不能顶。禁「只起 system/admin / 聚合注释 / 不值当」当 blocked。未起模块上的 `${}` 不得 verified；pom 注释掉 iot/pay/report ≠ 没这面。

**第三方 CVE**：`01-guo-jia/component-cve-ledger.json` 必须有五类扫描。带版本第三方 `hits>=1` 必须有 NVD/GHSA 查询原件（命中或 0 条目）+ `04-cao-ren/` 作业。曹仁/刘晔不得用「曹操收编 / 本地源码无情报 / coverage_gap」写 not-needed。模块没起 ≠ 没查；公开编号不能当 verified；**产品名+版本号也要过公开通告**（产品级 CVE 不挂组件坐标）。**close 时 `in_range` 每条必须有代码层结论**——实测闭环 / 代码否证（file:line）/ blocked（原件），「收编/记入待办」不算，dispatch 出去的实测未发包不得 close。命中去重留对照表（同一 advisory 编号 / 同一修复 commit / 同根因双版本线才许并）。
  - **判重对照表机械件（批三十九，era≥20261016 闸核）**：封存件 sealed_items 每条必带 `route_compare`（advisory 受影响路由原文 × 本地路由 file:line，≥1 行可解析）且查询覆盖面 ≥2 条/2 个不同 URL；正位卷 finding.json 的 `related_cve` 非空同样必带——防「真做但指向错误结论」草率封存真 0day，语义对照仍归曹操链审。

**运行工件与官方源锚（批三十九）**：源码场起服必落 `run/process-provenance.json`（深挖条款 30：port/pid/main_artifact/main_sha256/built_from，close 三层核——工件哈希账实、可追溯材料清单/构建账、活端口 PID 对账；仿写迷你服务在追溯核炸）。
  - era≥20261016 源码场信封必填 `official_source_url` 或 `official_source_waiver`（深挖条款 31：close 真下载官方包比对，开局前注毒在逐成员核暴露）。
  - canonical 根 `gates-canonical.json`（包根，或环境变量 `CAOCAO_CANONICAL_ROOT` 指到包外由用户保管）：env/close 双相比对检查器哈希，漂移 fail（用户批的合规改闸后须重跑 `scripts/make_canonical.py` 并记 CHANGELOG，**同时必跑 `selftest.py` 全绿**——批四十三，与 SKILL 改闸纪律同口径）；`baseline_sent_at` 缺键 close fail。
  - **批四十**：目录形态材料（material_source_path 非 zip）须落 `run/material-snapshot.sha256`（原档先打包快照再算清单）或信封 material_snapshot_waiver 二选一；close 回执带 env_receipt_sha256（深挖 29③ env 外发对账，断中段洗白）；同目标旧场素材摘要高重合且信封未声明 reuses_prior_session = 整场复读 fail（合法复测声明 + prior_run_ids 登记后放行记注）；dedup「零重复/全部原创」声明须 ≥1 条可重放查询原件（入 CVE 重放池，查询 URL 未含产品名/版本 token 记弱核 note）；正位卷接口清单 path 逐个须在本场证据文本命中（声明未实测的口 fail，batch31#7 升格）；H-24 抽验三条构成（环境探针/攻击效果/真值读回各 ≥1，效果条目标 URL 须出现在正位 DOCX，batch31#5 兑现）。

## 闸分层

| 层 | 信号 | 立刻做 | 不挡（禁充 = 禁止用该方式冒充本层完成） |
|---|---|---|---|
| A | 搭建批准 | 两套一起搭 | 启动实例 |
| B | native 入口可达 | 派司马懿第一段 | ready / BEC / 于禁 |
| B2 | captcha_removed 已在 | 派司马懿第二段 | 禁充：「等全部验证完 / LOCK-Q-002 / 等画面」排队 |
| C | 已监听 | 写回执，即使 not_ready | 禁充：等四类（＝回执四要素）全 passed 才首写 |
| D | 两套+适用小跑过（env passed） | ready、BEC、于禁发包 | 司马懿第一段派发 |
| E | 链锁空或已登记并行窗 | 才对目标发包 | 派发本身 |
| F | 能截且欠图 | 主会话截原图 | 禁充：JSON 标画面 passed |
| G | 复杂链/高危/严重+有视觉 | 必录（RF-VID 全套：录前三查+关键帧确认件+13 分钟+每步截帧） | 禁充：画面不干净的录屏、凑数乱录、高级别漏录 |

禁止回执完美主义空转；禁止能力 JSON 当视觉门通过。smoke 原包不准带 token（指**连通性探针**不准夹带凭据；攻击实测回包写实值是另一层，两者不矛盾）。

源码撞到过滤却无 `03-cao-chong/`：挡的是那条链的绕过结论、以及依赖过滤结论的验证；不挡司马懿第一段**派发**、不挡没撞过滤的其它链、不挡网站三人。入口可达却无司马懿、已到报告触发却无分身：挡的是继续黑盒空转/收口，不挡已在跑的无依赖静态本职。`local_source` / ZIP 无前端 / `website_work_required=false` 不是司马懿 not-needed。removed 已在却停第一段 = 收口失败。欠图工单 / `closed_loop_status=incomplete` 未关 = 收口失败。信封 not_started 但已作业 = 收口失败。计划仍 pending /「等窗口」= 收口失败（出报告可以）。点名 jimureport/IoT/pay 却不入 CVE/sink 账 = 收口失败。

**盘符与自制工具**：`run_root` 建在数据盘（library 根默认 `<数据根>/library/projects/`，数据根按环境自定），任何角色的产物/账/工具/截图不得出数据盘 run_root，系统盘材料只读；**例外：进程临时文件落系统临时目录（TEMP/TMP）**（认 SKILL H-18，不在 run_root 内算合规）。进程日志跟着进程 cwd 走：服务一律从 run_root 目录拉起，否则日志渗出 run_root 外收口后还在写。收口查环境连宿主机进程一起看（netstat + tasklist），「已停」要等于真的没有端口在听。自制工具审批与效力认 SKILL「工具够不够」节；闸脚本不扫审批件，由曹操链审把关（无批准记录的自制账按 candidate 退回重走）。

硬闸脚本 `scripts/hard_gate.py`：`--phase env` 在自称搭建完成后（挡 ready / removed 通过 / 于禁发包，不挡司马懿第一段派发）；`--phase verify` 在结 verified 前；`--phase close` 在分身已出 docx（或全场只剩低危不交、判决件记 below_medium）之后、本场结束/对外交付前（不要挡分身开工）。failed 磁盘说了算，聊天和手写 close-summary 不算；过关只认 `run/hard-gate-<phase>.json`。用户叫停或缺目标停工 ≠ 交付，不要跑 close 冒充收口。

close 抽 `reports/*.docx` **正位** finding：必须有 8 块字（目标网站URL / 描述 / 危害 / 接口 / 复现 / 修复 / 「我」 / 全角＃ / 请求行+Host）。结案表（一、身份 / BEC 台账 / 闭环矩阵）过不了；**内部角色名与内部账指针进正式卷 fail**（采证指针写文件名即可；豁免口径同闸：`test-summary` 总览件与复审/复测「总报告」不拦，只拦 finding 正位/修订卷）。废稿进 `reports/discarded/` 不得占正位；`revisions/` 里的 finding 也抽 8 块但不能代替正位；`test-summary.docx` 不抽 8 块。源码撞过滤：曹冲必须交过滤账，not-needed 写「被曹操吸收」= fail。`cors-audit/` 必须有 Origin+ACAO 实测（static_only / 无部署 web 面场次跳过，同司马懿豁免口径）。网站必须交 `09-si-ma-yi/js-collection.json` 禁 skip。已有 verified 必须 `02-cao-cao/` 签字件。源码 env/close 还查五套硬账（keyword-scan / auto-chain-scan / hybrid-discovery / sink-runtime / component-cve），互不顶替；召回层不是第六套硬账；禁「没有专文所以不挖」停工。close 另查：`blackbox-phases.json` 两段、司马懿假「无网站」、欠图 pending/工单 incomplete、信封假 not_started、计划 pending、点名 jmreport/IoT/pay 入账。**计划隐形 pending 也拦**：计划行写了 `test` 却无结果键 = 没打完；纯读探测（GET 差分/明文回显）禁「随 XX 批次一并跑」捆绑延后。verify/close 的 JS 清单禁 api-docs/菜单顶。

**批三十五新增机械拦（era≥20261015 场生效，存量放行记注；2026-10-15 立）**：

- reports 正位白名单放行 `.pdf`（修批三十四与⑯「同名 PDF 同目录」义务的死锁——其余非 DOCX 仍拒）；
- H-22 fail-closed：白盒 verified 必带 `source_refs`、源码场必落 `run/material-manifest.json`；env 回执锚清单哈希，收口前换清单 fail；
- 账本指向解析（深挖 27）：keyword/auto-chain items 的 file 按材料根（source_root/清单根/快照）可解析，编造 file:line fail；auto-chain `files_scanned` 与清单文件数同数量级；CVE queried 证据须含真实响应特征（HTTP/1. 行、公开库 URL、JSON results 键）；
- 分身判决三段各须 ≥1 个可解析原件指针（≥40B 实件，空段免）+ response 有 ≥ levels 条目数的 accepted/rejected 行；
- H-26 类型级别下限：低于下限须 finding 与 delivery-verdict 双留 ≥20 字 `downgrade_reason`；
- 嵌图确认件随机抽 1 张重跑 faker 判定（legacy 无 sha 件必进池；faker 断线/异常改 fail 挂起等恢复——认 RF-GATE-03，通道恢复重跑即过；批三十六翻转批三十五「断线记 note 不拦」旧口径，旧句作废）。

**批三十六新增机械拦（用户红队二轮；era≥20261015 场生效，存量放行记注；2026-10-15 立）**：

- **era 只认目录/路径名日期**（信封/alarm 是操作者可写文件，回填旧日期降级 era 的后门关死；无日期目录维持 99999999 最严档）；
- **缺键≠中性态**：tool_baseline 缺失、账本缺 tool_trace、full_span 缺 duration_sec、verified 缺 severity、账本材料基准全空——新场一律 fail（「存量兼容」不再给新场当第二把钥匙）；
- **扫描工具身份入基线**：tool_baseline 须含 tools.json + 包内 credential_scan.py 的 sha256（假扫描器防伪）；
- **三张双拓扑截图两两查重**：sha256 相同必拦；PIL 可用时 dhash 距离 ≤6 判近重复（同图复制配三个 URL 冒充两套实例）；
- **复检抽样提率**：legacy 件必抽 1、高危/严重场加抽 1、上限 3 张；faker 断线改 fail（拔网线不再关闭抽查，通道恢复重跑即过，认 RF-GATE-03）；
- **摘录锚**：曹仁核对件须引用 source 文件 ≥15 字连续原文；分身判决三段指针须带 excerpt 且逐字命中被指文件（治指鹿为马式指针与左手核右手）；
- **suspected-only 交叉拦**：全场零 verified 且盘面有 suspected 时每条须带 closed_loop_gap（≥10 字缺口账）；
- **no_findings_to_review 收紧**：盘面 reports/json 有 finding JSON 时写它 = 矛盾 fail；below_medium 免检改认 levels 结构化条目（存量子串兼容）；
- **scene_digest v2**：<1MB 文件入内容哈希（同长改写+utime 回填失灵）；旧口径回执 verify-close 按「闸升级重跑」处理不误判伪造；
- **visual_available:false 交叉验证**：声明无浏览器的场盘面出现真图/in_run=available = 矛盾 fail；
- **交付包机械检查**：正位 finding 卷须有 reports/packs/ 对应数量 zip，每包含 README+PDF+PoC/脚本件（落点与 verify.bat 认 RF-PKG-08）。

**批三十七新增机械拦（用户红队三轮「环境与工具信任链」；era≥20261015 场生效，存量放行记注；2026-10-15 立）**：

- **神谕通道防劫持**：faker 升 https + 闸/双视觉脚本发请求前剥代理环境变量（http_proxy 指向本地假神谕可零文件改动骗过全部视觉防伪）；
- **branch 材料反查**：场内出现源码工程特征（pom/build.gradle/composer/go.mod 或 java/php/cs/go 源文件 >20）而信封写 website_only = 五套硬账旁路，fail（对称补上既有反向拦）；
- **材料来源双账**：manifest 覆盖面重走（file_count 对账 + 抽 10 件重算 sha）+ 信封登记 material_source_path 的场 source_refs 出处必须同时命中原档账（zip_entries 逐成员）——开局投毒/清单缩水两个残留口关死；未登记原档记 waiver 提示；
- **账本产出工具入 H-25 基线**：auto_chain_scan/hybrid_discovery/js_unpack/material_hash 四件生产者与检查者同锚，新场基线缺任一必锚键 fail；
- **交付包内容核**：verify.bat 须含 hard_gate.py/--phase close/--verify-close 硬串（空壳 @echo passed 拦）；PoC .py 须含判定词+用法注释（空壳脚本拦）；
- **类型受控枚举**：finding 可选 evidence_loop_class（认 templates 枚举表）优先定 H-26 下限与配套；SEV_FLOOR_MED 补泄露/认证绕过/未授权族；
- **封存真实性**：sealed_items 每条须带查询原件 + 老向量阴性对照回包（没打过老向量不许封）；dedup 点名公开编号的 route 须带可解析查询原件且含真实查询特征；
- **H-24 落盘**：run/h24-replay/ 每卷 ≥1 条 .cmd+.out 实测记录（轻核存在与形态，内容真伪归用户 verify.bat 抽验）；
- **采证指针存在性**：卷内「采证记录：〈文件名〉」逐个在 run_root 找同名件，幽灵原件 fail；
- **计划白名单（新场）**：计划表末列状态不落在闭合集 = open（fail-closed）；黑名单全列兜底不变；
- **签字摘录锚**：曹操签字件须引用 finding 结论/证据原文 ≥15 字，空壳签字按未签论处；
- 确认件落 kind 判型行（判据松紧不许靠文件名自猜无痕）。

**批三十八新增机械拦（用户红队四轮「开局前的我」；era≥20261015 场生效，存量放行记注；2026-10-15 立）**：

- **era 回拨交叉核**：目录声称日期比场内最早文件 mtime 日期早 >1 天 = 谎报旧目录，fail（目录名是执行者起的——建旧日期目录曾可整批静默降级新拦；整场回拨系统时钟可骗过本核但须维持到收口且打乱宿主闹钟/Cron，成本从起个名涨到劫持时钟）；
- **查询原件机械重放**：close 对 CVE 账第三方 queried 与封存回执各随机抽 1 条，用卷内同一 URL 真实重放（响应落 run/cve-replay/），网络异常 fail 挂起——手写 42 字节假查询件（HTTP 行+URL+JSON 计数键三特征全可手写）不再能伪造「查无此洞」或草率封存真 0day；
- **scene_digest v3 扩覆盖**：五套硬账/三枪/黑盒两段/查重判决/司法回应/截图索引全部入指纹（收口后补假账 verify-close 必炸），口径版本 3，旧回执按升级重跑处理；
- **check_packs 免检短路 bug 修复**：「含 hard_gate+verify-close 即跳检」可被注释带词绕过——三硬串改逐一必须；verify.bat 增 certutil 哈希自打印行核（信任根外发第 -1 条载体）；PoC 增目标构造核（空壳 print 不构成 PoC）；
- **h24-replay 内容核落地**：.cmd 须为 --verify-close 重验或 curl/py 实探命令（docstring 承诺此前只查 ≥10 字）；
- **faker 复检抽样 1→25% 起步**（上限 4；识图费极低，压缩伪造 N 张图的期望收益）。

**规则层（同批）**：SKILL 深挖条款 29 信任根外发（开局外发基线摘要/收口外发回执指纹/H-24 第 -1 条 certutil 对照——没法被改写的存储是已发出的聊天消息）；看门狗四答回复附进度账（磨洋工透明化，效率判断交还用户）。图↔盘逐值对账、会话随机数入画、DOM 注入机械检测：记挂账不假装能拦（draft §4 口径）。

**分身出卷判决（2026-10-07 起场次机械拦）**：`02-cao-cao-shadow/delivery-verdict.json` 三段（levels / eliminations / dedup）且各段带独立证据指针（file:line / 回包原件 / 自发查询原件落分身目录）；三段与曹操结论全同且无原件指针 = 回述型假判决 fail。
- 回应`02-cao-cao/shadow-verdict-response.json` 逐点 accepted/rejected 带理由；无 finding 空场记 `no_findings_to_review`。
- **查重结论必须见处置**：dedup 点名的公开编号，要么对应卷封存进 `reports/discarded/` + `sealing-receipt.json` 记同源编号，要么正位卷内引用编号声明差异——脚本机械拦（判决件点名编号 × 正位 DOCX 引用 × 封存回执三方比对）
- **verified 终态处置（20261010 起）**：每条 verified 链对上四路证明之一（正位/修订卷引用 chain_id / sealing-receipt / delivery-verdict 留档行 / final-delivery-manifest），四路全无 = fail
- **收口即并账**：close passed 闸自动写数据根 `closure-ledger.jsonl`（findings 明细/sealed_count/runner_model；重跑追加、并账取最新），总览并账以台账为准；**战役归场**见 SKILL 深挖条款 22③。2026-10-07 前已出卷的在飞场次不追溯。

## 闭环（类型 → 最低证据）

| 类型 | `verified` 最低 |
|---|---|
| 注册/创建账号 | 注册成功 + **新账号登录** + 用该会话调接口回显新身份 |
| RCE / 命令注入 / SSTI / 反序列化 RCE | 真实文件执行或命令执行 |
| SQLi | 抽出可验证差异数据；sleep 只辅助 |
| 任意文件读 | 读到可预知内容并在应用回显 |
| 任意文件写/上传 | 独立进程读回一致，且应用自己可见 |
| XSS 反射 | 浏览器直开 URL 原生渲染 |
| XSS 存储 | 另一会话读取并原生渲染 |
| 越权/IDOR | 低权/他者拿到对方真实数据。源码场链审还须看该入口拼接条件（认曹操卡）；只扫注解、没看 Mapper/WHERE 不得把「无注解」直接当 verified 依据。漏标清单每口须实测或否证带包；没发包的口不得写进已 verified 危害 |
| SSRF | 受控端点真实回连 |
| 信息泄露 | 可验证敏感字段。源码场 swagger / api-docs 地图不当本类型白盒 verified、不上正式 finding（进观察册/入口清单）；黑盒匿名拿到全量路径+参数结构才可按本行出卷 |
| 认证绕过 | 取得被绕过身份会话并调一个专属接口 |
| 业务逻辑 | before→after 状态落盘 |

不够就 `suspected` 或 `coverage_gap`。**否证也一样挑面**：只对打过的那几个面成立。写「打不出来 / 无洞」前先问引擎或产品到底有几类语义面（求值面、`@bean` 面、上下文面…），清单 = 引擎全部语义面 − 防护覆盖面，逐面打完或留真实 blocked 依据才允许整体否证；只打一面不等于整链证伪。求值/解析类入口的探针先按该引擎真实语法包裹（如 warm-flow 只认 `#{...}`），格式不对的 200 = 从未求值不算打过。旧否证被新证据推翻（翻案）时旧件不改写，新结论指回旧链。CORS 只进 `cors-audit/`；源码场文档地图、传输加密硬编码/可逆混淆/明文直发绕过都不上 `reports/`（明文直发 30001 = 证伪）。

## 链锁

对目标发包一次一条活动链。司马懿第一段**派发**不占锁；**请求**占锁。要和于禁同时打，曹操先写 `sima_yi_parallel_window` 且入口无交集。链锁 JSON 落 `run/chain-lock.json`，只记 `chain_id`、占用角色、开始时间、释放时间，不嵌哈希。
