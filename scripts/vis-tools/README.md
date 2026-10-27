# 视觉工具链（2026-10-12 视觉门战役沉淀；拍后即验/机器复核/回退口径认 report-format RF-GATE 与 RF-IMG 族）

口径：所有图的确认一律走 faker 5.3f（无视觉会话禁止出「目验」件）。
流水线：**拍（snapwin/snapchrome）→ 发（cmdsend-any）→ 验（vision_gate）→ 嵌卷审（vision_review）**。

## 一、验（mini scripts/ 下）

| 工具 | 用途 | 用法 |
|---|---|---|
| `vision_gate.py` | **拍后即验门**：每张证据图拍完当场过，fail 立刻重拍（≤3 次） | `py -3 vision_gate.py --image <图> --kind cmd\|web\|frame\|dual --claim "图注关键值" [--out <确认件>]`；退出码 0=pass；**--kind 必填，不按文件名猜测**（r16 起文件名猜测逻辑已删：缺 --kind exit 2 no-kind，缺 --claim 同 exit 2）；kind=cmd 查「纯终端窗口/提示符+完整命令+真实回包/关键值可见」三判据；**dual=RF-IMG-15 脚本演示双窗专用型**（py 脚本 cmd 直跑演示图与 PoC 运行图禁走 cmd 型——「纯终端铺满」判据会错杀双窗图） |
| `vision_review.py` | **嵌卷前终审**（㉔）：出 evidence_ok 确认件、逐张对齐 | `py -3 vision_review.py --faker --image <图> --question "<复核问题>"` |

## 二、拍（本目录 vis-tools/）

| 工具 | 用途 | 要点 |
|---|---|---|
| `snapwin.ps1` | cmd 终端**窗口截屏**（v4） | SW_MAXIMIZE 铺满→GetClientRect→只截客户区；禁全屏 CopyFromScreen（㊴） |
| `snapchrome.ps1` | Chrome 窗口截屏 | alert/confirm 模态框会阻塞 CDP，弹窗类证据必须用这个屏幕截屏 |
| `cmdsend-any.ps1` | 向 cmd 窗口粘贴执行命令 | 按 title 精确匹配且要求唯一——同名多窗直接拒执行并报数量（双会话必须各用唯一 title，如 CMDPHOTO-B，防命令敲进对方会话）；发送前查 shotlock：锁在他人名下拒发 exit 3（`-Owner` 或环境变量 `SHOTLOCK_OWNER` 标识本方），无锁打 warning 后继续（单会话老用法）；fg 失败先 NOTOPMOST 还原再 throw，并注明剪贴板已被覆盖、原内容不保；置顶+粘贴+回车；发送前必须 cwd 锚定（cd /d <工作目录> 回显验证） |
| `send-shot-gate.sh` | 单发→等→拍→过门一体 | `WAIT=<秒> ./send-shot-gate.sh <命令txt> <输出png> "<claim>" [kind]` |
| `snapdual.ps1` | **双窗图一体拍摄**（RF-IMG-18，RF-IMG-15 的执行层） | Chrome 最大化打底 + cmd 侧窗 TOPMOST 不抢焦点落位 + 清场最小化 + 悬停出原生 title 提示 + 工作区区域截屏；`-CmdTitle` 精确匹配窗题，`-CmdX/Y/W/H` 侧窗矩形、`-CursorX/Y` 悬停点（负值跳过悬停）；拍完立即 `vision_gate --kind dual` |

## 三、浏览器（CDP 9222）

| 工具 | 用途 | 要点 |
|---|---|---|
| `drive.js` | 登录/导航/点按/截图/logout（参数 `\|` 分隔） | MSYS_NO_PATHCONV=1 前缀防 Git Bash 路径转换。**RuoYi 项目特化**：`BASE` 硬编码 `127.0.0.1:5173`、找页含 `includes('127.0.0.1:5173')`——换项目先改头部 BASE 与找页串（批二十五标明，勿当通用件直接跑） |
| `xss-alert3.js` | 打开含弹窗载荷 URL | waitUntil:'commit'（alert 阻塞 domcontentloaded）+ 不 dismiss（弹窗留画面）；截图用 snapchrome |
| `fill-search.js` | 填搜索框并点搜索 | placeholder 定位 |
| `shot-url.js` | 新页打开 URL 截图 | CDP 新开页无地址栏——地址栏证据图须用可见浏览器窗口+snapchrome |
| `shot-page.js` | headless 截整页（备用通道） | 非规则通道（2026-10-12 回退令，认 RF-IMG-14）；并行不抢 9222 时可用 |
| `who9222.py` | 查 9222 实况（down/idle/busy+锁主） | `py -3 who9222.py`；开工三查第②查（RF-SCREEN-03），busy 且锁非本批=退避重查 |

## 四、踩坑速查（判例细则认 `protocol/report-format.md` 规则 ID——本包无「skill 第 16 条」，已统一现行；㊳㊴㊵㊶对应 RF-CMD/RF-SCREEN/RF-GATE 族现行条文）

- URL 含 `&` 必须整条加引号，否则 cmd 截断（pageSize 不是内部命令判例）
- cls 与业务命令分两次发（同行 cls 会清掉命令行回显）
- 长命令：cd 短路径缩提示符 + `^` 续行（More? 是正常形态）
- CDP 被遗留 alert 页挂死：杀 chrome，`--user-data-dir=E:\Temp\cdp-profile --restore-last-session=false` 重启
- vision_gate 判定行已前置+max_tokens 3000（批二十三防截断；vision_review 侧 2000——批二十四）
- ps1 工具落盘必须 UTF-8 带 BOM 或纯 ASCII——无 BOM 的中文注释被 PowerShell 5.1 按 ANSI 解码会吞换行，报「空管道元素/意外的标记}」假解析错（2026-10-15 r14 场实判，ParseFile 定位 L47；存量 snapwin/snapchrome/cmdsend-any 均带 BOM 所以没炸）；snapdual.ps1 即因此纯 ASCII
- 异步执行的读回判定禁固定 sleep 硬等（RF-PKG-07）——r14 判例：trigger 20:15:20+固定 3 秒读回 20:15:23，执行器 20:15:25 才落盘，取证画面留「未找到」假阴性行，dual 门三连拦全拦对；先改脚本轮询重试，再谈拍图
- 判定解析只认「判定:」行（批二十九防绕过）：正文任何位置的 evidence_ok 字样（否定句「不是 evidence_ok」/选项回显）不再放行；--claim/--question 属不可信输入自动消毒（判定词与「判定：」伪指令剔除）；dual 型缺 --claim 直接拒收（exit 2 不调模型）；cmd 结论行失败字样（未找到/失败/error/Exception/拒绝/无法）即废，唯图注明示阴性对照/攻击前基线豁免——绕过测试 E2/E3/E4 三条偷懒路径全部堵死

## 内嵌形态录屏（record-page.js，不占屏幕不用锁）

headless Chrome recordVideo 录**页面视频**——双会话并行时的优先录屏形态：

```
# 一次性桥接系统 ffmpeg（建过就跳过）：
mkdir -p ./tmp/pw-ffmpeg/ffmpeg-1013
copy D:\ai\tools\ffmpeg\ffmpeg.exe E:\Temp\pw-ffmpeg\ffmpeg-1013\ffmpeg-win64.exe
# 录（env 必须在 node 启动前设置）：
PLAYWRIGHT_BROWSERS_PATH=./tmp/pw-ffmpeg node record-page.js "http://页1|http://页2" out.webm 3000 [选择器1|选择器2]
```

- 页面导航序列 + 可选点击序列，每页停留毫秒数；产出 webm（ffmpeg 可转 mkv）
- **边界**：录不到终端区（终端命令证据用 cmd 实拍图嵌卷/ffmpeg 拼合）；录不到浏览器原生 alert 框体（弹窗叙事仍走全屏形态+锁）
- 何时用全屏 ffmpeg 形态（持锁）：需要「敲命令↔页面同步变化」双区同框叙事、或弹窗镜头

## 五、双会话并行（A/B 两批同时跑时）

共抢四样：CDP 浏览器 9222、CMDPHOTO 终端、屏幕置顶/最大化、ffmpeg 全屏录制。分家+互斥：

1. **前端证据图一律外部真浏览器**（CDP 9222 + snapchrome，认 RF-IMG-14——内置浏览器已不作规则通道）；双批不抢 9222 = shotlock 互斥轮候（§三开工三查），或 B 批独立 profile 另起 debug 端口；不占屏的并行录屏走 record-page.js（headless）；位置图备选条件认 RF-IMG-03
2. **终端窗口按 title 分家**：A 批窗口 title=CMDPHOTO，B 批 title=CMDPHOTO-B；
   `cmdsend-any.ps1 <文件> -Title CMDPHOTO-B` / `snapwin.ps1 <输出> -Title CMDPHOTO-B`
3. **弹窗图与录屏必须持锁**（要动真屏幕：置顶/最大化/ffmpeg 全屏）：
   ```
   py -3 shotlock.py acquire --owner A --wait 3600  # 拿锁（与 RF-SCREEN-01 同参；B 批用 --owner B；等不到自动轮询）
   ...拍图/录屏...
   py -3 shotlock.py release --owner A              # 干完立即释放
   ```
   锁=E:\Temp\vis-lock\lock.json，O_CREAT\|O_EXCL 原子创建；stale 判定读**锁内 ts 字段**（非文件 mtime）：ts 距今>600 秒自动接管（对方暴死不卡死；时钟回拨/伪造 ts 只能推迟接管，判定信任写锁方时钟——残余风险，2026-10-16 r16 口径与 shotlock.py 对齐）
4. 录屏期间另一批只做写卷/重放，不拍不录

## XSS/弹窗图与画面红线（㊷⑥⑦⑧）

- XSS/弹窗类证据图：**真浏览器**（外部可见 Chrome + snapchrome 窗口截屏）——alert 框体+地址栏载荷必须入画；不用内置浏览器
- 内置通道（截图/录屏）视口一律最大 1536×864（record-page.js 已默认；browser-use 截图前显式设最大视口）
- 任何画面不得出现 Zcode 会话窗/聊天/任务面板：内嵌形态天然免疫；走外部屏幕（snapchrome/全屏 ffmpeg/snapwin）前先最小化 Zcode 及所有无关窗口

## 黑屏/挂机（㊷③补充）

- record-page.js / shot-page.js（headless）：不依赖显示器，锁屏关屏都能跑；唯一要求系统不睡眠（powercfg /change standby-timeout-ac 0）
- 全屏 ffmpeg / snapwin / snapchrome：必须亮屏+解锁，安排在有人值守时段

## 浏览器通道回退（2026-10-12，认 RF-IMG-14）

- 前端图默认通道回退为**外部真浏览器**（CDP 9222 导航 + snapchrome 截屏，持锁）；Zcode 内置浏览器不再作默认（shot-page.js 保留作备用工具但非规则通道）
- cmd 拍图：snapwin -Slot left（A）/ right（B）半屏分家免锁；full 模式持锁
- record-page.js（headless 页面录屏，独立进程非 Zcode 内置浏览器）保留：并行优先、不占屏不用锁

## 录屏=对方全停（RF-SCREEN-02）

- 一方全屏录屏（持锁）期间，另一方**停止一切屏幕类操作**（含半屏 cmd 拍图——会入镜污染视频）
- 等待方只做：写卷/重放/内嵌 record-page 录屏（headless 不上屏幕）
- 恢复条件（二选一）：shotlock 锁释放，或持锁方项目容器已关（docker ps/端口探活）

## 开工三查（用浏览器前）

```
py -3 who9222.py
# {"9222":"down"}  浏览器未起 → 拿锁后自己起（--remote-debugging-port=9222 独立 profile）
# {"9222":"idle"}  没人用   → 拿锁后直接连
# {"9222":"busy","lock_owner":"B"} 而你是 A → 对方没拿锁在用（违规/残留）→ 退避等待重查，记台账
```
锁原子创建=两批不可能同时持锁；who9222 兜住绕锁者。

## 两终端同框问题（RF-SCREEN-04）

- 静态图：snapwin 只截自己窗口矩形，两终端物理上不同框
- 全屏录屏：拍整屏——等待方"停止操作"不够，**必须把自己终端窗口最小化收起**（否则入镜污染）；
  持锁方录屏前核一遍屏幕只剩自己双窗

