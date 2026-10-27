# PHP 独立白盒审计方法论

> **消歧头（2026-10-15 复核批）**：本卡为 v7 同源搬回的冻结长文——正则分叉在 `deterministic-regex-and-java.md`（Java 文）不在本文件；本文件经复核批加了本消歧头并修正两处悬空引用（website-only-two-role→website.md、删 compact-core 残句），其余正文与 v7 同源。凡与 SKILL 冲突处一律以 SKILL 为准——含但不限于：§12 的「一漏洞一 Markdown」交付口径（现行 = H-13 唯一 DOCX）、外部 Doctor/DeepAudit 交接形态（现行 = hard_gate 三相位）、角色分工细节（现行 = SKILL 花名册）。

本文件是本 Skill 自带的 PHP 方法论。它保留旧版中入口、路由、正则、鉴权、参数绑定、Source -> Filter -> Sink、双向追踪、反证、抽样和交付规则，但不要求 DeepAudit 后端、外部 API、旧 Skill 或特定 Agent 类存在。PHP 项目由郭嘉使用本文件建立底账，曹操按本 Skill 的链锁和九将流程收口。

本卡仅用于源码分支（`local_source` / `source_and_website`）的 PHP 项目审计；`website_only` 不加载本卡流程，按 [网站三人流程](../protocol/website.md) 执行。

## 1. 方法边界和不变规则

- 只读取当前任务信封允许的本地 PHP 项目、配置、依赖、容器材料和已授权证据。`allowed_files`/`target_files` 非空时是硬范围；不可读、截断、生成物、缺失依赖和快照外引用进入 coverage，不能静默扩大范围。
- 默认先做静态白盒审计。只有曹操发出 `chain_lock_granted` 和 `approved_for_runtime`，且任务范围允许，才在本地隔离容器/Doctor 中运行验证。PHP 方法论本身不授权远程登录、利用链或破坏性动作。
- 关键字、正则命中、函数名、前端按钮、版本号、HTTP 200、异常信息和公开 PoC 都只是线索。最终 finding 必须同时证明真实入口、攻击者可控值、完整传播、实际效果和防护缺口五门。
- 角色证据保持独立上下文；共享工作区只交换带来源和哈希的事实，不把另一个 Agent 的聊天或结论当成自己的确认。
- 遇到任何 Filter、sanitizer、validator、白名单、编码、路径保护或权限保护，先查曹冲公共账；无匹配记录就让曹冲在当前链上审查。不能因 PHP 项目简单而跳过这一门。

四本账必须持续更新：

1. **入口账**：Web、直接脚本、CLI、Hook、回调、队列、计划任务、文件和消息入口，以及它们实际命中的鉴权。
2. **链路账**：`Entry -> Source -> 赋值/数组键/对象字段 -> Filter/Authz -> Sink`，每一跳保留 `file:line`、变量和转换。
3. **反证账**：参数绑定、固定映射、类型收窄、租户/属主条件、路径边界、编码、失败分支和运行配置。
4. **覆盖账**：已读文件、已反查 Sink、未解析动态分派、缺失模块、生成代码、范围外内容和未完成链。

## 2. PHP 项目起手底账

在判断漏洞前，郭嘉先记录：

- PHP、Composer、扩展和运行 profile；`composer.json`/`composer.lock`、autoload、框架版本和 PHP 配置；
- Web 根目录、`public/index.php`/`index.php`、bootstrap、Kernel、入口重写规则和错误处理；
- 路由文件、控制器、可调用 Action、middleware、guard、firewall、policy、voter、behavior 和异常分支；
- 模板、上传/存储/缓存/session/日志目录，以及运行用户对目录的读写权限；
- 数据库、缓存、队列、消息、cron、CLI、worker、插件和回调；
- 环境变量、配置合并、debug/profile 分支、测试/示例/备份文件、生成代码和外部 include；
- 文件地图、每个文件的快照哈希、扫描上限、跳过目录、不可读文件和快照完整性。

只看 `routes` 文件不算完成。真实入口可能在自动加载、魔术方法、Hook、插件注册、变量函数、直接 PHP 文件、重写规则、默认控制器、CLI 或消息消费者中。

### 2.1 完整度和运行失败分流

只能凭证据标记 `complete`、`incomplete`、`closed_source_or_binary_only` 或 `unknown`：

- 声明的 Composer 包/模块没有源码、autoload/include 指向缺失目标、路由/Hook 找不到处理器、清单截断、只剩构建产物或关键配置缺失，才是 `incomplete` 信号；
- Composer、扩展、数据库、权限、端口、容器或配置导致运行失败，不自动证明源码不完整；
- 源码完整但 Doctor/容器失败，保持全量静态审计，单独记录 `environment_failure`；
- 完整度未知时先补文件、模块、入口、依赖和缺失边界账，结论范围写 `unknown`；
- 闭源/二进制只读到片段时允许有界抽样，但必须写已知分母、必读骨架、抽样层、未抽样层、缺失模块和不可推断事实，不能把样本命中率外推为全项目结论。

只有当“运行环境搭建失败”与“源码快照明确不完整”同时成立，才启动稳定分层抽样：

1. 构建/依赖、启动/profile、入口重写、路由、全部鉴权配置、公开脚本和已定位高危 Sink 全读，不抽样。
2. 按模块/插件、Web/CLI/队列/Hook、鉴权边界、Controller/Service/Model/模板层、SQL/文件/命令/对象/外连/业务状态 Sink 分层。
3. 动态 include、变量函数、上传解压、raw SQL、执行、`unserialize`、远程请求、角色/金额/订单状态变更和未解析边界全部优先读；只对重复样板 CRUD 取样。
4. 按相对路径稳定排序或稳定哈希取样，记录 `file/reason/stratum/selected_by`；发现新 Hook、容器解析器、helper 或 Sink 家族立即扩样。
5. 进入缺失源码或依赖的链只能写 `needs_review`，不能凭邻近文件补写调用关系。

### 2.2 前端与确定性高危功能线

PHP 主线不等待前端按钮来确认后端入口。允许范围内的 JS、MJS、CJS、JSX、TS、TSX、Vue、Svelte、HTML 和构建配置应单独扫描请求 API、静态路径、HTTP method、参数、表单、FormData、上传、导入、删除、任务和外部 URL；复杂拼接、加密/混淆路径、动态 Include、未解析 GraphQL/WebSocket 只记 `dynamic_unresolved` 或信号。

前后端先分别保存证据，再用 `METHOD + normalized_path`、参数名、字段名、文件字段和 handler 上下文对齐。前端只提供入口/覆盖证据：

- JS 与 PHP 同时闭合真实链，静态可信度最高；
- 只有 PHP 后端链时标 `backend_only`，继续独立审查；
- 只有前端请求或按钮时标 `unmatched_frontend`/`dynamic_unresolved`，不能进入最终漏洞队列；
- 测试、调试、内部和未挂菜单的接口不能静默排除，附 `test_only`、`debug_only`、`unlinked_static` 或 `hidden_backend_entry` 标签。

前端基线 diff 只用于调整优先级，不删除当前代码证据；前端缺少对应请求不代表 PHP 入口不存在。

## 3. 确定性正则和 PHP 扫描方法

### 3.1 正则的定位

正则只建立候选索引。每次命中至少保存：`rule_id`、语言、文件、行号、匹配文本、前后至少两行上下文、快照哈希、扫描版本、`candidate_only=true`。命中重复时可按文件/行/类型去重，但不能删除不同规则的原始命中。

PHP 语法包含嵌套、字符串、注释、变量变量和动态调用；结构性问题优先用 AST、框架解析或局部语法读取，不能用一条大正则假装解析完整 PHP。没有 AST 时，使用有界的词法/上下文规则，并把不确定处标为 `dynamic_unresolved`。

### 3.2 PHP `preg_*` 执行纪律

使用固定规则时可用 `preg_match`/`preg_match_all`，规则以 `~...~i` 等明确分隔符和修饰符表示。对动态字面量使用 `preg_quote($literal, '~')`，不得把路径或用户输入直接拼成正则。跨行 `s` 只用于有界函数/配置片段，并设置最大字符数；不要对无限增长的请求或整个项目做无界回溯。

推荐的最小记录骨架：

```php
$pattern = '~\\bRoute\\s*::\\s*(?<method>get|post|put|patch|delete|options|head|any|match|resource|rule)\\s*\\(~i';
$matches = [];
$result = preg_match_all(
    $pattern,
    $source,
    $matches,
    PREG_SET_ORDER | PREG_OFFSET_CAPTURE
);

if ($result === false) {
    // 记录 rule_id、preg_last_error() 和 coverage，不把失败当成无命中。
}

foreach ($matches as $match) {
    $offset = $match[0][1];
    $line = 1 + substr_count($source, "\\n", 0, $offset);
    // 保存命名组、line、上下文、快照和 candidate_only=true。
}
```

`preg_match_all` 找到文本信号，不等于路由、参数或危险链成立。`preg_last_error()`、编码不兼容、超限、跳过二进制和无法解析的动态构造都进入 coverage。正则命中后必须读取完整函数/闭包/类和调用上下文。

### 3.3 保留的规则种子

这些规则应按语言和项目范围执行；规则只是候选，不能直接写漏洞：

| `rule_id` | 正则/结构信号 | 用途 |
| --- | --- | --- |
| `PHP_ENTRY_SUPERGLOBAL_V5` | `\\$_(?:GET|POST|REQUEST|COOKIE|FILES)\\s*\\[\\s*['"](?<key>[^'"]+)` | 超全局输入和字段 |
| `PHP_ENTRY_BODY_V5` | `php://input|json_decode\\s*\\(|getallheaders\\s*\\(|filter_input\\s*\\(` | 原始体、JSON、Header 和过滤输入 |
| `PHP_ENTRY_ROUTE_CALL_V5` | `\\bRoute\\s*::\\s*(?<method>get|post|put|patch|delete|options|head|any|match|resource|rule)\\s*\\(` | 传统/框架 Route 调用 |
| `PHP_ENTRY_HOOK_V5` | `\\b(?:add_action|add_filter|register_rest_route|wp_ajax(?:_nopriv)?|admin_post(?:_nopriv)?)\\s*\\(` | WordPress/Hook 入口 |
| `PHP_ENTRY_DISPATCH_V5` | `PATH_INFO|REQUEST_URI|\\b(?:m|a|c|module|controller|action|method|file)\\b` | 裸 PHP/模块分派候选 |
| `PHP_SQL_SIGNAL_V5` | `mysql_query\\s*\\(|mysqli_query\\s*\\(|\\$\\w+->query\\s*\\(|whereRaw|orderByRaw|DB::raw|\\$\\{` | SQL/动态标识符候选 |
| `PHP_FILE_SIGNAL_V5` | `include\\s*\\(|require(?:_once)?\\s*\\(|file_get_contents\\s*\\(|fopen\\s*\\(|unlink\\s*\\(|rename\\s*\\(|copy\\s*\\(|ZipArchive|extractTo|move_uploaded_file` | 文件加载、读写、上传、解压 |
| `PHP_EXEC_SIGNAL_V5` | `\\b(?:system|exec|shell_exec|passthru|proc_open|popen|eval|assert|call_user_func)\\s*\\(` | 执行/动态调用候选 |
| `PHP_OBJECT_SIGNAL_V5` | `unserialize\\s*\\(|Phar|__wakeup|__unserialize|__destruct|__toString|__call` | 对象解析和魔术方法 |
| `PHP_OUTPUT_SIGNAL_V5` | `echo\\s+\\$_|print\\s+\\$_|{!!|\\braw\\b|Markup\\s*\\(|th:utext` | 输出上下文/XSS 候选 |
| `PHP_HTTP_SIGNAL_V5` | `curl_setopt|CURLOPT_URL|file_get_contents\\s*\\(\\s*\\$_|Guzzle|HttpClient` | 外部请求/SSRF 候选 |
| `PHP_FILTER_SIGNAL_V5` | `\\b(?:filter|sanitize|validate|verify|check|allowlist|whitelist|normalize|escape)\\b` | 强制触发曹冲 Filter 审查 |

高危种子使用更精确的专用规则补充，例如 `include($x)`、`unserialize($x)`、`exec($x)`、`$pdo->query("..." . $x)`、`preg_replace(.../e...)` 和用户输入到 `move_uploaded_file` 的目标路径。专用规则优先，通用规则只补漏。

## 4. 入口和路由还原

### 4.1 Laravel

- 展开 `routes/web.php`、`api.php`、`console.php`、`channels.php` 和自定义路由文件的 group `prefix`、`domain`、`middleware`、`where`、`name`、嵌套顺序、HTTP method 和最终 URI。
- 核对 Kernel 或应用 bootstrap 中 middleware group/alias 的实际注册和顺序；控制器注解或方法名不能代替路由证据。
- 记录 Controller、invokable Action、闭包、Job、Listener、Command、事件和队列入口；路由模型绑定必须追到真实对象和资源授权。
- FormRequest 的 `rules` 只证明格式校验；必须证明当前 Action 实际注入并执行，且资源权限另由 Policy/Gate/`authorize`/scope/tenant/owner 约束。

### 4.2 Symfony

- 合并 Attribute、YAML、XML、PHP route，核对 path、method、host、condition、priority 和 Controller。
- 按 firewall 顺序、`pattern`、`security`、`stateless`、`access_control` first-match、Voter 和异常处理确定实际保护。
- `ParamConverter`/`EntityValueResolver` 自动取对象不等于有对象级授权；继续找 owner/tenant/组织边界。
- Messenger handler、Console command、事件订阅和直接控制器都进入入口账。

### 4.3 ThinkPHP、Yii 和其他框架

- 展开模块/控制器/方法分派、路由配置、middleware/behavior 的 `only`/`except`、默认控制器和版本差异。
- `input`/`request`/`param` 取值后的 filter/default/type 只按真实参数和最终 Sink 判断；全局过滤器不能替代语义防护。
- Model 的 `allowField`、`fillable`/`guarded`、`save`/`update`、scenario/safe rules 必须与当前字段集合和 Action 对齐。
- 任何自定义 Router、Hook、插件注册、容器解析或动态 Controller 不能仅凭命名推断；记录无法闭合的断点。

### 4.4 WordPress

- 枚举 `register_rest_route`、`wp_ajax`/`wp_ajax_nopriv`、`admin_post`/`admin_post_nopriv`、shortcode、`template_redirect`、插件 Hook 和可直达 PHP 文件。
- `permission_callback` 要核返回语义；`wp_ajax_nopriv` 是匿名入口；`check_ajax_referer`/`wp_verify_nonce` 主要验证请求意图，不代替 capability、角色、owner 或 tenant 授权。
- 插件文件从 Web 根直达时核 `ABSPATH` guard 是否存在、是否在统一初始化之前执行，以及直达分支是否跳过权限。

### 4.5 传统 PHP、重写和非 Web 入口

- 从 Apache/Nginx/IIS 重写规则、Web 根、`index.php`、PATH_INFO、查询参数和脚本名还原外部路径；`m/a/c`、module/controller/action、文件名或类名分派必须追到最终 include/调用。
- 枚举 CLI、cron、queue、worker、文件监听、Webhook、回调、消息和缓存消费；定时任务自身不是漏洞，只有不可信数据能进入危险操作才形成 Source。
- 自动加载、动态 `include/require`、`__call`、变量函数、`call_user_func` 和容器解析要写出解析是否确定。无法确定时是覆盖缺口，不是任意调用结论。

## 5. Source、参数绑定和信任边界

除 `$_GET`、`$_POST`、`$_REQUEST`、`$_COOKIE`、`$_FILES`、`$_SERVER` 外，还要检查：

- `php://input`、JSON 解码、Header、Authorization、路由参数、框架 Request、表单和上传对象；
- CLI `argv`/stdin、环境变量、Session、Cookie、缓存、数据库、队列和消息中由低信任主体写入的值；
- 数组键、对象属性、DTO、Model 批量赋值、`extract`、`parse_str`、变量变量和类型转换；
- 上传内容、原始文件名、目标文件名、目录、扩展名、URL、类名、方法名、排序/列名和完整 SQL 片段各自的控制粒度。

变量名相同不代表同一个 Source。每次赋值、拼接、解码、数组合并、字段复制和跨函数传参都要逐跳记录；只见参数名、前端字段或超全局命中时，最多写 `likely`。

## 6. 鉴权、CSRF 和资源边界

每条入口标记 `enforced`、`partial`、`none` 或 `unknown`，并给出执行证据：

1. 路由最终绑定了哪些 middleware、firewall、behavior、permission callback 或 Hook，实际顺序和例外是什么。
2. 认证只证明“是谁”，CSRF token、WordPress nonce 和表单 token 主要证明请求意图，不能代替角色、capability、owner 或 tenant 授权。
3. 资源查询、更新、删除和批量操作是否把当前主体/租户绑定进查询条件；仅要求登录、隐藏 ID、UUID 或前端菜单控制都不够。
4. `only`/`except`、默认路由、直接脚本、子请求、插件入口、异常分支、重定向和方法差异是否绕过统一保护。
5. 当前环境/profile/config 是否真的启用保护；注释、测试配置、未注册 Middleware、日志和前端隐藏不算有效防护。

Session 读取、`session_start`、Cookie 存在或 `is_user_logged_in` 只能作为信号；继续核签名、固定、更新、注销、并发状态、跨租户键和可信主体来源。

## 7. 两头追踪：Source 正追和 Sink 反查

### 7.1 从入口向下

对高价值入口按执行顺序确认：

1. 攻击者控制整串、数组键、字段、内容、原始文件名、最终路径、类名、方法名、URL 还是仅一个封闭值。
2. 每次赋值、拼接、解码、类型转换、数组合并、对象填充、Model 写入和跨函数参数传递。
3. Filter/Validator/Authz 在哪条分支执行，保护的是不是最终危险参数；失败、异常、空值、超限和未知枚举是否真正 `return`/`throw`。
4. 变量进入哪个 Sink 的哪个参数，最终查询、读写、包含、执行、请求、解析、渲染或状态改变是什么。

### 7.2 从危险点向上

对每个 Sink 反查所有调用者，而不是只看前端是否存在按钮：

- SQL：PDO/mysqli 原始查询、`DB::raw`、`whereRaw`/`orderByRaw`、ThinkPHP `exp`、字符串 where、动态列/表/排序；
- 文件：`include`/`require`、`file_get_contents`、`fopen`、`unlink`、`rename`、`copy`、`ZipArchive`、`Phar`、`move_uploaded_file`、Storage；
- 执行：`eval`、`assert`、`preg_replace` 的旧 `e` 语义、变量函数、`call_user_func`、`system`/`exec`/`shell_exec`/`passthru`/`proc_open`/`popen`；
- 对象/模板：`unserialize`、魔术方法、Blade/Twig/Smarty raw 输出、`echo`/`print` 到 HTML/属性/URL/JS/CSS/JSON 上下文；
- 外部请求：cURL、Guzzle、stream wrapper、`file_get_contents` URL 和其他 HTTP 客户端；
- 业务状态：Model `fill/create/update/save`、金额、库存、订单、审批、角色、租户、密码/邮箱和回调状态。

两头只有在同一条可执行路径会合才算完整链。动态类名、变量变量、Hook 优先级、容器解析、动态 Include、反射和缺失模块不能靠相似名字补齐。

## 8. 五门成洞

每个 PHP finding 必须同时满足：

1. **可达**：外部路径、Hook、CLI、队列、文件或消息入口真实注册并能到达处理器；
2. **可控**：攻击者能控制具体值、字段、路径、文件名、内容、类名、callable 或 URL，且控制粒度明确；
3. **传播**：Source 到危险参数逐跳闭合，赋值、解码、类型转换、数组合并和跨函数传参都有证据；
4. **效果**：Sink 的真实结果可描述并由白盒或授权运行证据支持，不能用函数名或响应文案替代；
5. **防护**：当前执行路径没有覆盖该值、该分支和该 Sink 的有效 Filter/Authz，或存在明确旁路。

缺一门进入 `needs_review`/`coverage`；防护完整或传播断裂进入 `closed`，并保留反证。高危功能名只决定审查顺序，不决定漏洞类型；类型按最终效果定类，例如上传只能形成浏览器输出时按 XSS，只有确实控制服务器执行语义时才讨论代码执行。

## 9. PHP 风险信号的成链标准

### 9.1 SQL 和动态查询

必须回答 Source 是否进入 SQL 语法位、表/列/排序/条件片段或未参数化值位；`prepare`/`bind` 是否覆盖危险值；可控片段是否在绑定前已经拼入查询。`whereRaw`、`orderByRaw`、ORM raw 和 ThinkPHP `exp` 要逐参数核语义。

强反证包括固定 SQL 加正确占位符、动态列名经封闭枚举映射、查询始终绑定可信 tenant/owner 且请求不能覆盖。看到 `query`、`raw`、`${}` 只是高信号，不是自动注入。

### 9.2 Include、文件、上传和解压

把内容、原始文件名、目标文件名、目录、最终扩展名和访问 URL 分开记录：

- `include`/`require`：核绝对/相对路径、stream wrapper、扩展拼接、`realpath`、固定基目录和封闭白名单；
- 读写删除：核最终规范化路径、目录边界、盘符/UNC、编码/多次解码、符号链接、TOCTOU、覆盖和删除对象；
- 上传：核 `is_uploaded_file`/`move_uploaded_file`、MIME/内容/扩展、随机命名、存储目录、Web 可达性和服务器解释规则；
- `ZipArchive`/`extractTo`：逐条核 Entry 规范化、绝对路径、`..`、符号链接、覆盖和解压后加载；
- Phar：证明攻击者能控制 Phar 文件，且存在会读取元数据的可达操作；不能凭 gadget 名称猜测执行效果。

`basename`、删除一次 `../`、只验后缀、只验 MIME 或“放到 uploads”都不能单独闭合风险。

### 9.3 命令、动态代码和回调

- `system`/`exec`/`shell_exec`/`passthru`/反引号通常经过 Shell，追踪完整命令字符串；`proc_open`/`popen` 还要区分程序名、数组参数和 Shell 选项。
- `escapeshellarg` 只保护一个参数边界，不能修复可控程序名、选项注入、重新拼接或后续 Shell 解析；固定程序加封闭枚举参数是反证，需看是否存在第二个执行边界。
- `eval`/`assert`/变量函数/`call_user_func`/旧 `preg_replace` 执行语义必须证明攻击者控制代码、可调用目标或关键参数；`is_callable`/`method_exists` 只证明“能调用”，不证明“允许调用”。
- 回调、Hook 和事件要核注册来源、优先级、参数来源和是否可由请求选择；只看到回调名称不算任意调用。

### 9.4 对象解析和魔术方法

对 `unserialize` 追 Source、`allowed_classes`、autoload、返回对象后续用法和真实危险效果；`__wakeup`、`__unserialize`、`__destruct`、`__toString`、`__call` 只是 gadget 信号。`json_decode` 默认不是 PHP 对象反序列化漏洞；Phar 结论要结合 PHP 版本、配置和触发函数。不得生成、拼接或执行利用链。

### 9.5 模板、输出和 XSS

记录最终输出上下文：HTML 文本、属性、URL、JavaScript、CSS 或 JSON。Blade `{{ }}`、Twig 默认转义和正确上下文编码是反证；Blade `{!! !!}`、raw、Markup、手工 HTML/JS 拼接和二次解码要继续追。`htmlspecialchars` 必须核 flags、encoding、`double_encode` 和实际上下文，HTML 编码不能代替 URL/JS/CSS 编码。

### 9.6 SSRF 和外部请求

分别记录 `scheme`、`host`、`port`、`path`、`query` 的控制粒度；核 URL 解析、userinfo、编码、重定向、DNS 解析后 IP、代理、stream wrapper、内网 egress 和响应是否回传。固定目标加受限 path 通常不是完整 SSRF，但可能仍是路径越权；仅允许 HTTP/HTTPS 不是目标白名单。

### 9.7 业务状态、Mass Assignment 和弱比较

- IDOR/租户越权：主体、资源 ID、查询、更新、删除和批量操作都要绑定同一可信边界。
- Mass Assignment：记录请求字段 -> DTO/数组 -> `merge`/`only`/`except`/`fill` -> Model 的每一步；核 `$fillable`/`$guarded`、FormRequest 和服务端覆盖。
- 金额、库存、审批、角色、密码和回调：核旧状态、事务、锁、幂等、受影响行数和失败回滚。
- `==`、非严格 `in_array`、类型转换和真假值比较只有在两侧真实类型、可控值和关键分支闭合时才是漏洞；PHP 版本差异写入环境证据。

## 10. Filter、防护和误报止损

所有 Filter 先交曹冲。曹操收到结果后仍核对函数指纹、版本、输入契约、调用位置、分支和 Sink 是否一致。防护至少回答四问：

1. 真执行吗：当前路由、环境、Middleware/Hook 顺序和异常分支会命中吗？
2. 管到这个值吗：保护的是最终 SQL 片段、路径、命令参数、对象类型、输出上下文或资源 ID 吗？
3. 语义对吗：HTML 编码不能防 SQL，`basename` 不能单独证明路径受限，MIME 不能证明不可执行，nonce 不能代替授权。
4. 失败会关门吗：验证失败、解析异常、空值、超限、未知枚举和重复解码会 `return`/`throw`，还是继续进 Sink？

常见信号与止损：

| 信号 | 必须继续证明 | 不可直接下的结论 |
| --- | --- | --- |
| PDO/mysqli/ORM raw | 可控值进入 SQL 语法位，绑定覆盖范围 | 看见 query/raw 就报注入 |
| include/require | 可控路径、协议、扩展、基目录和加载可达性 | 文件名可控就报 RCE |
| 上传/解压 | 内容、名称、路径、Web 可达性、解释条件 | 只上传图片就报代码执行 |
| `system`/`exec` | 程序名/参数/Shell 边界和实际控制 | 看见 `escapeshellarg` 就一律安全或一律可绕 |
| `unserialize`/Phar | Source、配置、autoload、对象效果和版本 | 凭类名构造 gadget 结论 |
| raw 模板/echo | 最终输出上下文、编码和 raw 开关 | 所有 echo 都算 XSS |
| cURL/Guzzle | authority 控制、解析、redirect、DNS 和响应影响 | 只允许 HTTP/HTTPS 就算完整防护 |
| Model fill/update | 敏感字段集合、映射和资源边界 | 看到批量赋值就报越权 |
| 弱比较 | PHP 版本、两侧类型、可控值和关键影响 | 任何 `==` 都报认证绕过 |

## 11. 与九将流程的交接

### 郭嘉

郭嘉写入 `01-guo-jia/` 的 PHP 事实至少包括：PHP/Composer/扩展与完整度、Web 根和重写、框架/传统入口、路由/Hook/CLI/队列/cron、参数来源、实际鉴权、正则规则命中、动态断点、危险 Sink、文件清单和容器状态。每条初始条目必须说明入口在哪里、哪个变量可控、来源位置、潜在 Filter/Sink、最强反证和下一步，不宣布最终漏洞。

### 曹操、曹冲和运行验证

曹操把 PHP 条目按链指纹去重后逐条取得唯一 `chain_lock`。完整链先查曹冲公共账，再由曹操决定是否交于禁/曹仁/典韦或本地 Doctor。不同漏洞链不得并行发请求、改容器或验证 Filter；刘晔情报、郭嘉只读索引和模板准备可以并行。

于禁和典韦默认使用 `captcha_removed` 容器，且必须使用曹操批准的最小测试对象、停止条件、清理方案和同一目标证据；曹仁只做静态适用性核对、不运行目标，动态证实交于禁/典韦。验证码清理只发生在郭嘉建立的本地临时副本，固定记录 `remote_bypass=false`；PHP 方法论不允许远程绕过 CAPTCHA、MFA、WAF 或频控。

### CVE/CNVD

公开 CVE/CNVD 只提供线索。曹仁读取郭嘉的精确组件/版本，分别标记 `component_n_day` 与 `system_n_day`，再在当前 PHP 代码中核 Source -> Filter -> Sink、启用条件和补丁状态；缺外部情报时按需请求刘晔整理历史记录、影响版本、修复说明和 PoC 来源（两线可并行）。版本命中、公告或外部 PoC 不能代替本地链和验证；存疑资料进入 `needs_review`/存疑区。

### 高危终点和 Doctor 运行交接

定时任务、队列、CLI、动态加载、命令/模板、上传、导入、解压和对象解析是选路信号。典韦可以从触发器正查 Source，也可以从 Sink 反查调用者；新链必须回曹操查重，遇到 Filter 回曹冲，再由曹操批准于禁或本地 Doctor 验证。不能在 PHP 专项内另起一条绕过链，也不能因为“高危终点”名称直接报 RCE。

本 Skill 没有固定的 DeepAudit API。若宿主提供本地 Doctor，交接包至少包含 `chain_id`、快照哈希、入口、Source、逐跳链、Filter 结论、Sink、预期观测、允许动作、停止条件和清理方案；若宿主不提供，保留静态证据并把运行事实写入 `verification_gaps`。Doctor 状态应区分 `queued`、`running`、`completed`、`partial`、`failed`、`nothing_to_do`、`environment_failure` 和 `not_reproduced`，不能把下游状态直接改写成 `verified`。

只有明确证据显示 Sandbox/Docker、依赖准备、构建、启动或运行时准备失败，且快照已有 `incomplete` 证据时，才采用第 2.1 节抽样；快照完整时保持全量静态审计，完整度未知时先做 coverage-first。调度失败、没有候选、普通断言失败或候选未复现本身不触发抽样。

## 12. 交付结构和证据字段

静态审计输出四栏：`findings`、`needs_review`、`closed`、`coverage`。每条候选至少包含：

```yaml
candidate_id: PHP-0001
title: "简短事实标题"
vulnerability_type: sql_injection|path_traversal|file_inclusion|upload|command_injection|deserialization|xss|ssrf|idor|mass_assignment|other
severity: low|medium|high|critical
confidence: low|medium|high
entry_point:
  path_or_trigger: "POST /import 或 plugin hook/CLI"
  handler: "Controller@action"
  authz: enforced|partial|none|unknown
source:
  expression: "$request->input('name')"
  control_granularity: value|field|path|filename|content|class|callable|url|unknown
call_chain:
  - location: "app/Http/Controllers/ImportController.php:42"
    symbol: "import"
    variable: "name"
    transformation: "request -> DTO -> service"
filter_authz:
  status: effective|partial|missing|unknown|not_applicable
  locations: ["app/Support/Validator.php:18"]
sink:
  call: "..."
  dangerous_argument: "..."
  effect: "必须描述真实效果"
five_gates:
  reachability: proven|likely|unknown|false
  controllability: proven|likely|unknown|false
  propagation: proven|partial|unknown|false
  effect: proven|likely|unknown|false
  defense: missing|partial|effective|unknown
evidence:
  snapshot_sha256: "..."
  files: ["...:line"]
  runtime_ids: []
  screenshots: []
negative_evidence: []
verification_gaps: []
root_cause: "..."
remediation: "..."
```

`severity` 表示若链成立的影响，`confidence` 表示当前证据完整度，两者不能互换。静态 Agent 不把自己的候选写成 `verified`；曹操核对于禁请求、响应、截图、容器和白盒行号后定稿，交曹操分身 report_layout 生成正式交付（一漏洞一 Markdown，另存 JSON、PoC/最小复现和证据索引），主会话不得调 docx_report.py 或手写顶替。

## 13. 两轮收工检查

第一轮按入口账铺全并建立候选；第二轮从 SQL、文件、执行、对象、模板、外连和业务 Sink 反查调用者，复查共享 Middleware/Hook、Helper、Model、上传目录、动态加载器和相邻入口。只有以下条件同时满足才收工：

- 范围内入口都有鉴权状态，高风险入口已追链；
- 每个高危 Sink 都有处置、闭合链或明确断点；
- finding 五门齐全，逐跳 `file:line`、快照和最强反证可复读；
- Filter 全部查过曹冲，结论限定到正确函数指纹、版本、输入和 Sink；
- 动态分派、缺失依赖、生成代码、运行失败和未抽层都进入 coverage；
- “没发现”只表示当前范围、文件、容器和预算内没有形成闭合 finding，不写成项目绝对安全。
