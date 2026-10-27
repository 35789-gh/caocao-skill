# 确定性正则、混合匹配与 Java/Spring 规则

本文件是本 Skill 自带的方法论，不依赖旧版本资料。它把正则和 Java 规则用于“建立入口/风险候选索引”，不把命中直接升级成漏洞。

## 1. 扫描契约

1. 先建立文件清单、语言、模块、快照哈希和覆盖上限。默认读取源码、路由配置、模板、构建配置、依赖清单、容器配置和允许范围内的静态资源；`node_modules`、`vendor`、构建产物等跳过项必须记入 coverage。
2. 第一遍做确定性规则匹配：按语言取专用规则，再合并 `_common` 规则。对每个命中保存 `rule_id`、文件、行号、原文、前后至少两行上下文、语言、快照和 `candidate_only=true`。
3. 第二遍做混合模式：把前端请求、后端声明、参数绑定、鉴权/Filter 和危险 Sink 的结果按 `METHOD + normalized_path`、参数名、字段名、文件字段、handler 和调用上下文对齐。字符串常量可静态解析才生成固定路径；复杂拼接、加密、运行时注册和未解析 GraphQL/WebSocket 只记 `dynamic_unresolved`。
4. 对候选从入口向下追 Source -> Propagation -> Filter/Authz -> Sink，也从 Sink 向上反查调用者。每一跳保留 `file:line`；缺一跳就留在线索或 `needs_review`。
5. 正则执行失败、编码不一致、文件超限、无法解析和命中重复都必须写入覆盖账；不能把“没有命中”解释成“没有入口”。

## 2. 规则种子

以下是保留语义的确定性种子。宿主可以用等价的语言正则 API 实现，但不能删除规则家族或改变“只做候选”的语义。PHP 的完整入口、`preg_*`、框架路由和 Sink 规则见 [PHP 独立方法论](php-methodology.md)。

| rule_id | 语言 | 正则/结构信号 | 用途 |
| --- | --- | --- | --- |
| `ENTRY_PHP_REQUEST_V5` | PHP | `\$_(?:GET\|POST\|REQUEST\|COOKIE\|FILES)\s*\[\s*['\"](?P<key>[^'\"]+)` | 请求变量与字段来源 |
| `ENTRY_JS_REQUEST_V5` | JS/TS | `\b(fetch\|axios\.(?:get\|post\|put\|patch\|delete)\|XMLHttpRequest\|\$\.ajax)\s*\(` | 前端请求调用 |
| `ENTRY_JS_FORMDATA_V5` | JS/TS | `\bnew\s+FormData\s*\(|\.append\s*\(\s*['\"](?P<field>[^'\"]+)` | 表单/上传字段 |
| `ENTRY_JAVA_MAPPING_V5` | Java | `@(?:RequestMapping\|GetMapping\|PostMapping\|PutMapping\|PatchMapping\|DeleteMapping)\b` | Spring MVC 注解入口 |
| `ENTRY_JAVA_NONHTTP_V5` | Java | `@(?:Scheduled\|KafkaListener\|RabbitListener\|JmsListener)\b` | 任务、消息和异步入口 |
| `SOURCE_JAVA_REQUEST_V5` | Java | `(?:@(?:PathVariable\|RequestParam\|RequestBody\|RequestHeader\|CookieValue\|RequestPart\|ModelAttribute)\b\|\w+\.getParameter(?:Values)?\s*\()` | Java 外部输入来源。注意 `@` 前不设 `\b`（`@` 非单词字符，`\b` 会让注解永远匹配不上，只剩 getParameter 一条腿） |
| `SINK_SQL_V5` | 多语言 | `${...}`、`createQuery(`、`.query(`、`executeQuery(`、`text(` | 动态 SQL 候选 |
| `SINK_FILE_V5` | 多语言 | `MultipartFile`、`ZipEntry`、`Files\.(?:read\|write\|delete)`、`open(`、`sendFile(` | 文件读写、上传、解压 |
| `SINK_CMD_V5` | 多语言 | `ProcessBuilder`、`Runtime\.getRuntime\(\)\.exec`、`subprocess\.(?:run\|call\|Popen)`、`exec\(` | 命令/脚本执行候选 |
| `SINK_OBJECT_PARSE_V5` | 多语言 | `ObjectInputStream`、`readObject(`、`XMLDecoder`、`pickle\.loads?`、`yaml\.(?:load\|unsafe_load)` | 对象解析候选 |
| `SINK_HTTP_OUTBOUND_V5` | 多语言 | `new URL(`、`HttpClient`、`requests\.(?:get\|post)`、`fetch(`、`axios\.` | 服务端外连/SSRF 候选 |
| `SINK_OUTPUT_V5` | 多语言 | `innerHTML\s*=`、`dangerouslySetInnerHTML`、`th:utext`、`echo\s+\$_` | 输出/XSS 候选 |
| `FILTER_SIGNAL_V5` | 多语言 | `\b(?:filter\|sanitize\|validate\|verify\|check\|allowlist\|whitelist|normalize)\b` | 触发曹冲审查，不代表防护有效 |

风险种子仍要使用专用规则补充精度，例如 Java 的 `Runtime.exec` 参数拼接、MyBatis `${}`、PHP `include($x)`、JS `res.sendFile(x)`。不能只靠一条跨语言大正则；专用规则优先，通用规则只补漏。

## 3. Java 正则实现方法

### 3.1 `Pattern`/`Matcher` 纪律

Java 中用 `Pattern.compile(regex, Pattern.CASE_INSENSITIVE)` 创建可复用规则，用 `Matcher.find()` 找行内候选；不要用 `matches()` 误把“整行匹配”当作“包含信号”。需要跨行的结构只在明确边界内使用 `Pattern.DOTALL`，并设字符上限，避免把整个文件吞进一次匹配。

每次 `find()` 都记录 `start()`/`end()` 对应的源码行，优先使用命名组提取 `path`、`method`、`field`、`variable`；没有命名组时保留原文，不凭捕获组位置猜语义。字面路径拼接正则必须使用 `Pattern.quote(literal)`，不能把路径原文直接拼成正则。多个规则应按 `rule_id` 独立运行，再按同一文件/行/类型去重，不覆盖原始命中。

推荐的最小 Java 扫描骨架：

```java
Pattern rule = Pattern.compile(
    "@(?:RequestMapping|GetMapping|PostMapping|PutMapping|PatchMapping|DeleteMapping)\\b",
    Pattern.CASE_INSENSITIVE
);
Matcher matcher = rule.matcher(sourceText);
while (matcher.find()) {
    int line = 1 + (int) sourceText.substring(0, matcher.start()).chars()
        .filter(ch -> ch == '\\n').count();
    // 记录 rule_id、line、上下文和 candidate_only=true；之后再解析上下文。
}
```

这段代码只证明注解出现。真正路由需要合并类级/方法级映射、继承/接口映射、context path、servlet path、代理前缀、HTTP method 和 handler；复杂 annotation value 或常量引用无法静态求值时标 `unknown`。

### 3.2 Spring 入口和参数绑定

对每个 Java 入口分别记录：

```text
外部路径 | context path | servlet path | Security matcher 所见路径 | HTTP method
| handler | 参数来源 | 注册位置 file:line | 鉴权状态
```

参数来源不只看显式注解，还要看未注解简单类型、`@ModelAttribute`、`@RequestBody`、Header、Cookie、Part、原始流、Session 和缓存写入点。`Principal`、`Authentication`、`Locale` 等框架注入对象不是攻击者字段。DTO 的可写字段、`@InitBinder`、Jackson 可见性、setter、构造器和服务端覆盖必须继续核对。

### 3.3 Spring Security 实际覆盖

按执行顺序核对六层：

1. 请求是否被 `web.ignoring`、静态资源规则或自定义防火墙排除。
2. 多条 `SecurityFilterChain` 的 `@Order` 与 `securityMatcher` 命中了哪一条。
3. 链内 `requestMatchers` 的方法、路径、规则先后和最终兜底是 `permitAll`、`anonymous` 还是 `authenticated`。
4. 自定义 Filter 的注册位置、路径范围、Token/认证对象建立方式，以及解析失败、异常、缺失 Token 是否放行。
5. `@EnableMethodSecurity` 或旧版开关是否启用，所用方法注解是否被支持。
6. 方法是否通过受管 Bean 代理执行；自调用、`private/final`、手工 `new` 和未扫描 Bean 可能不受方法拦截。

注册 Bean、看到注解、存在 Filter 名字或前端隐藏按钮都不能代替实际覆盖证据。`excludePathPatterns`、尾斜杠、扩展名、HTTP 方法差异、Shiro 规则顺序和 catch-all 后继续放行都要记录。

### 3.4 Java Source -> Filter -> Sink

对 Java 高危种子优先核：

- SQL：`${}`、字符串拼接、native query、排序/列名/表名是否来自外部输入；`#{}` 只保护值位，不能自动保护标识符。
- 文件：内容、目录、最终文件名、扩展名分开判断；路径应在最终解析形态下规范化并核 `startsWith(base)` 的路径语义、符号链接和 TOCTOU。
- 命令：参数数组不等于 shell 注入；若进入 `sh -c`、`cmd /c` 或解释器，再核字符串边界和可控参数。
- 对象解析：核当前实例、输入来源、类型选择能力、allowlist、深度/大小限制和解析前是否生效。
- Filter/Validator：核成功、失败、异常、空值、超限和重复解码分支是否都阻断，且保护的是同一变量、同一 Sink。

只有入口、可控变量、逐跳传播、实际危险效果和无效/缺失防护五门闭合，才交曹操进入链队列。命中 Java 正则、CVE、危险 API 或类名都不是最终结论。
