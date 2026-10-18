# 已知问题与可修改点（Open Issues）

> 📌 **v2 状态表（2026-10-17，JWE 协议重做后复核）**：本文以下正文是 v1 时代的记录，**已随 v2 协议重做大部分失效**。逐条处置如下；除标注"仍开放"外，其余条目问题已不复存在（所在代码已删或行为已重写）。
>
> | 条目 | v2 处置 | 说明 |
> | --- | --- | --- |
> | P0-1 | 🟩 消除 | uri 级配置重做为 kid 白名单（`crypto-config` → Map&lt;String,List&lt;String&gt;&gt;），有绑定回归测试 |
> | P0-2、P0-3、P0-6、P0-7 | 🟩 消除 | 所在代码（reactive 加密路径/pom 残留/常量撞值/EncryptorKit）已删 |
> | P0-4、P0-5、P1-1 | 🟩 消除 | v2 防重放默认开启：`ReplayGuard` 对称时间窗 + `InMemoryNonceStore.compute` 原子消费，且在 GCM tag 校验后 |
> | P1-2 | 🟩 消除 | v2 熵源：客户端 WebCrypto `getRandomValues`，服务端 `SecureRandom` |
> | P1-3、P1-4、P1-6 | 🟩 消除 | v2 无 MD5/无 PKCS1v15/客户端不可选算法（白名单在 codec 内强制） |
> | P1-5、P1-7、P1-8 | 🟩 消除 | 统一 UTF-8；JWE 结构解析；WebContext 入口重置 + 最外层 clear |
> | P1-9、P1-10、P1-11 | 🟩 消除 | 响应过滤器链后判黑名单；converter 已删；请求视图单一来源（明文） |
> | P1-12、P1-13 | 🟩 消除 | `EncryptorFailure` 分类 + 统一 failure-status + traceId；max-request/response-size 两侧强制 + 有界执行器 |
> | P2-1、P2-4、P2-6 | 🟩 消除 | HttpTest 真断言；GroupEncryptor 已删；surefire 固定 2.22.2 |
> | P2-5 | 🟩 消除 | 三载体（query/JSON/form）统一为单字段 `jwe` |
> | P2-7、P2-8、P2-9、P2-10 | 🟩 消除 | 密钥库缓存已解析密钥 + 每次新建 Cipher；死代码/伪签名栈/ComponentScan 全删 |
> | P3-1、P3-2、P3-3 | 🟩 消除 | AGENTS.md/README 已按 v2 重写 |
> | P3-6、P3-7 | 🟩 消除 | StrKit 正则缓存 + 确定性保留；`[key]` 括号写法有绑定回归测试 |
> | P3-8 | 🟩 保持 | enforcer/工程卫生仍在 |
> | P2-2 | ⚠️ 仍开放 | CI 是否覆盖新模块（bench 不随发布）待确认，非协议问题 |
> | P2-3 | ⚠️ 仍开放 | 两份 `jwe.js`（web/gateway 示例）仍对称复制，接受（无共享发布物） |
> | P3-4 | 🟩 已修（2026-10-18） | 名单正名 `skip-*`（命中即跳过），旧名 `black-*` 保留为**弃用 alias**（启动 WARN、新旧合并去重、绑定测试钉死） |
> | P3-5 | 🟩 已修（2026-10-18） | 改为 `.github/ISSUE_TEMPLATE/bug_report.md`（front-matter 形式）；`pull_request_template.md` 本就在规范路径 |
>
> 原始记录（v1 时代，保留供追溯）：
>
> 生成于 2026-10-16，来源：全仓扫描（codegraph 索引 + 逐文件阅读）。**本文件记录问题与建议修法，不代表已修。**
> 
> 状态图例：🟥 未修 · 🟨 待决策（需要拍板 / 涉及行为•协议变更）· 🟩 已修
>
> 机制级（密码学 / 协议设计）问题单独放在 `security-review.md`，编号 `S1…`，本文用 `S-n` 交叉引用。
>
> 修完请把状态改成 🟩 并补日期，**不要删条目**。
>
> ⚠️ **验证环境（2026-10-16 更新）**：本机具备构建环境——`java`/`javac` 11.0.28，Maven 3.8.9 在 **`/usr/local/maven/3.8.9/bin/mvn`**（未加入 PATH，需显式指定）。`mvn clean install`（默认 all-modules profile，含 examples）**已跑通：BUILD SUCCESS，73 个测试全绿**（core 43 / reactive 1 / web 17 / gateway 10 / web-example 2）；示例亦已**真实起服务跑通端到端**（web-example:8081、gateway:8080）。
>
> ⚠️ **排障提示**：surefire 默认 `trimStackTrace=true`，会把栈帧裁剪到只剩测试方法一行（例如只显示"at Test.method:38"），看不到真正抛异常的框架帧。定位失败原因时请加 `-DtrimStackTrace=false`——本轮的 NPE 就是靠它才定位到 `ConcurrentHashMap.put(key, null)`。
>
> 🧪 **第二批修复（2026-10-16）**：P0-1、P0-5、P1-1（Redis 侧）、P1-5、P1-7、P2-4、P2-6 —— **已用 `mvn` 验证通过**（其中 P0-1 的 gateway 回归用例当时是坏的，见 P0-1 条目）。
>
> ✅ **第三批修复（2026-10-16）**：P0-2、P0-6、P0-7、P1-10 已修复并各自带**先红后绿**的回归用例；`encryptor-core` 新增 `CryptoMechanismAuditTest`（5 条机制行为断言，见 `security-review.md`）。全量 `mvn clean install` 绿。

## P0 · 真 bug（静默产生错误行为）

### P0-1 uri 级 `crypto-config` 永远取不到 🟩（2026-10-16 已修）

- **位置**：`encryptor-starters/encryptor-web-starter/src/main/java/io/github/cuukenn/encryptor/web/filter/EncryptorWebFilter.java:49-50`；`encryptor-starters/encryptor-gateway-starter/src/main/java/io/github/cuukenn/encryptor/reactive/gateway/filter/rewrite/EncryptorGatewayFilter.java:48-49`
- **现象**：`StrKit.getBestMatchStr(uri, keys)` 取出命中的正则 key 后，却用 `config.getCryptoConfig().get(uri)` 取值。map 的 key 是**正则**、`uri` 是真实路径，二者几乎永不相等 → 取到 `null`，静默退回全局默认配置。两处同源复制。
- **影响**：`CryptoConfig` 里"按 uri 配不同密钥"的功能**写了不生效**，无任何报错。
- **修法**：`get(bestMatchStr)`（两处各一词）。
- **验证**：加回归用例——`crypto-config` 的 key 配成正则（如 `.*/pay/.*`），请求该 uri，断言取到该 `CryptoConfig` 而非默认。servlet 侧可用单测直接覆盖 `EncryptorWebFilter`。
- **顺带**：同文件 `isBlankUri` / `isBlankMethod` 命名与语义相反（命中名单时才 `return`），建议改名 `skipUri` / `skipMethod`。
- **已修（2026-10-16）**：web 与 gateway 两处都改成 `get(bestMatchStr)`。
  - 回归用例：`encryptor-web-starter/src/test/java/.../web/filter/EncryptorWebFilterTest.java`、`encryptor-gateway-starter/src/test/java/.../reactive/gateway/filter/rewrite/EncryptorGatewayFilterTest.java`。用例配正则 key `^/test/hello.*` + 一个 `CryptoConfig`，请求 `/test/hello`，断言工厂收到的就是那个 `CryptoConfig` —— **修前收到的是 `null`（这就是红灯）**。
  - ✅ **已验证（2026-10-16，`mvn`）**：servlet 侧用例直接绿；gateway 侧用例**最初是坏的**——它让工厂 `return null`，而 `GatewayKit.setEncryptorFacade` 往 `MockServerWebExchange` 的 **`ConcurrentHashMap`** 里 `put(key, null)` → NPE（`HashMap` 才容忍 null，所以 servlet 同构用例侥幸绿）。已改为返回 `new EncryptorFacade(null, null, null, null)`（该 facade 不会被调用）。
  - 反向验证：把 gateway 的取值临时改回 `get(uri)`，用例报 `expected: <CryptoConfig@…> but was: <null>`，**证明这条用例真的能抓到 P0-1**。
  - 教训：一个"永远返回 null 的 stub"能让回归用例失去意义；`ConcurrentHashMap` 不接受 null value 是这次暴露它的原因。

### P0-2 reactive 侧 AES key 编码与 servlet/前端不一致 → 网关 JS Demo 实际解不开 🟩（2026-10-16 已修，方案 A）

- **位置**：`encryptor-starter-reactive/.../reactive/configuration/EncryptorReactiveAutoConfiguration.java:50`（`obj.getBytes("key")`）对比 `encryptor-starter/.../configuration/EncryptorAutoConfiguration.java:50`（`encoder.decode(obj.getStr("key"))`）
- **证据链**：
  - 两套前端 `front/encryptor/aes.js:23,28` 都是 `CryptoJS.enc.Base64.parse(key)`；`generateBase64Key(128)` = `btoa(16 个字符)` = 24 个 base64 字符 → 解码 **16 字节**（AES-128）。
  - servlet 侧 `Base64.decode` → 16 字节 → 与前端一致 ✅
  - reactive 侧 `"...".getBytes()` → 24 字节（AES-192）→ 与前端**不一致** ❌
  - 交叉证据：`encryptor-examples/gateway-example/gateway/src/test/java/io/github/cuukenn/encryptor/HttpTest.java:56` 用 `IdUtil.fastSimpleUUID()`（32 字符）当 key，并与同源 facade 往返 → 自洽所以"能过"。即**同一个网关：Java 测试通过、JS 客户端必然失败**。
- **修法（二选一）**：
  - (A) reactive 改为 `encoder.decode(obj.getStr("key"))`，与 servlet + 两套前端对齐（HttpTest 因自洽仍绿）。**代价：对已上线、客户端传"原始字符串当 key"的网关是破坏性变更**，须写进 release note。
  - (B) 实现不动，改前端（`aes.js` 改用 `CryptoJS.enc.Utf8.parse(key)`）+ 文档写明"网关的 key 是原文字节"。
- **已修（2026-10-16，选 A）**：`EncryptorReactiveAutoConfiguration` 改成 `encoder.decode(obj.getStr("key"))`，与 servlet 侧逐字对齐（iv 两侧本来就是 `getBytes(UTF_8)`，未动）。
  - ✅ **先红后绿**：`encryptor-starter-reactive/src/test/java/.../EncryptorReactiveAutoConfigurationTest.java` —— 用真实 RSA 生成密钥对、按前端契约（`key` = 16 字节的 Base64 文本）造报文，再走**真实的** `encryptorFacadeFactory`。
    - 修前：`cn.hutool.crypto.CryptoException: BadPaddingException: pad block corrupted`（红灯，正是"网关解不开前端报文"）。
    - 修后：解密回 `hello` ✅。
  - 该模块此前**没有任何测试与测试依赖**，已补 `junit-jupiter-engine`（test scope，不影响使用方）。
- **仍未做**：真实端到端（起 `gateway-example` + 浏览器/Node 跑 `front/index.js` 三种请求）。单测已锁住 key 派生契约，端到端仍建议补（见 P2-1）。

### P0-3 `web-example/pom.xml` 复制残留 🟩（2026-10-16 已修）

- **位置**：`encryptor-examples/web-example/pom.xml:25-27`（`<build><finalName>gateway</finalName></build>`）
- **影响**：web 示例打出来叫 `gateway.jar`，与网关示例同名。
- **已修**：删除该 `<build>` 块（`finalName` 回落到 `${project.artifactId}-${project.version}` = `web-example-1.0.0-SNAPSHOT.jar`）。⚠️ 未经 `mvn` 验证（本机无 JDK/Maven）。

### P0-4 防重放校验在 starter 里默认关闭，且两个 checker 从未被注册 🟨

- **位置**：`EncryptorAutoConfiguration.java:44`、`EncryptorReactiveAutoConfiguration.java:44` 只注入 `List<CheckerStrategy>`；全仓**没有任何 `@Bean` 注册** `InMemoryNonceChecker` / `InRedisNonceChecker`（只有示例 `WebApplication.java:18`、`GatewayApplication.java:18` 手动注册）。
- **影响**：不写 bean 的业务方 → **无时间窗校验、无重放防护**，启动日志只有一个空列表、无告警。结合 `S1`/`S5`，防重放是这套机制唯一实际的防伪手段。
- **修法**：starter 内提供默认 `InMemoryNonceChecker`，用 `@ConditionalOnMissingBean` + `@ConditionalOnProperty(..., name="enable-checker", matchIfMissing=...)` 控制；关闭时 `logger.warn`。
- **风险**：行为变更，需先定默认值（建议 `matchIfMissing=true`，与 `enable` 一致）。

### P0-5 时窗校验只挡"过去"，不挡"未来" 🟩（2026-10-16 已修）

- **位置**：`encryptor-core/.../core/checker/InMemoryNonceChecker.java:30`、`InRedisNonceChecker.java:29`
- **现象**：`System.currentTimeMillis() - ts >= window` 才拒绝；`ts` 在未来时差值为负 → 永远通过。
- **修法**：`Math.abs(System.currentTimeMillis() - ts) > windowMs`。
- **顺带**：`offsetDuration.get(ChronoUnit.SECONDS)` 会把亚秒截断（`Duration.ofMillis(500)` → 0 → 校验直接失效），建议改 `toMillis()`。
- **已修（2026-10-16）**：两个 checker 都改为 `Math.abs(System.currentTimeMillis() - ts) >= offsetDuration.toMillis()`；并补 `timestamp == null` → 抛 `EncryptorException("request timestamp is missing")`（原来直接 NPE → 500）。
  - **校验顺序也变了**：现在"先校时间、再查重放"，过期垃圾请求不再占用 nonce 缓存（原来反过来，等于放大 S5 的缓存驱逐效应）。
  - 测试：`encryptor-core/src/test/java/io/github/cuukenn/encryptor/core/checker/InMemoryNonceCheckerTest.java`（未来时间戳 / 过期 / 1.5s 窗口下 1.1s 前不被截断 / 缺 timestamp）、`InRedisNonceCheckerTest.java`（同 nonce 第二次被拒、时间不合法不写 Redis）。
  - ⚠️ 未经 `mvn` 验证。

### P0-6 网关侧 `x-gateway-encryptor-enable` 与 `x-gateway-encryptor-request-enable` 是同一个字符串 → `black-req-content-type` 静默失效 🟩（2026-10-16 已修）

- **位置**：`encryptor-starters/encryptor-gateway-starter/.../reactive/gateway/constant/GatewayConstant.java:8-9`——两个常量**值完全相同**（都是 `"x-gateway-encryptor-enable"`）；消费方 `reactive/gateway/kit/GatewayKit.java:18`；写入方 `reactive/gateway/filter/rewrite/EncryptorGatewayFilter.java:41,45`。
- **现象**：`isReqEncryptorEnable` = `getAttr(ENABLE) != null && getAttr(REQUEST_ENABLE) != null`，而两个 key 是同一个 map key → 等价于 `attr != null`；该 attribute 又在 `EncryptorGatewayFilter:41` 被**无条件置为 `true`**。于是第 44-46 行"命中 `black-req-content-type` 就不置 request 标志"这一分支**没有任何效果**。
- **影响**：网关侧 `black-req-content-type`（例如给 `multipart/form-data`、`text/plain`、`application/octet-stream` 放行）**配了不生效**——这些请求仍会被 `EncryptorRequestFilter` / `EncryptorRequestParameterFilter` 拦下来走解密，最终落到 `DefaultMessageConverter`（按 JSON 读 String）→ `JSONException` / 解密异常 → 500。**web 侧无此问题**（`WebContext` 里是两个独立的 boolean 字段）。
- **已修（2026-10-16）**：`GATEWAY_ENCRYPTOR_REQUEST_ENABLE` 改为独立值 `"x-gateway-encryptor-req-enable"`（**只改这一个常量值，别的都不用动**）。
- ✅ **先红后绿**：`EncryptorGatewayFilterTest#test_black_req_content_type_disables_request_decrypt` —— 配 `black-req-content-type: ["multipart/form-data"]` + `Content-Type: multipart/form-data` 的 exchange，断言 `isReqEncryptorEnable` 为 false、`isResEncryptorEnable` 仍为 true。修前 `expected: <false> but was: <true>`。
- 🛠️ **更正（2026-10-16，本轮实测推翻了本条的静态预测）**：原文说"常量拆开后必须同时改 `EncryptorSkipFilter`，否则 `x-skip-encryptor` 会只跳响应"。**这是错的**：`isReqEncryptorEnable` 是 `ENABLE && REQUEST_ENABLE` 的**与**，`EncryptorSkipFilter` 只 `remove(ENABLE)` 就已经让两个方向都失效（实测拆开后 `test_skip_header_disables_both_directions` 依然绿）。因此 `EncryptorSkipFilter` **不需要改**。
  - 但**保留**该用例作为绊线：若将来有人把 `isReqEncryptorEnable` 改成 `||`，只 remove 一个 attribute 就会漏掉请求方向，届时这条用例会红。

### P0-7 `EncryptorKit.decrypt` 提前拆箱 `Long timestamp` → 缺 timestamp 直接 NPE（500），checker 的 null 守卫不可达 🟩（2026-10-16 已修）

- **位置**：`encryptor-core/.../kit/EncryptorKit.java:37`（`final long timestamp = data.getTimestamp();`），而 `EncryptorDataWrapper.timestamp` 是 `Long`。
- **现象**：第 37 行在**任何 checker 之前**执行。报文缺 `timestamp`（或显式 `null`）→ 自动拆箱 NPE，**永远走不到** P0-5 刚在 `InMemoryNonceChecker` / `InRedisNonceChecker` 里加的 `"request timestamp is missing"` 分支——那两个守卫在真实调用链（`EncryptorFacade.decrypt`）里是死代码。
- **影响**：畸形报文得到的是**未分类 500**（消息里带 NPE 类名），而不是 4xx / `EncryptorException`；攻击者可用它区分错误类型（S11、S15）。
- **已修（2026-10-16）**：`EncryptorKit.decrypt` 入口先做字段存在性校验（`nonce`/`timestamp`/`signature`/`data` 任一为 null → `EncryptorException`），再跑 checker、验签；`EncryptorFacade.decrypt` 入口校验 `data`/`key` 非空（否则会变成 hutool 内部的 `CryptoException(NPE)`）。
- ✅ **先红后绿**（`EncryptorKitTest` + `EncryptorFacadeTest`）：

  | 用例 | 修前 | 修后 |
  | --- | --- | --- |
  | `EncryptorKitTest#test_missing_timestamp_raises_encryptor_exception` | **`NullPointerException`**（P0-7 本体） | `EncryptorException` |
  | `EncryptorKitTest#test_missing_signature_raises_encryptor_exception` | `CryptoException: IllegalArgumentException: Null input buffer`（新发现） | `EncryptorException` |
  | `EncryptorFacadeTest#test_missing_key_raises_encryptor_exception` | `CryptoException: NullPointerException`（新发现） | `EncryptorException` |
  | `EncryptorKitTest#test_missing_nonce/data_...` | 已抛 `EncryptorException`（巧合，靠拼接 "null" 使验签失败） | 不变（作为回归锁） |

- **未做**：异常→HTTP 状态码的映射（现在仍会冒泡成 500）。属 P1-12（错误面统一）。

## P1 · 正确性 / 并发 / 安全

### P1-1 两个 checker 都是 check-then-act，非原子 🟩（2026-10-16 已修）

- `InMemoryNonceChecker.java:27-33`：`containsKey` 与 `put` 之间可并发穿透 → 同一 nonce 可被两线程同时通过。
- `InRedisNonceChecker.java:26-32`：`get` 与 `set` 非原子；应改 `setIfAbsent(nonce, true, ttl)`。
- 另需确认 Hutool `newLRUCache` 并发安全性（该 checker 是有状态对象，会被多线程共享）。
- **已修（Redis 侧，2026-10-16）**：`InRedisNonceChecker` 改为 `Boolean firstSet = opsForValue().setIfAbsent(nonce, true, offsetDuration)`，只有 `!Boolean.TRUE.equals(firstSet)` 才判重放。测试见 `InRedisNonceCheckerTest`。
- **已修（InMemory 侧，2026-10-16）**：不再用 Hutool 的 `CacheUtil.newLRUCache`（非线程安全），改为自实现 `ConcurrentHashMap<String, Entry>` 存储——用 `compute` 把"判断 + 写入"合成**一次原子操作**，并发下同一个 nonce 只会有一个线程拿到自己写入的 `Entry`，其余线程拿到的都是已存在的 `Entry`（即判重放）。过期项按需清理，并保留容量上限（先清过期、仍超限则按迭代顺序丢弃）。
  - **没有引入任何新依赖**（原本设想的 Caffeine 方案作废），符合 core "不加新依赖"的约定。
  - 测试：`InMemoryNonceCheckerTest.test_concurrent_same_nonce_only_one_passes`（16 线程抢同一 nonce，必须恰好 1 个通过）、`test_replay_within_capacity_rejected`、`test_capacity_overflow_does_not_break_check`、`test_missing_nonce_rejected`。
  - ⚠️ 未经 `mvn` 验证。

### P1-2 熵源不是密码学安全 🟥（详见 S10）

- 前端 `front/encryptor/random.js:13` 用 `Math.random()` 生成 AES key / IV / nonce；服务端 `EncryptorKit.java:19` 用 `IdUtil.fastSimpleUUID()`。
- 建议：前端 `crypto.getRandomValues` / `randomBytes`，服务端 `SecureRandom`。

### P1-3 签名摘要硬编码 MD5 🟨（详见 S2）

- `EncryptorAutoConfiguration.java:55`、`EncryptorReactiveAutoConfiguration.java:55`：`new DigestWithEncryptSigner(new HtlDigester(new MD5()), ...)`，不可配置。

### P1-4 示例 RSA 1024 位 + PKCS1 v1.5 🟨（详见 S8）

- `front/encryptor/rsa.js:11`（`RSAES-PKCS1-V1_5`）+ 示例公钥 1024 位 → 单次最多 117 字节；`options` JSON 已接近上限，key/iv 一变长前端直接抛错。

### P1-5 `String::getBytes()` 使用平台默认字符集 🟩（2026-10-16 已修）

- `EncryptorAutoConfiguration.java:50`、`EncryptorReactiveAutoConfiguration.java:50`（iv，以及 reactive 的 key）。
- ASCII 内容下 GBK/UTF-8 恰好一致所以现在能用，换环境/换内容即变。建议显式 `StandardCharsets.UTF_8`。
- **已修（2026-10-16）**：协议路径上所有 `getBytes()` / `new String(byte[])` 都显式指定 `StandardCharsets.UTF_8`：`core/kit/EncryptorKit.java`（签名输入 ×2）、`core/facade/EncryptorFacade.java`（`new String(params, UTF_8)` ×4）、两个自动装配类（iv、reactive 的 key）、gateway `EncryptorRequestParameterFilter.java:57`。
- **⚠️ 特意说明：这一条没有测试。** 本机 JVM 默认字符集就是 UTF-8，改动前后行为完全一致，**构造不出红灯**（要验证只能在 `-Dfile.encoding=GBK` 的 JVM 里跑）。这是本轮唯一"无测试支撑"的改动，靠代码评审保证。
- **刻意没动**：`core/digester/HtlDigester`（输出是 hex，纯 ASCII）；各处 `Charset.forName(...)`（本来就显式）。
- 行为等价性说明：reactive 的 `obj.getBytes("key")` → `obj.getStr("key").getBytes(UTF_8)`，对 Base64/ASCII 字符串**字节完全相同**，因此**没有**顺手改掉 P0-2 的不对称。

### P1-6 客户端可选 mode/padding/key 长度，服务端无白名单 🟥（详见 S3）

- `new AES(obj.getStr("mode"), obj.getStr("padding"), ...)`：`mode`/`padding` 直接来自客户端 JSON。

### P1-7 报文解析健壮性 🟩（2026-10-16 已修）

- `web/converter/FormMessageConverter.java:56-57`：`x.indexOf("=")` 为 -1 时 `substring(0,-1)` 抛 `StringIndexOutOfBoundsException`（无值参数 → 500）。
- `web/filter/EncryptorRequestParameterFilter`：`Collectors.toMap` 无合并函数，重复 key 抛 `IllegalStateException`。（gateway 版用 `toSingleValueMap`，无此问题。）
- **已修（2026-10-16）**：解析逻辑抽成包内静态方法 `FormMessageConverter.parseForm(String)` 与 `EncryptorRequestParameterFilter.parseFormData(String)`：`index < 0` 时取值 `""`、过滤空段落、`toMap` 带合并函数（保留第一个值）。抽方法是为了让它**可以直接单测**。
  - 测试：`FormMessageConverterTest`（`nonce=1&broken`、`data=1&data=2`）、`EncryptorRequestParameterFilterTest`（`a=1&broken`、`a=1&a=2`）。
  - ⚠️ 未经 `mvn` 验证。
- **主动放弃的一项**：原条目里 `x.getValue()[0]` 的"空数组"防护（`EncryptorRequestParameterFilter:55`）**没改** —— Servlet 容器不会产生长度为 0 的参数值数组（`?a` 得到的是 `[""]`），是不可达路径，改了只会增加未验证代码。判定为非缺陷。

### P1-8 `WebContext` 的 ThreadLocal 在请求之间不重置 🟩（2026-10-16 已修）

- **位置**：`encryptor-web-starter/.../web/kit/WebContext.java`（`ThreadUtil.createThreadLocal(WebContext::new)`，**没有 `remove()` / `clear()`**）；`web/filter/EncryptorWebFilter.doFilterInternal` 只 `setEncryptor(true)`、命中条件时才 `setReqEncryptor(true)`，**从不置回 false**，`setResEncryptor(false)` 也从未被调用过。
- **现象**：Servlet 线程池复用线程时，上一个请求写入 ThreadLocal 的 `encryptorFacade` / `config` / 三个标志位会**残留到下一个请求**；若过滤器链中途抛异常提前中断，下一个请求可能直接拿到上一个请求的 `EncryptorFacade`（也就是别人的密钥配置）。
- **影响**：按 uri 配不同密钥 / 多租户场景下理论上会串号解密。当前代码每个请求都会覆盖 `config`，所以不是必然触发，但"没有清理"意味着没有任何保证。
- **修法**：`doFilterInternal` 包一层 `try { … } finally { WebContext.clear(); }`（或至少在 finally 里复位全部标志位）；给 `WebContext` 加 `remove()`。
- **已修（2026-10-16）**：`WebContext` 新增 `public static void clear()`（内部 `CONTEXT.remove()`）；`EncryptorWebFilter.doFilterInternal` 整体包进 `try { … } finally { WebContext.clear(); }`——**黑名单 uri / method 的提前 return 路径也走 finally**，异常路径同样清理。
  - 回归用例：`EncryptorWebFilterTest.test_context_cleared_after_request`（正常路径结束后 `isEncryptor()` / `isReqEncryptor()` 为 false，`encryptorFacade` / `config` 为 null）与 `test_context_cleared_when_chain_throws`（链中抛异常也要清）。
  - 顺序说明：清理由 order `-12` 的 `EncryptorWebFilter` 统一负责；`EncryptorRequestBodyFilter`(-10)、`EncryptorResponseFilter`(-3) 都在链**内部**执行，清理发生在响应写出之后，不影响它们。
  - ⚠️ 未经 `mvn` 验证。

### P1-9 `black-res-content-type` 在 web 与 gateway 两侧都于"响应产生之前"求值 → 永远不生效 🟩（2026-10-16 第三批扫描发现 → 当批已修，经 `mvn` 验证）

- **web**：`encryptor-web-starter/.../web/filter/EncryptorResponseFilter.java:31` 在 `filterChain.doFilter`（第 36 行）**之前**调用 `WebContext.isResEncryptorEnable(response)`；此刻响应 Content-Type 还没被 handler 设置（几乎必为 `null`）→ `anyMatch` 恒 false → 黑名单完全不起作用。（对照：第 37 行选 `MessageWriter` 时用的才是**链后**的 content type。）
- **gateway**：`GatewayKit.isResEncryptorEnable`（`gateway/kit/GatewayKit.java:21-25`）在 `EncryptorResponseFilter.filter`（order = `WRITE_RESPONSE_FILTER_ORDER - 1`，即 `NettyWriteResponseFilter` 之前）的**前置阶段**求值，此时下游响应头还没写回 `exchange.getResponse()` → 同样拿不到 Content-Type。
- **影响**：`black-res-content-type` 与 P0-6 对称——"写了永远不生效"的死配置（例如想放行 `text/event-stream`、`application/octet-stream` 的下载响应，实际仍会被包装/加密）。
- **修法**：把该判断挪到"真正决定要不要改写响应体"的位置：web 侧用链后的 `response.getContentType()` 决定是否包装（需把 `isReqEncryptor()` 与 content-type 判断拆开）；gateway 侧把判断放进 `ModifyResponseBodyGatewayFilterFactory` 的 `RewriteFunction` 内（那里已是链后）或改到 `NettyWriteResponseFilter` 之后。
- **验证**：web 侧单测——先设 `response.setContentType("application/octet-stream")` 再走过滤器，断言响应体**未被**加密（用 `MockHttpServletResponse`）。gateway 侧需要集成测试。
- **已修（2026-10-16）**：
  - **web**：`EncryptorResponseFilter` 链前只判 `WebContext.current().isReqEncryptor()`（命中就包 `ContentCachingResponseWrapper`），把 `WebContext.isResEncryptorEnable(response)` 挪到 `filterChain.doFilter` **之后**判定；命中黑名单时 `copyBodyToResponse()` 原样放行（**不 copy 会得到空响应**）。`WebContext.isResEncryptorEnable` 的方法体**没改**——它本来就是"链后语义"，之前只是被调早了。
  - **gateway**：三个 `MessageWriter`（`Default`/`Json`/`FormMessageConverter`）的 `write()` 内部（`RewriteFunction.apply(exchange, input)` 时刻，下游响应头已就位）再判一次 `GatewayKit.isResEncryptorEnable(exchange)`，命中黑名单就直接返回未加密字节；`EncryptorResponseFilter` 入口处的调用等价于 `ENABLE != null`（那一刻 contentType 必为 null），保持不动并补了 Javadoc 说明"只能在组装响应体时调用"。
  - ✅ **先红后绿**：web `EncryptorResponseFilterTest#test_blacklisted_response_content_type_is_not_encrypted`（修前：黑名单命中的响应**依旧被加密**）；gateway `MessageWriterTest#test_blacklisted_response_content_type_is_not_encrypted`（修前 facade 被调用、且 `ClassCastException: EncryptorDataWrapper cannot be cast to [B`）。配对用例 `test_encryptable_response_content_type_is_still_encrypted` 锁住"可加密路径不受影响"。
  - **附带收益/行为变更**：网关响应体不再交给 SCG 的 Jackson 去序列化 `EncryptorDataWrapper`（writer 直接产出 JSON 字节），业务 Content-Type 非 JSON 时也能正常写出。

### P1-10 `FormMessageConverter.canRead` 用 `equals` 判表单类型 → 带 `;charset=UTF-8` 的表单请求识别失败 🟩（2026-10-16 已修）

- **位置**：web `web/converter/FormMessageConverter.java:29`、gateway `reactive/gateway/converter/FormMessageConverter.java:29`，都是 `MediaType.APPLICATION_FORM_URLENCODED.equals(mediaType)`。
- **实证**（本机用 spring-web 5.3.20 跑了 3 行验证代码）：`MediaType.APPLICATION_FORM_URLENCODED.equals(MediaType.valueOf("application/x-www-form-urlencoded;charset=UTF-8"))` → **`false`**（`MimeType.equals` 会把 parameters 一起比较），而 `isCompatibleWith(...)` → `true`。带 `;boundary=` 之类参数同理为 false。
- **影响**：
  - **gateway 侧是硬故障**：`application/x-www-form-urlencoded;charset=UTF-8` 的请求不会被识别为表单 → 落到 `DefaultMessageConverter`（JSON / inClass=String）→ `JSONUtil.toBean` 抛 `JSONException` → 500。而带 charset 的表单请求是常态（axios 传 `URLSearchParams`、Spring `RestTemplate` 的 `FormHttpMessageConverter`、很多客户端默认都会带）。示例前端（`gateway/front/index.js:62-66`）手写了不带 charset 的 Content-Type，所以**示例掩盖了这个 bug**。
  - web 侧影响较轻但真实：form body 已被容器解析进 `getParameterMap()`，参数过滤器仍能解密；但 body 过滤器会走 JSON 分支并把 body 置空 → 形如示例 `TestController.helloForm`（`@RequestBody MultiValueMap`）的 handler 只能拿到**空表**。
- **修法**：改用 `MediaType.APPLICATION_FORM_URLENCODED.isCompatibleWith(mediaType)`（或直接复用参数过滤器里的 `ContentType.isFormUrlEncode(contentType)`，两侧保持一致）。
- **已修（2026-10-16）**：两侧 `canRead` 都改为 `MediaType.APPLICATION_FORM_URLENCODED.isCompatibleWith(mediaType)`（`canWrite` 复用 `canRead`，一并生效）。`isCompatibleWith(null)` 实测为 false，所以空 content-type 的行为与原来一致，无副作用。
- ✅ **先红后绿**：web `FormMessageConverterTest#test_form_content_type_with_charset_is_readable`、gateway `converter/FormMessageConverterTest#test_form_content_type_with_charset_is_readable` —— 修前 `expected: <true> but was: <false>`，修后绿。

### P1-11 参数过滤器的 `HttpServletRequestWrapper` 只覆写了一半 → 同一请求两个视图（明文/密文） 🟩（2026-10-16 第三批扫描发现 → 当批已修，经 `mvn` 验证）

- **位置**：`encryptor-web-starter/.../web/filter/EncryptorRequestParameterFilter.java:39-51`，只覆写了 `getParameterNames()` / `getParameterValues()`。
- **现象**：`HttpServletRequestWrapper.getParameter(name)` 与 `getParameterMap()` 仍**委托给原始请求** → 返回**密文**。于是同一个请求里 `request.getParameterValues("data")` 是明文、`request.getParameter("data")` / `getParameterMap()` 是密文，且没有任何提示。Spring MVC 的 `@RequestParam` 走 `getParameterValues`（所以示例能跑），但任何直接调 `getParameter()` / `getParameterMap()` 的代码（自写拦截器、审计日志、`ServletRequestUtils`、部分安全框架）拿到的都是密文。
- **修法**：wrapper 里一并覆写 `getParameter(String)` 与 `getParameterMap()`（都从 `decryptParameters` 派生），保证三个视图一致。
- **验证**：单测断言 wrapper 上 `getParameter("data")`、`getParameterValues("data")[0]`、`getParameterMap().get("data")[0]` 三者相同且为明文。
- **已修（2026-10-16）**：匿名 wrapper 除 `getParameterNames`/`getParameterValues` 外，新增覆写 `getParameter(String)`（缺失或空数组返回 `null`）与 `getParameterMap()`（返回 `decryptParameters`），三个视图保证一致。
- ✅ **先红后绿**：`EncryptorRequestParameterFilterTest#test_wrapped_request_exposes_plaintext_from_all_parameter_accessors` —— 修前 `getParameter("field")` 得到 `null`（`expected: <plain> but was: <null>`）。

### P1-12 错误面：所有失败路径都逃逸为"未分类 RuntimeException"，且互相可区分 🟩（2026-10-16 第三批扫描发现 → 当批已修，经 `mvn` 验证；对应 S11 / S15）

- **实证**（本机 hutool 5.8.26 + spring-core/web 5.3.20 实跑）：
  - `DigestWithEncryptSigner.verify` 遇到**被篡改的 signature** 不是"返回 false"，而是 `encryptorStrategy.decrypt(signature)` 直接抛 `cn.hutool.crypto.CryptoException: IllegalBlockSizeException: Input length must be multiple of 16 when decrypting with padded cipher`（长度恰为 16 的倍数时改为 `BadPaddingException`）。
  - `Base64.decode("!!!not-base64!!!")` **不报错**，返回垃圾字节（→ 后续 AES 解密炸）；`HexUtil.decodeHex("zz")` 抛 `UtilException`；`JSONUtil.toBean("not json", …)` 抛 `JSONException`；缺 `timestamp` → NPE（P0-7）。
- **影响**：① `"sig check error"` 这条路径几乎只在"密文能被正确解密成另一个 digest"时才出现，**篡改报文不会产生"验签失败"这种明确信号**，审计维度丢失；② 失败模式可区分（长度错 / padding 错 / JSON 错 / NPE），对攻击者是额外信息（配合 S8 的 padding oracle）；③ 全部以 500 返回，对客户端是噪音。
- **修法**：在 `EncryptorFacade.decrypt` 外层统一包一层，把 `CryptoException` / `JSONException` / `UtilException` / `NullPointerException` 收敛成 `EncryptorException("request decrypt failed", cause)`（对外只给 traceId），失败计数打指标（S11/S15）。
- **验证**：`EncryptorFacadeTest`：篡改 `signature` / `data` 后断言抛的是 `EncryptorException`（修前是 `CryptoException`）。
- **已修（2026-10-16）**：报文解不开不再逃逸成未分类异常 / 500——
  - `EncryptorFacade.encrypt/decrypt` 把 `RuntimeException`（含 hutool `CryptoException`）统一包成 `EncryptorException(..., cause)`；本身已是 `EncryptorException` 的原样上抛，不重复包装。
  - **web**：`EncryptorRequestParameterFilter` / `EncryptorRequestBodyFilter` 捕获 `EncryptorException` → 回 `encryptor.config.web.failure-status`（**新增配置项，默认 400**，见 `WebEncryptorConfig#failureStatus`）且**不进入业务链**；body 侧的 JSON 解析失败也包成 `EncryptorException`。
  - **gateway**：新增 `GatewayKit.failure(exchange)`——把状态码写成 `encryptor.config.reactive.gateway.failure-status`（同上，默认 400）并结束响应；`EncryptorRequestFilter` 用 `.onErrorResume(EncryptorException.class, …)` 收敛反应式链上的解密错误；参数过滤器同 web。
  - **顺带修掉一个相关缺陷**：**明文请求（没有协商 key）走到响应加密时会因 `key=null` 而 500**。现在两侧都改成"没有 `x-key` 就不加密、原样放行"（web `EncryptorResponseFilter`；gateway 三个 writer）。
  - 响应加密**真的失败**时仍然是 500（属于服务端问题），但会 `logger.error` 记下 cause，且**不会把明文当密文发出去**（web 侧 `resetBuffer()` + `setStatus(500)`）。
- ✅ **先红后绿**：core `EncryptorFacadeTest` 4 条（修前统一报 `Unexpected exception type thrown ==> expected: <EncryptorException> but was: <cn.hutool.crypto.CryptoException>`，cause 分别是 `NullPointerException` / `BadPaddingException` / `IllegalBlockSizeException`）；web `EncryptorRequestParameterFilterTest#test_undecryptable_payload_responds_with_failure_status_and_skips_chain`（修前 `CryptoException` 直接冒泡）、`EncryptorResponseFilterTest#test_response_without_negotiated_key_is_passed_through`（修前 key=null 时仍去调 `facade.encrypt`）；gateway `EncryptorRequestParameterFilterTest`（修前状态码 500）。
- **仍未做**：失败计数 / 指标 / 统一 traceId（S11、S15 的"可观测"部分）；`DigestWithEncryptSigner` 的验签仍然是"解密后比较"，只是它抛出的异常现在被包住了。

### P1-13 无报文大小上限 + 网关在 Netty 事件循环上做同步密码学运算 🟩（2026-10-16 第三批扫描发现 → 当批已修，经 `mvn` 验证；对应 S17）

- **位置**：web `web/filter/EncryptorRequestBodyFilter.java:44`（`IoUtil.readBytes(request.getInputStream())` 一次性读完，无上限）、web `EncryptorResponseFilter.java:35`（`ContentCachingResponseWrapper` **把整个响应体缓存进堆**）；gateway `ModifyRequestBodyGatewayFilterFactory`（inClass=String 时会先整体转成 String）同样全量缓冲；gateway 的 `RewriteFunction`（`DefaultMessageConverter.read/write`）在**事件循环线程上同步**调用 `EncryptorFacade.decrypt/encrypt`（含 RSA 私钥运算）。
- **影响**：这些路径都在**认证之前**（本机制不提供认证，见 S1）→ 单个大报文就能放大成堆内存压力；每次请求至少 1 次 RSA 私钥运算、响应方向再 1 次（见 P2-7），同步跑在 event loop 上还会阻塞同 reactor 的其它连接。
- **修法**：加报文大小上限（超限直接 4xx）；大响应改流式/分块或至少在文档里声明"只适合中小 JSON 报文"；gateway 侧把加解密挪到 `Schedulers.boundedElastic()`。属设计改进，不适合单测，需压测/集成验证。
- **已修（2026-10-16，拆成两半做的）**：
  - **web 报文上限**：新增 `encryptor.config.web.max-request-size`（`WebEncryptorConfig#maxRequestSize`，**默认 1048576 字节，`<=0` 表示不限**）。`EncryptorRequestBodyFilter` 先看 `getContentLengthLong()`，超限直接 `413 SC_REQUEST_ENTITY_TOO_LARGE` 且不进链；没有 Content-Length（chunked）时用有界读取（最多读 `limit+1` 字节，超限同样 413）；不限时完全走原路径。413 是协议语义固定值，**不**跟随可配的 `failure-status`。
  - **gateway 事件循环**：三个 `MessageReader`/`MessageWriter` 的 RSA/AES 运算包成 `Mono.fromCallable(...).subscribeOn(Schedulers.boundedElastic())`，不再阻塞 Netty event loop；`input == null`、`isResEncryptorEnable`、缺 `x-key` 这些放行分支仍在 event loop 上提前返回（不切线程）。
- ✅ **先红后绿**：web `EncryptorRequestBodyFilterTest`（修前 `expected: <413> but was: <400>` ×2：一条带 Content-Length、一条 chunked）；gateway `MessageConverterOffloadTest`（去掉 `subscribeOn` 时断言失败，实际线程名是 `main`）。
- **仍未做**：**响应**方向仍是全量堆内缓冲（web 的 `ContentCachingResponseWrapper`、gateway 的 `ModifyResponseBody`），所以大响应仍建议只传中小 JSON；`boundedElastic` 的容量调优未做。

## P2 · 工程化 / 测试 / CI

### P2-1 两个 `HttpTest` 是"没有断言的伪测试" 🟩（2026-10-16 已修，已真实端到端跑通）

- `encryptor-examples/gateway-example/gateway/src/test/java/io/github/cuukenn/encryptor/HttpTest.java:36-44,76-80,110-116`（web 侧同构）。
- **现象**：标 `@Test` 但只 `consumeWith(res -> logger.info(...))`，**无任何断言**；且打的是 `127.0.0.1:8080` / `8081` 上**外部已启动**的服务。
- **后果**：服务没起 → 红；**业务错了 → 仍然绿**；CI 里必失败。
- **修法**：改 `@SpringBootTest(webEnvironment = RANDOM_PORT)` + 真断言；或 `@Disabled` / `@Tag("e2e")` + surefire exclude；或改成独立 `main` 脚本。
- **已修（2026-10-16）**：两个 `HttpTest` 都加了真断言（HTTP 200 + 解出的明文含 `Hello`/`小明`），并**真起服务跑通**（web-example 8081、gateway 8080）。跑法：`spring-boot:run` 前缀在本仓**不可用**（POM 未声明 `spring-boot-maven-plugin`），要用全坐标 `org.springframework.boot:spring-boot-maven-plugin:2.4.2:run`；跑被 surefire 排除的用例用 `-Dtest=HttpTest -Dsurefire.excludes= -DfailIfNoTests=false`。
- ⚠️ **网关示例的下游必须是没有引入 encryptor 的应用**（`encryptor-examples/gateway-example/web`）；拿 `web-example` 当下游会 **400** —— 网关转发出去的已经是**明文**参数，下游若自己也带 starter 就会再解一次密（`key=null`；P1-12 之后是 400 而不是 500）。这与 `docs/architecture/encryptor-examples.md:7,25` 的"加密在网关上终结，下游看到的是明文"一致，是架构约束而非 bug。
- **加断言立刻抓到 3 个 HEAD 就存在的真 bug**（此前因为"没有断言"而全部被掩盖）：
  1. `encryptor-examples/gateway-example/gateway/src/main/resources/application.yml` 的 `skip-able:` 是**空值** → `boolean` 绑定失败 → **网关根本起不来**（`Failed to convert String to boolean`）；已改为 `skip-able: false`。
  2. web 的 `HttpTest` 用的是**网关的密钥对**，而它请求的是 8081（web-example），在此之前**一直会 400**；已改为 `web-example/application.yml` 里那对（与 `front/*.js` 一致）。
  3. 两个 `HttpTest` 的 GET 查询串**没有做 URL 编码**（Base64 里的 `+` 被服务端解成空格 → 密文损坏 → 400）；已改成严格 `URLEncoder` 编码后整体 `HttpRequest.get(fullUrl)`（实测 hutool 的 `.form()` 也不转义 `+`），并删掉无用代码。
  - 结论：这两个用例仍然是"需要先起服务"的端到端脚本（继续留在 surefire 排除清单里），但它们现在**真的能判错**。

### P2-2 没有任何 push/PR 触发的 CI 🟩（2026-10-16 已修一半）

- `.github/workflows/publish.yml` 是唯一 workflow，仅 `on: release: released`；且使用已归档的 `samuelmeuli/action-maven-publish@v1`。
- 修法：新增 PR workflow 跑 `mvn -Pmain-module verify`；发布改用官方 `setup-java` + `mvn -Prelease deploy`。
- **已做（2026-10-16）**：新增 `.github/workflows/ci.yml` —— `on: push / pull_request / workflow_dispatch`，temurin 8 + maven 缓存，执行 `mvn -B -Pmain-module clean install`（会真正跑测试；examples 不参与）。
- **仍未做**：`publish.yml` 里那个**已归档**的 `samuelmeuli/action-maven-publish@v1` 没有替换（不想顺手动坏发布流程）；另外本仓库同时推 Gitee，**Gitee 不会读 GitHub Actions**，真要两边都跑测试还得配 Gitee Go 之类的流水线。

### P2-3 两套前端 JS 近乎逐行复制 🟨

- `encryptor-examples/web-example/front/*` 与 `encryptor-examples/gateway-example/gateway/front/*`（`aes.js` / `index.js` / `rsa.js` / `random.js` / `md5withaes.signature.js`）。P0-2 这类漂移正是复制导致的。建议抽 `front-shared/`。

### P2-4 `GroupEncryptor.encrypt/decrypt` 直接 `return null` 🟩（2026-10-16 已实现）

- 未实现的公开 API；调用方拿到 `null` 而不是异常。建议实现，或抛 `UnsupportedOperationException` / 标 `@Deprecated`。
- **已修（2026-10-16）**：按**仓库里早就写好的测试** `encryptor-core/src/test/java/io/github/cuukenn/encryptor/lectotype/EncryptorStrategyTest.java:79-94`（`test_hutool_sc_encryptor_groupEncoder`：groupSize=4，断言加解密往返）实现：
  - `encrypt`：按 `groupSize` 用 `Arrays.copyOfRange` 切片 → 逐片 `delegate.encrypt` → `String.join(groupSplit, ...)`。
  - `decrypt`：`data.split(Pattern.quote(groupSplit))`（**必须 quote**，默认分隔符 `.` 是正则元字符）→ 逐片 `delegate.decrypt` → `ByteArrayOutputStream` 拼接。
  - 空输入返回 `""` / `new byte[0]`；顺带把 `groupSize <= 0` 的校验补进三参数构造器（原来只有两参数构造器校验）。
  - ⚠️ 未经 `mvn` 验证。这个类目前**没有任何生产代码在用**，属于补全公开 API。

### P2-5 两种承载形态（参数 / 请求体）耦合脆弱 🟩（2026-10-18 已锁）

- **v1 前提已不成立**：v2 里**只有门面过滤器** `EncryptorWebFilter` 读请求（`getParameter*` / `getInputStream`），一次性识别载体、解密并把结果装进 `WebContext`；`EncryptorRequestParameterFilter`(-11) 与 `EncryptorRequestBodyFilter`(-10) 只把结果包装成请求视图，**不再各自读请求**——"两个过滤器抢同一个请求体"的耦合随 v2 重写消失（状态表早已记为 🟩）。
- **已做（2026-10-18）**：新增 `encryptor-web-starter/src/test/.../filter/FilterChainOrderTest`（7 例）——不手抄链序，而是向 `WebEncryptorConfiguration` 取**生产注册的 `FilterRegistrationBean`**、按 `getOrder()` 排序组装链，再跑三载体往返 + 响应回加密 + 链尾不残留 ThreadLocal。**验证过它会红**：把 `encryptorReqParamsFilterOrder` 默认值从 `-11` 改成 `-9`，7 例中 2 例失败（`生产注册的链序与文档约定一致` + `顺序默认值保持门面最外响应最内`），改回即绿。
- 同时在 `WebFilterConfig` 类头写明整条链的不变式与每段理由，并修掉 `EncryptorResponseFilterTest` 类头那句与自身代码矛盾的 v1 描述（原写"参数 → body → 响应 → 门面"，还称响应过滤器在门面**外层**）。
- 网关侧不存在该耦合：WebFlux 没有参数 map 解析，query / 表单体都由 `EncryptorGatewayFilter` 从 `ServerWebExchange` 单点读取。

### P2-6 JUnit5 测试其实从未被执行（根 POM 没有 surefire） 🟩（2026-10-16 已修）

- **位置**：根 `pom.xml` 的 `pluginManagement`（原来只有 maven-javadoc / source / gpg / nexus-staging 插件，**没有 maven-surefire-plugin**）。
- **现象**：不显式声明时 Maven 用默认 surefire（2.12.x 一代），它**不支持 JUnit 5 平台**——于是全仓那些 `org.junit.jupiter` 测试**从来没真正跑过**。这也正好解释了：`GroupEncryptor` 明明是 `return null`，`EncryptorStrategyTest` 里针对它的用例却一直"没问题"。
- **已修（2026-10-16）**：`pluginManagement` 里固定 `maven-surefire-plugin:2.22.2`（JUnit5 需要 2.22+），并加 `<exclude>**/HttpTest.java</exclude>`（端到端脚本，见 P2-1）；`encryptor-core/pom.xml` 加 test 作用域 `mockito-core`，`encryptor-web-starter` / `encryptor-gateway-starter` 各加 test 作用域 `spring-boot-starter-test`。
- ⚠️ **这是本批风险最高的一处改动**：它会让原本"假绿"的测试真的跑起来——一旦构建，很可能暴露更多既有问题。未经 `mvn` 验证。

### P2-7 每个请求都重建 facade / RSA / AES，且响应方向会再解析一次 RSA 🟩（2026-10-16 第三批扫描发现 → 当批已修，经 `mvn` 验证）

- **位置**：`web/configuration/WebEncryptorConfiguration.java:82-86`、`reactive/gateway/configuration/GatewayEncryptorConfiguration.java:68-76` 把 `facadeFactory.apply(cryptoConfig)` 交给过滤器，而过滤器**每个请求**调用一次：`EncryptorWebFilter.java:54`、`EncryptorGatewayFilter.java:51`。每次 `apply` 都会 `new RSA(algorithm, privateKey, publicKey)`（Base64 解码 + PKCS8/X509 KeySpec + KeyFactory，RSA 私钥运算前最贵的一步）。
- **再叠加**：`EncryptorFacade.decrypt` 里 `strategyFunction` 被调用 **2 次**（encryptor + signer）→ 2 个 `AES` 对象；`EncryptorFacade.encrypt(data, key)` 又自己 `negotiateEncoder.decrypt(key)` 一次（**第二次 RSA 私钥运算**）+ 2 个 `AES`。
- **量化**：一个加密往返 = **2 次 RSA 私钥运算 + 4 次 `new AES`**（含 `mode`/`padding` 字符串解析、`SecretKeySpec` 构造）。`CryptoConfig.getOrDefaultFill` 每请求还会 new 一个 `CryptoConfig`。
- **修法**：① 按"命中的 key / 哨兵默认值"缓存 facade（或至少缓存 `HtlASymmetricCryptoEncryptor`）——**不要把 `CryptoConfig` 实例当缓存 key**（每请求都是新对象）；② 让 `EncryptorFacade.encrypt` 复用请求解密时已解析的 params（`x-key` attribute 已在，可再存一份 params）；③ 把 `IEncryptorFacadeFactory` 的"调一次建一个、可缓存"语义写进 Javadoc。
- **验证**：注入一个计数用的 factory，断言两次请求只 `new` 一次 RSA；或简单计时对比。
- **已修（2026-10-16）**：
  - `EncryptorWebFilter` / `EncryptorGatewayFilter` 各加了一个 `ConcurrentHashMap<String, EncryptorFacade>` 缓存，键是**命中的正则 key**（没命中用哨兵 `"\u0000default"`），用 `computeIfAbsent` 复用 → 每请求 `new RSA(...)` 降为"每命中 key 一次"。
  - `EncryptorFacade` 新增 `paramsCache`（`key → params JSON`，**有界**：默认 1024 条、到顶整体清空），`decrypt`/`encrypt` 共用 `negotiateParams(key)` → **同一请求内响应方向不再做第二次 RSA 私钥运算**（一个往返从 2 次 RSA 降到 1 次）。
  - ✅ **先红后绿**：`EncryptorFacadeTest#test_response_encrypt_reuses_negotiated_params`（`expected: <1> but was: <2>`）；web `EncryptorWebFilterTest#test_facade_cached_by_matched_config_key` 与 gateway `EncryptorGatewayFilterTest#test_facade_cached_by_matched_config_key`（同为 1 vs 2）。
- ⚠️ **如实记录两点**：① 有界性用例（`test_negotiated_params_cache_is_bounded`）因为实现前无法编译，是先补了最小 API stub 才跑起来的，属**平凡通过**，它没有真正的红→绿证据；② 两个缓存都是"有界近似"（`size() >= cap` 与 `put` 之间是竞态），而且**没有失效入口**——运行期改 `crypto-config` 不会生效（已写进代码注释）。
- **仍未做**：`StrKit.getBestMatchStr` 仍每请求对全部正则 key 跑一遍匹配；`CryptoConfig.getOrDefaultFill` 仍会在每次"未命中缓存"时构造一次。

### P2-8 `GroupEncryptor` 按**明文**分组独立加密（ECB 式），公开 API 却无人使用 🟩（2026-10-16 第三批扫描发现 → 当批已修，经 `mvn` 验证）

- **位置**：`encryptor-core/.../core/encryptor/GroupEncryptor.java:42-45`：按 `groupSize` 把**明文**切片后逐片 `delegate.encrypt`，再用 `groupSplit` 拼接。
- **问题**：同一 `(K, IV)` 下**相同的明文分组产生相同密文分组**（相当于把 CBC 退化成"分组内 ECB"），明文结构会泄漏；正确语义通常是"分组只影响传输/编码，不影响加密粒度"（或至少给每片加位置/序号再加密）。
- **现状**：仓库内没有任何生产代码使用它，文档也没说明；实现是从测试反推的（P2-4）。
- **建议**：要么标 `@Deprecated`/在文档里定性为"实验性"，要么改成"先 `encrypt` 一次再按 `groupSize` 切分**密文/Base64 输出**"——后者才是"传输分片"的常见语义。
- **已修（2026-10-16，采用了后一种）**：`encrypt`/`decrypt` 改为**整段只加解密一次**，分组只作用于**编码后的密文**：`encrypt` = `delegate.encrypt(data)` 之后按 `groupSize` 切分密文字符串、用 `groupSplit` 连接；`decrypt` = 先拼回完整密文、再 `delegate.decrypt` 一次。→ 相同的明文分组不再产生相同的密文分片，**泄漏消失**，往返（含空输入、非整数倍长度、`groupSize=1`）不变。
- ✅ **先红后绿**：`CryptoMechanismAuditTest#test_group_encryptor_does_not_leak_repeated_plaintext_blocks`（修前 `expected: not equal but was: <geYRWZzXT1UX0cgSSDKI2Q==>`）、`EncryptorStrategyTest#test_group_encryptor_encrypts_whole_plaintext_once`（修前 `was: <+8T8AsaDxDCO2sg6I0lAJg==.+8T8AsaDxDCO2sg6I0lAJg==>`——两片密文完全相同）。
- ⚠️ **破坏性语义变更**：`groupSize` 现在数的是**密文字符数**，不再是明文字节数，因此分片结果与旧实现不同。仓库内没有任何生产代码使用它，但外部消费者若按旧语义解析会不兼容。

### P2-9 死代码与无用依赖 🟩（2026-10-16 第三批扫描发现 → 当批已修，经 `mvn` 验证；含一处**自我更正**）

- web `web/filter/EncryptorResponseFilter.java:46-48`：`private EncryptorDataWrapper getEncrypt(byte[], String)` 无人调用。
- web `web/kit/WebContext.java`：`resEncryptor` 字段 + `setResEncryptor()`/`isResEncryptor()` **从未被调用**（响应是否加密实际由 `isReqEncryptor()` 决定，见 `isResEncryptorEnable`）→ 对使用者是误导性 API。
- web `web/constant/GatewayConstant.java`：整个类在 web 模块里**没有任何引用**（纯复制残留），且与网关侧同名类的语义并不相同。
- `encryptor-core/pom.xml:18-21`：`org.bouncycastle:bcpkix-jdk18on`（1.78.1）**源码里没有任何直接引用**（`grep -rn "bouncycastle\|bcpkix\|BouncyCastleProvider"` 零命中）→ 当时被判定为"无用依赖"。🛠️ **该判断后来被证伪，见下方"更正"**。
- web `web/configuration/WebEncryptorConfiguration.java:100-108`：`Builder.filterConfiguration` 的 `patterns` 为空（`addUrlPatterns()` 传空数组），依赖容器"未配置 url-pattern 即匹配全部请求"的行为；建议显式传 `"/*"`。
- **已修（2026-10-16，经 `mvn` 验证）**：
  - 删除 web `web/constant/GatewayConstant.java`（整类零引用）与 web `EncryptorResponseFilter` 里无人调用的 `getEncrypt(...)`。
  - web `WebEncryptorConfiguration.Builder.filterConfiguration`：`patterns` 为空时**显式传 `"/*"`**，不再依赖容器的隐含行为。
  - web `WebContext` 的 `resEncryptor` / `isResEncryptor()` / `setResEncryptor()`：**没删**（`isResEncryptorEnable` 是公开 API，删字段牵动面更大），仍标记为"误导性 API / 无调用者"，留待后续清理。
- 🛠️ **更正（重要）**：`bcpkix-jdk18on` **不是无用依赖**。把它从 `encryptor-core/pom.xml` 删掉后，`EncryptorStrategyTest` 的 4 个国密用例立刻报 `CryptoException: SM4 KeyGenerator not available` / `NoClassDefFound org/bouncycastle`——**hutool 的 SM2/SM4 依赖 BouncyCastle 提供的 JCA provider，源码里没有任何直接引用**，所以"grep 零命中 = 无用依赖"这个推断是错的。已把依赖**加回** `encryptor-core/pom.xml` 并加注释说明用途（版本仍由 `encryptor-dependencies` BOM 管理）。教训：**删一个依赖前要跑全量测试，而不是只看 grep**。

### P2-10 自动装配里做 `@ComponentScan`，转换器又无 `@ConditionalOnMissingBean` 🟩（2026-10-16 第三批扫描发现 → 当批已修，经 `mvn` 验证）

- **位置**：`web/configuration/WebEncryptorConfiguration.java:35`、`reactive/gateway/configuration/GatewayEncryptorConfiguration.java:37`：`@ComponentScan(basePackageClasses = {MessageReader.class})` 把 starter 包里的 `FormMessageConverter`/`JsonMessageConverter` 作为 bean 注入**业务上下文**，且没有 `@ConditionalOnMissingBean`（使用方只能靠同名 bean 覆盖，无法真正去掉）。Boot 官方倾向自动装配用 `@Import`/`@Bean` 而不是扫包。
- **顺带**：`EncryptorRequestFilter.java:44-49` / `EncryptorResponseFilter.java:46-48` 用反射从 `MessageReader`/`MessageWriter` 的接口泛型推 `inClass`/`outClass`（`ResolvableType.getInterfaces()` 顺序不保证，多接口时靠 `isAssignableFrom` 过滤），泛型一变就抛 `EncryptorException("Get ResolvableType Error")`；`orElseGet(DefaultMessageConverter::new)` 还让"未知 content-type"静默回落到 JSON，而不是明确拒绝。
- **已修（2026-10-16）**：两侧自动装配都去掉了 `@ComponentScan`，改为显式 `@Bean @ConditionalOnMissingBean(FormMessageConverter.class)` / `(JsonMessageConverter.class)`；四个转换器也去掉了 `@Component`（容器不再需要扫 starter 包）。→ 使用方现在**可以用自己的同类型 bean 覆盖**，starter 也不会再往业务上下文里塞 bean。
  - 顺带修掉 `GatewayEncryptorConfiguration` 的 logger 误用（AGENTS 已知问题第 5 条），改用本类。
- **仍未做**：反射推 `inClass`/`outClass` 的脆弱做法，以及"未知 content-type 静默回落 JSON"的行为，都保持原样。

## P3 · 文档 / 命名

### P3-1 `AGENTS.md` 说 core"无 Spring"不成立 🟩（2026-10-16 已修）

- 反证：`encryptor-core/pom.xml:22-31` 有 optional 的 `spring-boot-starter-data-redis`、`logback-classic`；`core/checker/InRedisNonceChecker.java:6` 直接 `import org.springframework.data.redis.core.RedisTemplate`。`docs/architecture/encryptor-core.md:11` 本来写对了。

### P3-2 `README.md` 声称的网关 gzip 不存在 🟩（2026-10-16 已修）

- `README.md:17` 曾声称支持"网关 gzip encode/decode"，全仓无 gzip 代码（仅此一行提及）。
- **已修**：删除该特性行（README 特性列表不再包含 gzip）。同时更新了引用它的 `AGENTS.md`、`encryptor-starter-development/SKILL.md`、`docs/architecture/encryptor-gateway-starter.md`。若要真做 gzip，需从零实现（`encode/decode` 两面 + 配置开关）。

### P3-3 `README.md` 依赖坐标与残留注释 🟩（2026-10-16 已修）

- groupId 写成 `io.github.cuukenn.encryptor`（实际 `io.github.cuukenn`）；含 `dynamic-mongodb-database-starter` 的复制残留注释。
- **已修**：三处 `groupId` 全部改为 `io.github.cuukenn`；三个 `mvnrepository` 提示链接补全为 `.../artifact/io.github.cuukenn/<artifactId>`（含被污染的 gateway 那条）；残留注释删除。

### P3-4 `black*` 命名与语义相反，且是正则 🟩（2026-10-18 已修）

- 原问题：`blackUris` / `blackMethods` / `blackReqContentType` / `blackResContentType` 实为"跳过加密名单"；`StrKit.anyMatch` → `ReUtil.isMatch`（**正则**，非通配符）。
- **已修（2026-10-18）**：四个名单改名为 `skip-*`（`skip-uris` / `skip-methods` / `skip-req-content-type` / `skip-res-content-type`），**旧名 `black-*` 保留为弃用 alias**（getter/setter 均标 `@Deprecated`，仍可绑定，绑定时落一条 WARN 指出去哪改名）。
  - 实现要点（servlet `WebEncryptorConfig` 与 reactive `GatewayEncryptorConfig` **成对**）：旧名有**独立的绑定字段**，由 `InitializingBean.afterPropertiesSet()` 在绑定完成后并入 `skip-*` 生效名单（去重、幂等）。
  - ⚠️ **不能新旧共用一个 list**：Spring Boot 对集合属性是"就地绑定（clear + 回填到 getter 返回的那个 list）"，共用一份时后绑定的名字会把先绑定的清掉（首版实现实测：`skip-uris=[/api/open.*]` + `black-uris=[/api/open.*, /other]` 结果只剩 `[/api/open.*]`，丢了 `/other`）。
  - 测试：`WebCryptoConfigBindingTest` 追加 2 例（旧名可绑定到生效名单、新旧共存合并去重）；新增 `GatewaySkipAliasBindingTest` 4 例（旧名 / 新名 / 共存 / 未配置为空，用 `Binder` + `MapConfigurationPropertySource` 直接钉属性名）。
  - 同步改动：6 处 filter 调用点与 3 处测试改用 `getSkip*()`；两处自动装配告警文案（`请配合 black-res-content-type 使用` → `skip-res-content-type`）与 `EncryptorResponseFilter` javadoc；README 配置样例、设计文档 §3.7 表与 §3.2 样例、本文件状态表/本条/「确实仍未修」清单、`.opencode` 技能清单一并更新。

### P3-5 `.github` 模板为单文件形式 🟩（2026-10-18 已修）

- 原为 `.github/issue_template.md`——文件名大小写也不对：GitHub 只认 `.github/ISSUE_TEMPLATE/`（目录）或历史上的少数几个名字，这个文件实际上等于没生效。
- 已改为 `.github/ISSUE_TEMPLATE/bug_report.md` 并加上 front-matter（`name`/`about`），正文原样保留；`pull_request_template.md` 本来就在 GitHub 认的路径上（`.github/pull_request_template.md`），不动。
- 不与 `.gitee/` 的多语言模板（`ISSUE_TEMPLATE.zh-CN.md` / `.en.md`）强求一致：GitHub 侧保持单模板，避免凭空造内容。

### P3-6 `StrKit.getBestMatchStr` 等长正则 key 只留一个，命中结果依赖配置声明顺序 🟩（2026-10-16 第三批扫描发现 → 当批已修，经 `mvn` 验证）

- **位置**：`encryptor-core/.../kit/StrKit.java:35-40`：`TreeSet` 比较器为 `(s1, s2) -> s2.length() - s1.length()`，**长度相同即视为重复** → 后加入的被静默丢弃。
- **实证**（本机按该方法原样复现）：候选 `["^/test/hello$", "^/test/hell.*"]`（都是 13 字符）→ 集合里只剩 1 个，且**留下谁取决于 `selectable` 的迭代顺序**（`cryptoConfig` 是 `LinkedHashMap`，即 yml 声明顺序）。"最长正则"也 ≠ "最匹配"（长而宽松的模式会压过短而精确的模式）。
- **顺带实证**：`ReUtil.isMatch` 是**整串匹配**，不是 `find` —— `isMatch("api","/x/api/y")` = false、`isMatch("/api","/api2/x")` = false（hutool 5.8.26 实跑）。也就是说 `black-uris` / `black-methods` / `black-*-content-type` / `crypto-config` 的 key 都要写**完整正则**（要前缀匹配得写 `.*`），文档只说了"是正则"，没提"整串"。
- **修法**：比较器加 `thenComparing`（如并列时按插入序），或明确规定"最长且最先声明者优先"；文档补一句整串匹配的说明。
- **已修（2026-10-16）**：`getBestMatchStr` 不再用 `TreeSet`（其比较器对等长 key 返回 0 → 静默吞掉后来的同长候选），改为 `selectable.stream().filter(x -> ReUtil.isMatch(x, str)).max(Comparator.comparingInt(String::length)).orElse(null)` —— 语义是**显式**的"最长正则优先；等长时按 `selectable` 迭代顺序取先者"（`Stream.max`/`maxBy` 对相等元素保留先遇到的那个），并补了 `str == null || selectable == null || isEmpty()` 的守卫；Javadoc 把契约与"`ReUtil.isMatch` 是**整串**匹配"一起写清（文档层面补上了原本缺的说明）。
- ✅ **先红后绿**：`encryptor-core/src/test/java/io/github/cuukenn/encryptor/kit/StrKitTest.java`（4 条）——`test_best_match_equal_length_is_resolved_by_declaration_order`（两侧声明顺序各断一次，修前因 TreeSet 丢候选而得到一个"看运气"的结果）、`test_best_match_prefers_the_longest_matching_regex`、`test_best_match_returns_null_when_nothing_matches`、`test_any_match_is_full_match_not_contains`（把"整串匹配"钉成断言）。

### P3-7 uri 级 `crypto-config` 的 key 是含 `.` 的正则 → 必须用 `[key]` 括号写法，且没有端到端用例 🟩（2026-10-16 第三批扫描发现 → 当批已修，含实测与端到端证据）

- P0-1 修完只是"取值不再恒为 null"，但 `Map<String, CryptoConfig>` 的绑定对含 `.`、`[` 的 key 需要 `encryptor.config.web.crypto-config.[^/pay/.*].private-key=...` 这种**括号形式**（Spring Boot 对 Map key 的既定要求）；而 `README.md`、`docs/`、两个示例 `application.yml` 里**都没有 uri 级配置的样例**（`crypto-config` 在示例里是空的）。
- **影响**：这个"每个 uri 一套密钥"的功能虽然逻辑修好了，仍是**无示例、无端到端验证**的状态；使用者按正则思路写成 `^/pay/.*` 很可能因 key 在第一个 `.` 处被截断而静默走默认密钥——和 P0-1 的"静默失效"是同一类坑。
- **建议**：`web-example` 加一个 uri 级配置 + 一条真实请求的回归用例；文档给出括号写法完整示例。⚠️ Spring 绑定行为需动态验证。
- **已修（2026-10-16，已实测 + 端到端）**：`web-example` 真的加了一条 uri 级覆盖 + 新端点 `GET /test/secret`：
  - `application.yml` 里 `encryptor.config.web.crypto-config` 写成 **YAML 括号写法** `"[^/test/secret.*]":`（含一对**新的** RSA 密钥；全局配置不动，因此"这次请求用了哪套密钥"是可判定的）。
  - 🛠️ **括号写法是必需的（实测，非照搬常识）**：写成**裸** key `^/test/secret.*:` 时 Spring Boot **不报错**，而是把 key 静默改坏成 `testsecret`（`^`、`/`、`.*` 里的非法字符被剥离）→ 配置形同不存在。这是比崩溃更危险的一种失效。
  - ✅ **先红后绿**：新增 `encryptor-examples/web-example/src/test/java/.../example/web/CryptoConfigBindingTest.java`（`@SpringBootTest(webEnvironment = RANDOM_PORT)`，CI 可跑、不需要先起服务）——修前（裸写法）`crypto-config 应原样包含含 . 的正则 key [^/test/secret.*]，实际 keys=[testsecret]`；加括号后 2/2 绿，且断言该 key 的私钥/公钥**精确等于** yml 里那对。
  - ✅ **端到端**：`HttpTest` 新增两条并真实跑通——用**覆盖密钥**打 `/test/secret` → 200 / `Secret, 小明`；用**全局默认密钥**打同一端点 → **400**（服务端拿覆盖私钥解不开）。
  - 文档已补 YAML + properties 两版括号写法示例（见 `encryptor-web-starter.md` 的"uri 级配置"）。**网关侧未加同款样例**（同一套 `Map` key 绑定机制，web 侧三重证据已覆盖；网关要复现只需把前缀换成 `encryptor.config.reactive.gateway.crypto-config`，key 写法完全相同）。

### P3-8 工程卫生（pom `<name>` 重复、无 enforcer；并纠正"本机没有 JDK"的说法） 🟩（2026-10-16 第三批扫描发现 → 当批已修，经 `mvn` 验证）

- `encryptor-starters/encryptor-starter/pom.xml:15` 与 `encryptor-web-starter/pom.xml:15` 的 `<name>` 都是 `encryptor-spring-boot-starter`；`encryptor-starter-reactive/pom.xml` 与 `encryptor-gateway-starter/pom.xml` 都叫 `encryptor-spring-boot-starter-reactive` → 四个模块两两同名（影响中央仓库/Maven 站点展示与排查）。
- 无 `maven-enforcer-plugin`（不做依赖收敛/版本冲突检查），无覆盖率或其它质量门禁（surefire 已由 P2-6 固定）。
- **环境事实纠正**：本机**有** `java`/`javac`（`/usr/bin`，版本 11.0.28）、**有 maven 3.8.9**（`/usr/local/maven/3.8.9/bin/mvn`，只是不在 `PATH`）与部分 `~/.m2`。本文档头部"没有任何 JDK"的说法应据此更正。（更正于 2026-10-16 第二批扫描时；第三批期间已用该 maven 跑通全量构建。）
- **已修（2026-10-16，经 `mvn` 验证）**：`<name>` 去重——`encryptor-web-starter/pom.xml` → `encryptor-web-spring-boot-starter`、`encryptor-gateway-starter/pom.xml` → `encryptor-gateway-spring-boot-starter`（reactor 摘要里已能区分四个模块）；根 `pom.xml` 新增 `maven-enforcer-plugin`（3.4.1），规则为 `requireMavenVersion [3.6,)`、`requireJavaVersion [1.8,)`、`banDuplicatePomDependencyVersions`。
  - **刻意不开** `dependencyConvergence`：上游 Spring Boot / Cloud 的传递依赖树容易产生"需要先确认期望版本"的收敛失败，硬开会让构建变成猜谜（已在 POM 里写注释说明）。

## 建议动手顺序

### 第三批（2026-10-16 扫描 → **当批全部修完并验证**）

- ✅ **已修 + `mvn` 验证（第三批当批完成的）**：**P0-2**（网关 key 编码对齐）、**P0-6**（常量撞值导致 `black-req-content-type` 失效）、**P0-7**（缺字段 NPE）、**P1-9**（`black-res-content-type` 求值时机）、**P1-10**（表单 content-type 识别）、**P1-11**（参数 wrapper 三个视图）、**P1-12**（错误面统一 + `failure-status`）、**P1-13**（报文大小上限 + 网关切 `boundedElastic`）、**P2-1**（两个 `HttpTest` 加断言并真跑通，顺带修掉 3 个示例真 bug）、**P2-7**（facade/params 缓存）、**P2-8**（GroupEncryptor 不再泄漏）、**P2-9**（死代码清理，并**更正** bcpkix 结论）、**P2-10**（去掉 `@ComponentScan`）、**P3-6**（StrKit 契约显式化）、**P3-7**（uri 级 `crypto-config` 括号写法 + 样例 + 绑定/端到端证据）、**P3-8**（pom `<name>` + enforcer）。每一项都带"先红后绿"用例（少数例外在各自条目里注明）。
- 🟥 **确实仍未修**：各条目里"仍未做"小节列出的部分（响应方向的全量缓冲、失败指标/告警、`WebContext.resEncryptor` 等死 API、反射推泛型、失败计数、示例前端复用 IV）——**2026-10-18 逐条复核，绝大多数随 v2 重写已消失**：`WebContext.resEncryptor` 已删（现存 `protocol` 字段只被写入、无读取方，但作为下游过滤器可读的公开上下文保留，不算死代码）；`反射推泛型`/`失败计数` 随 v1 策略栈删除；**「示例前端复用 IV」不成立**——`jwe.js` 每次都新取随机量（`:103` CEK、`:137` 12 字节 IV、`:138` 16 字节 nonce）。真正仍开放的只有 **响应方向的全量缓冲（D2）**（失败指标/告警 D1/D3 已于 2026-10-18 用可选模块落地）。
- 🧪 **验证资产**：
  - `encryptor-core/src/test/java/.../audit/CryptoMechanismAuditTest.java`（5 条，机制行为：签名输入歧义(S7)、CBC 确定性(S14)、篡改可检出、畸形签名逃逸(S15)、GroupEncryptor 不再泄漏(P2-8)）；
  - `encryptor-core/src/test/java/.../audit/ClientAuthAuditTest.java`（2 条，**S1** 任何人拿公钥即可伪造合法请求、**S3** 服务端接受任意客户端自选算法）；
  - 过滤器/转换器级用例：`EncryptorResponseFilterTest`(3)、`EncryptorRequestBodyFilterTest`(3)、`EncryptorRequestParameterFilterTest`(4+1)、`EncryptorWebFilterTest`(4)、`MessageWriterTest`(2)、`MessageConverterOffloadTest`(2)、`EncryptorGatewayFilterTest`(4)、两侧 `FormMessageConverterTest`(3+1) 等。
  - 示例侧：`encryptor-examples/web-example/src/test/.../example/web/CryptoConfigBindingTest.java`（2 条，**uri 级 `crypto-config` 括号写法的绑定证据**，CI 可跑）+ 两个需要先起服务的 `HttpTest`（web 侧 4 条、网关侧 2 条，均带真断言）。
  - **改这些行为时它们会报警**，请连同 `security-review.md` 一起更新。

1. **P3-1、P0-3、P3-2、P3-3** —— ✅ 已完成（零风险，文档 / 配置类）
2. **P0-1、P0-5、P1-1（Redis 侧）、P1-5、P1-7、P2-4、P2-6** —— ✅ 已落盘并经 `mvn` 验证通过（2026-10-16；其中 P0-1 的 gateway 回归用例当时是坏的，已修，见 P0-1）；P2-1 已从 surefire 排除
3. **P1-8（WebContext 不重置）、P1-1（InMemory 侧并发）、P2-2（PR CI）** —— ✅ 已落盘并随全量构建验证通过
4. **P2-1（`HttpTest` 加断言）** —— 已从 surefire 排除（不再挡构建），但"无断言"本身还没治
5. **P0-4、P1-3、P1-6** —— 涉及行为/协议变更，需先定默认值与兼容策略（见 `security-review.md`）

## 与机制级问题的对应

| 代码级 | 机制级（`security-review.md`） |
| --- | --- |
| P0-2 🟩 | S4、S12（同一密钥承担多用途 / 无版本协商） |
| P0-6 🟩 | — （纯实现缺陷：常量撞值） |
| P0-7 🟩 | S11、S15（畸形报文未分类错误） |
| P1-10 🟩 | — （纯实现缺陷：content-type 比较方式） |
| P0-4、P0-5、P1-1 | S5、S6（防重放默认关闭、校验先于验签、容量驱逐） |
| P1-2 | S10（熵源） |
| P1-3 | S2（MD5 签名） |
| P1-4 | S8（PKCS1 v1.5 + 1024 位） |
| P1-6 | S3（客户端可降级算法） |
| P1-12 | S11、S15（错误面可区分 / 审计信号丢失） |
| P1-13、P2-7 | S17（无大小上限 + 每请求强制 RSA 私钥运算 + 事件循环阻塞） |
| — | S1（无客户端身份认证）、S7（签名覆盖面）、S9（跳过开关）、S11（错误处理）、S13（响应方向） |
| — | S14（示例前端跨请求复用同一 K/IV）、S16（网关把明文参数写回下游 URI） |

## v2 整分支评审修复（2026-10-18，commit `8a3e065`）

> 来源：`feat/jwe-protocol` 整分支复核（对照设计文档 `## Review Focus` 五条 + 逐文件阅读）。
> 分级：Critical 3 / Important ~15 / Minor 若干。全部 Critical 与 Important 已修，Minor 逐条裁定见下。
> 修复后单测：core 70→**79**、web 26→**31**、gateway 19→**23**（全量 **145 绿**）。

### 已修（按簇）

| 簇 | 修法 | 回归 |
| --- | --- | --- |
| core | `InMemoryNonceStore` 改 FIFO 淘汰（插入序队列 + 序号比较，驱逐确定性）+ `evictedCount()`；`DefaultProtocol.builder().nonceChecker(...)` 注入缝；`enc` 白名单与密钥类型联动（SM2 密钥缺 `SM4-GCM` 启动期 fail-fast） | `InMemoryNonceStoreTest`(4)、`SmCipherSuiteTest` 响应 header 断言 |
| web | 响应缓冲有界（`BoundedContentCachingResponseWrapper`，超限 500 不发明文）；响应 `enc` 显式取协商值；失败面统一 `fail()`（8 个早退口 + trace 头 + `WebContext.clear()`）；5 个过滤器注册 `asyncSupported=true` | `ResponseFilterHardeningTest`(5)、`SmJweTestSupport` |
| gateway | 响应 `enc` 显式取协商值；`onErrorResume` 把非法 JSON 信封归 `failure-status`、执行器队列满归 **503**；封装时 `HttpHeaders.remove(CONTENT_ENCODING)`；`black-methods` 与 ct 匹配语义与 servlet 侧一致化（整串正则 + ct 小写）；失败响应带 trace 头 | `GatewayJweTest` 13→17 |
| 自动装配 | 两侧 `ObjectProvider<NonceChecker>` → `builder.nonceChecker(...)`（换 Redis 不必覆盖整个 `DefaultProtocol`）；危险开关启动告警（`require-encrypted=false` / `bypass.*` / `max-response-size<=0` / 网关 `skip-able=true`） | `EncryptorReactiveAutoConfigurationTest` |
| 文档 | README 新增「运行须知（部署前必读）」；轮换 SOP 改写为**必须重启**；设计文档 §3.8/§3.9 加「实现校正」 | — |

### 裁定记录

- **RF-1**：`setHeader(name, null)` 在 Spring 的 `MockHttpServletResponse` 直接抛 `IllegalArgumentException` ⇒ servlet 侧改用 `Content-Encoding: identity` 覆盖（仅当原头存在），网关侧用 `HttpHeaders.remove()`。
- **RF-2**：响应缓冲溢出 ⇒ **500 且不发明文**（不是截断透传）。大响应/流式接口的正确姿势：content-type 进 `black-res-content-type` 且 `max-response-size<=0`。
- **RF-3**：网关密码学执行器队列满 ⇒ **503**（有意偏离评审建议的 `failure-status`：服务端过载不应伪装成客户端错误）。

### 明确推迟（Minor）——D1/D3 已于 2026-10-18 用可选模块落地（表内 🟩），本表保留原推迟理由以便追溯

| 编号 | 内容 | 推迟理由 |
| --- | --- | --- |
| D1 🟩 | 无 Micrometer 适配器（只有 `EncryptorListener` SPI） | **2026-10-18 已实现（可选模块）**：新增 `encryptor-micrometer-spring-boot-starter`，metrics 依赖只在显式引入该模块时出现——core 与两个 starter 的依赖面仍为零 metrics |
| D2 | 204/重定向等空响应两侧行为不对称 | 语义一致（都不包装）；改齐需动 `NettyWriteResponseFilter` 时序，风险 > 收益 |
| D3 🟩 | 网关有界执行器无队列深度指标 | **2026-10-18 已实现**：同模块导出 `encryptor.gateway.crypto.pending`/`rejected`/`threads`/`queue.capacity`；`pending` = 提交数 − 完成数（Reactor 的 `Scannable.Attr.BUFFERED` 实测恒为 0，不可用，故在 `CryptoExecutor` 内自行记账） |
| D4 | servlet 侧 `max-request-size` 只对 JSON 载体是真上限 | FORM 走容器 `getParameter()`（Tomcat `maxPostSize`）、QUERY 受 `maxHttpHeaderSize`；已在 README 写明边界，不改容器语义 |
| D5 | JS 参考客户端覆盖 RSA/AES 与 ECDH-ES(P-256)，仍不含 SM | WebCrypto 无 SM，`sm-crypto` 只有 SM4-ECB/CBC（无 GCM）；国密由 core/web/gateway 三层 Java 测试覆盖（2026-10-18 起 RSA+ECDH-ES 均有 JS 端到端用例） |

## ECDH-ES（P-256 直接密钥协商）新增与复查（2026-10-18）

**范围**：在既有 `CipherSuite` SPI 上新增 `alg=ECDH-ES`（RFC 7518 §4.6 直接密钥协商），不改线格式（仍是单 `jwe` 字段的 compact）。

### 已做
- `ConcatKdf`（NIST SP 800-56A §5.8.1 / RFC 7518 §4.6.2，SHA-256）+ `EcCipherSuite`（仅 P-256；AEAD 复用 `JceCipherSuite`，每次新建 `Cipher`）。
- `CipherSuite` 新增带 protected header 的 `unwrapCek` 重载（默认委托旧签名）；`JweCodec` 统一走带 header 入口，并把 `null`/空 `encrypted_key` 交给套件裁定（ECDH-ES/`dir` 该段为空）。
- `KeyType.EC`：PKCS#8 + SPKI，启动期 fail-fast（曲线必须 P-256；公私钥必须成对，用自协商校验）；JWKS 输出 `kty=EC, crv=P-256, alg=ECDH-ES`。
- `DefaultProtocol`：有 EC 密钥时默认加 `ECDH-ES`；**并修了一个联动缺陷**——只有 EC+SM2 密钥时（无 RSA）默认 `enc` 白名单原本不含 `A256GCM`，EC 请求会被 `ENC_NOT_ALLOWED` 误拒；现已用单测钉死（`EC与SM2并存时enc白名单同时含AES与SM4GCM`）。
- 客户端：两份 front `jwe.js` 支持 ECDH-ES（WebCrypto `ECDH` + 手写 Concat KDF），并修掉"响应 `enc` 写死 A256GCM"的互通缺口（改以响应头为准，`enc` 支持 A128/A192/A256GCM）。

### 证据
- core 单测 92 绿（新增 `EcCipherSuiteTest` 11 条 + `DefaultProtocolTest` 2 条）；`EcCipherSuiteTest` 以 nimbus `ECDHEncrypter`（独立实现）当 oracle 双向互通，并覆盖 P-384 `epk`、缺 `epk`、`epk` 带 `d`、非空 `encrypted_key`、RSA 密钥配 ECDH-ES 等拒绝面。
- 全 JIT 真实端到端：web-example 11/11（含 `/test/ec` 的 uri 级 EC 密钥绑定、A128GCM fail-closed）、gateway-example 10/10。

### 过程中发现并修正的问题
- ⚠️ `crypto-config` 的 uri 正则 key **不能嵌套括号**：`"[/]test[/]ec.*"` 被 Spring 的 key 解析静默改坏 → 规则整体失效、`/test/ec` 退回全局白名单（实测 RSA kid 被放行）。正确写法是整体包一层：`"[/test/ec.*]"`。已写进 `AGENTS.md` 坑清单；`P3-7` 的括号写法说明据此收紧。
- ⚠️ ECDH-ES 的 `encrypted_key` 段为空属正常，`JweCodec` 原来的"结构不完整"判定会把合法报文判成 `BAD_HEADER`（该判定已放宽，失败分类改由套件给出：RSA 收到空段仍会 `DECRYPT_FAILED`）。

### 明确不做（如需要请单独立项）
- **其它曲线**（P-384/P-521/X25519）：只做 P-256 是刻意的——它是 WebCrypto/Java 8/nimbus 的共同交集；多曲线要同时扩配置、JWKS 与 JS 客户端。
- **ECDH-ES+A128KW/A192KW/A256KW**（密钥包装模式，非直接协商）：与 `dir` 语义不同，需引入 CEK 包装层，收益不足。
- **`apu`/`apv`**：不实现，Concat KDF 的 PartyU/VInfo 固定为空（已与 JS 客户端、nimbus oracle 对齐）。
- **Java 手拼客户端的 ECDH-ES 用例**（两份 `HttpTest.java`）：JS 参考实现已覆盖端到端；`HttpTest` 要手拼 `epk`+Concat KDF，重复度高，暂不加。

## 复查建议 ①②③ 的落实（2026-10-18）

上一轮「正确性 + 性能」报告里的三条建议，现状：

1. **① JS 参考客户端把 `enc` 写死成 `A256GCM`**（服务端只允许 `A128GCM` 时无法互通）——**已修**：`decrypt()` 不再断言 `enc` 等于常量，改以响应头为准并按 `header.enc` 校验 CEK 长度；`encrypt()` 支持 A128/A192/A256GCM，按 `enc` 决定 CEK 字节数。
2. **② dev 模式（`spring-boot:run`）的性能数字不可用于决策**——**已落文档**：`README.md`「性能基准（JMH）」里加粗警告（该插件注入 `-XX:TieredStopAtLevel=1`，同代码 0.95 ms/op → 7.5 ms/op、HTTP rtt 1.6 ms → 8.6 ms），并给出全 JIT 手起方式（见 `AGENTS.md`）。
3. **③ 示例未配 SM2 密钥，国密能力无法在示例中自证**——**已补**：web-example 加 `sm-2026`（`^/test/sm.*` 绑定 + `GET /test/sm` 端点）、gateway-example 加 `sm-gw-2026`。用独立 SM 客户端（手拼 SM2 C1C3C2 + SM4-GCM，不复用 core）打 `/test/hello`，两侧各 **12/12 PASS**：正常往返、响应 `alg=dir`/`enc=SM4-GCM`/空 `encrypted_key`、以及重放 / 篡改密文 / 未知 kid / AAD 上下文不匹配四条拒绝面；同一批实例上 `node front/test.js` 仍 11/11、10/10（RSA 与 ECDH-ES 路径无回归）。

性能基准数据（JMH 六个基准、三次独立运行的中位数）已写入 `README.md`「性能基准（JMH）」；`encryptor-bench` 新增 `EcdhEsBenchmark`（配 `BenchSupport.ecStore()` / `sealEcdh()`），`check-thresholds.sh` 改为全限定基准名精确匹配、ECDH-ES/RSA 比值只打印不断言。

⚠️ 顺带更正一条此前的**误判**：`crypto-config` 的 `"[^/test/secret.*]"` 不是"否定字符类"。外层 `[ ]` 是 Spring 的括号写法（绑定后会被剥掉），真正的 key 是正则 `^/test/secret.*`；`WebCryptoConfigBindingTest.括号key绑定含点的正则uri` 已钉死该语义（`.[^/api/.*]` → key `^/api/.*`，且注释说明不用 `[key]` 时 Spring 会把 `^/api/.*` 静默改成 `api`）。示例与 README 的写法本身正确，无需改动。

## CI 加固与 JDK 8 复验（2026-10-18）

此前 `.github/workflows/ci.yml` 只有一步 `mvn -B -Pmain-module clean install`（temurin **JDK 8**），即**只覆盖 dependencies + core + starters**：示例工程与 JMH bench 在 CI 里连编译都不做，两份前端参考实现是否同步也没有守卫。

- **JDK 8 复验**：本地用 CI 同款 JDK（Oracle 1.8.0_461，arm64）跑 CI 同一条命令 → **158 绿 / BUILD SUCCESS**。ECDH-ES 在 JDK 8 上走 SunEC 的 `KeyAgreement("ECDH")` 正常（`EcCipherSuiteTest` 里以 nimbus `ECDHEncrypter` 为独立 oracle 的双向互通用例全过）；SM2 + SM4-GCM（BC 1.78.1）与 RSA-OAEP-256 亦然。此前所有验证都在 JDK 11 上做，这次补上了"CI 真实 JDK"这一环的证据。
- **新增两步**：①`mvn -B -Pall-modules -DskipTests package` —— 保证示例与 bench 能编译（`-DskipTests` 仍会编译测试源码，可挡住编译腐坏）；②`diff -u` 两份 `jwe.js` —— 把 `AGENTS.md`「成对文件」表里的前端双写面变成 CI 守卫（两份文件当前逐字节一致）。
- **故意不做**：JMH 阈值脚本不进 CI —— 共享 runner 上吞吐噪声大，硬闸门只会带来假失败；它仍是本地/发布前的手动闸门（`README.md`「性能基准（JMH）」有复现命令）。

## P3-4 落实：`black-*` → `skip-*`（正名 + 弃用 alias，2026-10-18）

- 四个跳过名单改名为 `skip-uris` / `skip-methods` / `skip-req-content-type` / `skip-res-content-type`；旧名 `black-*` 仍可绑定（getter/setter 标 `@Deprecated`），绑定时落一条 WARN 指出去哪改名。**新旧共存时合并去重**（无顺序依赖，也不会互删）。
- 实现（servlet `WebEncryptorConfig` 与 reactive `GatewayEncryptorConfig` **成对**）：旧名有独立绑定字段，`InitializingBean.afterPropertiesSet()` 在绑定完成后并入生效名单。
  - ⚠️ 踩到的坑（首版实现被它打回）：**不能共用同一个 list**。Spring Boot 对集合属性是"就地绑定（clear + 回填到 getter 返回的那个 list）"，共用一份时后绑定的名字会把先绑定的清掉——`skip-uris=[/api/open.*]` + `black-uris=[/api/open.*, /other]` 实测只剩 `[/api/open.*]`（先红：`WebCryptoConfigBindingTest.新旧名字可共存并合并去重` 断言 `[/api/open.*, /other]` 失败）。
- 测试：`WebCryptoConfigBindingTest` +2（旧名可绑定 / 新旧共存合并去重）；新增 `GatewaySkipAliasBindingTest` 4（旧名 / 新名 / 共存 / 未配置为空；用 `Binder` + `MapConfigurationPropertySource` 直接钉属性名，`afterPropertiesSet()` 显式调用）。
- 同步：6 处 filter 调用点、3 处测试调用点、两处自动装配告警文案、`EncryptorResponseFilter` javadoc、README 配置样例、设计文档 §3.7 表与 §3.2 样例、`.opencode` 技能清单。
- 证据：`mvn -B -Pall-modules clean install`（JDK 8）→ **164 绿 / BUILD SUCCESS**（web 31→33、gateway 23→27）。

## 顺带修掉：示例 `HttpTest.java` 在 JDK 8 下编译不过（2026-10-18）

- 现象：`mvn -B -Pall-modules clean install`（JDK 8）在 `web-example` 的 **testCompile** 阶段失败：`不兼容的类型: java.nio.charset.Charset 无法转换为 java.lang.String`（`HttpTest.java:51/66/79/165`）。
- 根因：`URLEncoder.encode(String, Charset)` 是 **Java 10+** API；本项目宣告 Java 8（`source/target=8`），JDK 11 上编得过、JDK 8 上过不了。两份 `HttpTest.java` 因被 surefire 排除（需先起服务）而长期没被真正编译过。
- 影响：`-Pall-modules` 全量构建在 JDK 8 上是**红的**；是本轮新增的 CI 步骤 `mvn -B -Pall-modules -DskipTests package` 先把它暴露出来的（这正是那一步的价值）。
- 修法：两个文件都加 `private static String enc(String s)`（`URLEncoder.encode(s, "UTF-8")`，受检异常包成 `IllegalStateException`），4 处调用改用它。
- 证据：JDK 8 下 `mvn -B -Pall-modules clean install` → BUILD SUCCESS（含两示例与 bench）；CI 第二步 `mvn -B -Pall-modules -DskipTests package` → BUILD SUCCESS；`diff` 两份 `jwe.js` → exit 0。

## D1/D3 落地：可选 Micrometer 模块（2026-10-18）

**结论**：D1（无 Micrometer 适配器）与 D3（网关有界执行器无队列深度指标）都用**新的可选模块** `encryptor-micrometer-spring-boot-starter` 实现，core 与两个 starter 的依赖面**零变化**——这正是当初推迟这两项的唯一理由。

**模块内容**（`encryptor-starters/encryptor-micrometer-starter/`，artifactId `encryptor-micrometer-spring-boot-starter`）：

- `MicrometerEncryptorListener implements EncryptorListener`：`encryptor.decrypt{result=success|failure}`（Counter）、`encryptor.decrypt.failures{failure=<分类>}`、`encryptor.encrypt.failures{failure=<分类>}`；分类取 `EncryptorFailure` 枚举名，注册时遍历枚举一次性预建（未出现的分类也有 0 值），未知/null 归 `INTERNAL`。
- `GatewayCryptoExecutorMetrics`：`encryptor.gateway.crypto.pending`（Gauge = 提交数 − 完成数）、`rejected`（FunctionCounter，每次被拒 +1，对应用户可见的一次 503）、`threads`/`queue.capacity`（Gauge 常量）。持 `CryptoExecutor` 强引用（Micrometer 的 Gauge 只弱引用）。
- `EncryptorMicrometerAutoConfiguration`（`META-INF/spring.factories` 注册）：`@ConditionalOnClass(MeterRegistry)` + `@AutoConfigureAfter(name = "...MetricsAutoConfiguration")`（用字符串名避免硬依赖 actuator）；`EncryptorListener` bean 带 `@ConditionalOnBean(MeterRegistry)` + `@ConditionalOnMissingBean(EncryptorListener)`（用户自定义优先）；内部 `@ConditionalOnClass(CryptoExecutor)` 子配置导出网关指标（`CryptoExecutor` 属 gateway starter，而它是本模块的 **optional** 依赖，故 servlet 应用不会被拖进 Spring Cloud Gateway）。
- pom：`encryptor-core` + `spring-boot-autoconfigure` + `micrometer-core`（版本由 spring-boot-dependencies 管）+ `encryptor-gateway-spring-boot-starter`（optional）+ `spring-boot-starter-test`。`encryptor-starters/pom.xml` 与 `encryptor-dependencies/pom.xml`（BOM）已登记。

**为什么不记耗时**：`EncryptorListener` 只有"结束时"回调，没有开始钩子；要加计时段就得改 core 热路径（`JweCodec`），收益配不上风险。端到端 P99 用 HTTP 层指标（`http.server.requests`）即可覆盖。

**D3 的记账方式（踩坑记录）**：最初想直接读 Reactor 的 `Scannable.Attr.BUFFERED`（`BoundedElasticScheduler.estimateSize()`），实测**恒为 0**——任务被 Reactor 从待派发队列抽进执行器内部队列后就不可见了。改为在 `CryptoExecutor` 内包一层记账 `Scheduler`：`submit` 成功才 `submitted++`、`count` 的 `finally` 里 `completed++`、`RejectedExecutionException` 时 `rejected++` 并原样抛出（不计入 pending）；`pendingTasks()` = submitted − completed。另一个 API 事实：Reactor 3.4.2 的 `Scheduler` 只 `extends Disposable`（**不是** `Scannable`），抽象方法仅 `schedule(Runnable)`/`createWorker()`，覆写 `scanUnsafe` 会编译失败。

**同时改动的生产码（网关侧 D3 hook）**：新增 `reactive/gateway/runtime/CryptoExecutor`（`SCHEDULER_NAME`、`DEFAULT_QUEUE_CAPACITY=1000`、`create()`）；两个网关过滤器不再各自持有 `private static final Scheduler`，改为注入**同一个** `CryptoExecutor`（构造器 4 参）；`GatewayEncryptorConfiguration` 新增 `@Bean @ConditionalOnMissingBean CryptoExecutor`（两过滤器共用、指标模块读同一实例、用户可覆盖）。

**证据**：

- `JAVA_HOME=…jdk-1.8.0_461 mvn -B -Pall-modules clean install` → BUILD SUCCESS，**182 绿**（core 92、starter 9、reactive 3、web 40、gateway 30、micrometer 8），fail/err 均 0。
- gateway 30 = 原 27 + `CryptoExecutorTest` 3（默认取值 / 待执行数记账 / 被拒记账）。
- micrometer 8 = `MicrometerEncryptorListenerTest` 3（计数、分类预建、null→INTERNAL）+ `EncryptorMicrometerAutoConfigurationTest` 4（有/无 registry、用户监听器优先、网关指标导出）+ `MicrometerListenerWiringTest` 1（**接线证明**：真实 reactive starter 与本模块同时装配，`DefaultProtocol.openRequest("not-a-jwe", …)` 抛异常后 `encryptor.decrypt{result=failure}` == 1，且恰好一个分类被计数）。
- 未做：Micrometer 的 Timer/耗时（理由见上）；D2 仍开放。
