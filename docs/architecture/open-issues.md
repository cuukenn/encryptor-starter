# 已知问题与可修改点（Open Issues）

> 生成于 2026-10-16，来源：全仓扫描（codegraph 索引 + 逐文件阅读）。**本文件记录问题与建议修法，不代表已修。**
>
> 状态图例：🟥 未修 · 🟨 待决策（需要拍板 / 涉及行为•协议变更）· 🟩 已修
>
> 机制级（密码学 / 协议设计）问题单独放在 `security-review.md`，编号 `S1…`，本文用 `S-n` 交叉引用。
>
> 修完请把状态改成 🟩 并补日期，**不要删条目**。
>
> ⚠️ **验证环境（2026-10-16 实测）**：本机**没有安装 JDK 与 Maven**——`mvn` / `java` / `javac` 均不在 PATH，`C:\Program Files\JetBrains` 下无内容（IDEA 安装目录为空），`E:` 盘也搜不到 `javac.exe`。因此**代码类修改无法在本机用 `mvn` 验证**：必须在装有 JDK 8 + Maven 的机器上跑 `mvn -Pmain-module clean install` 才算验完。纯文档/README 类修改不受影响。
>
> 🧪 **第二批修复（2026-10-16）**：P0-1、P0-5、P1-1（Redis 侧）、P1-5、P1-7、P2-4 已落盘，并顺带修好 P2-6（固定 `maven-surefire-plugin:2.22.2`，让 JUnit5 真正执行）。**这些代码改动一行都没编译过、没运行过**——只做过"花括号/圆括号配平"这一层弱检查。请在有 JDK 8 + Maven 的机器上执行 `mvn -Pmain-module clean install` 之后，再把它们的状态视为可信。

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
  - 注意：gateway 用例里工厂返回的 `EncryptorFacade` 是 `null`（只关心传入的 `CryptoConfig`），`GatewayKit.setEncryptorFacade` 只做 `attributes.put`，不会 NPE。
  - ⚠️ 未经 `mvn` 验证。

### P0-2 reactive 侧 AES key 编码与 servlet/前端不一致 → 网关 JS Demo 实际解不开 🟨

- **位置**：`encryptor-starter-reactive/.../reactive/configuration/EncryptorReactiveAutoConfiguration.java:50`（`obj.getBytes("key")`）对比 `encryptor-starter/.../configuration/EncryptorAutoConfiguration.java:50`（`encoder.decode(obj.getStr("key"))`）
- **证据链**：
  - 两套前端 `front/encryptor/aes.js:23,28` 都是 `CryptoJS.enc.Base64.parse(key)`；`generateBase64Key(128)` = `btoa(16 个字符)` = 24 个 base64 字符 → 解码 **16 字节**（AES-128）。
  - servlet 侧 `Base64.decode` → 16 字节 → 与前端一致 ✅
  - reactive 侧 `"...".getBytes()` → 24 字节（AES-192）→ 与前端**不一致** ❌
  - 交叉证据：`encryptor-examples/gateway-example/gateway/src/test/java/io/github/cuukenn/encryptor/HttpTest.java:56` 用 `IdUtil.fastSimpleUUID()`（32 字符）当 key，并与同源 facade 往返 → 自洽所以"能过"。即**同一个网关：Java 测试通过、JS 客户端必然失败**。
- **修法（二选一）**：
  - (A) reactive 改为 `encoder.decode(obj.getStr("key"))`，与 servlet + 两套前端对齐（HttpTest 因自洽仍绿）。**代价：对已上线、客户端传"原始字符串当 key"的网关是破坏性变更**，须写进 release note。
  - (B) 实现不动，改前端（`aes.js` 改用 `CryptoJS.enc.Utf8.parse(key)`）+ 文档写明"网关的 key 是原文字节"。
- **建议**：选 (A)，并对齐后跑一次真实端到端（见 P2-1）。
- **验证方式**：起 `gateway-example` + 用修正后的 `front/index.js` 跑三种请求（get / json / form-urlencoded），断言响应体能被 JS 解回明文。

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

## P2 · 工程化 / 测试 / CI

### P2-1 两个 `HttpTest` 是"没有断言的伪测试" 🟥

- `encryptor-examples/gateway-example/gateway/src/test/java/io/github/cuukenn/encryptor/HttpTest.java:36-44,76-80,110-116`（web 侧同构）。
- **现象**：标 `@Test` 但只 `consumeWith(res -> logger.info(...))`，**无任何断言**；且打的是 `127.0.0.1:8080` / `8081` 上**外部已启动**的服务。
- **后果**：服务没起 → 红；**业务错了 → 仍然绿**；CI 里必失败。
- **修法**：改 `@SpringBootTest(webEnvironment = RANDOM_PORT)` + 真断言；或 `@Disabled` / `@Tag("e2e")` + surefire exclude；或改成独立 `main` 脚本。

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

### P2-5 两种承载形态（参数 / 请求体）耦合脆弱 🟨

- web 侧 `EncryptorRequestParameterFilter`（order `-11`，读 `getParameterMap()`）与 `EncryptorRequestBodyFilter`（`-10`）共享同一请求；form 请求的 body 会被容器解析掉。调整 order 或增删过滤器会**静默**改变行为。
- 建议：补注释/文档说明该耦合，并加集成测试锁住行为。

### P2-6 JUnit5 测试其实从未被执行（根 POM 没有 surefire） 🟩（2026-10-16 已修）

- **位置**：根 `pom.xml` 的 `pluginManagement`（原来只有 maven-javadoc / source / gpg / nexus-staging 插件，**没有 maven-surefire-plugin**）。
- **现象**：不显式声明时 Maven 用默认 surefire（2.12.x 一代），它**不支持 JUnit 5 平台**——于是全仓那些 `org.junit.jupiter` 测试**从来没真正跑过**。这也正好解释了：`GroupEncryptor` 明明是 `return null`，`EncryptorStrategyTest` 里针对它的用例却一直"没问题"。
- **已修（2026-10-16）**：`pluginManagement` 里固定 `maven-surefire-plugin:2.22.2`（JUnit5 需要 2.22+），并加 `<exclude>**/HttpTest.java</exclude>`（端到端脚本，见 P2-1）；`encryptor-core/pom.xml` 加 test 作用域 `mockito-core`，`encryptor-web-starter` / `encryptor-gateway-starter` 各加 test 作用域 `spring-boot-starter-test`。
- ⚠️ **这是本批风险最高的一处改动**：它会让原本"假绿"的测试真的跑起来——一旦构建，很可能暴露更多既有问题。未经 `mvn` 验证。

## P3 · 文档 / 命名

### P3-1 `AGENTS.md` 说 core"无 Spring"不成立 🟩（2026-10-16 已修）

- 反证：`encryptor-core/pom.xml:22-31` 有 optional 的 `spring-boot-starter-data-redis`、`logback-classic`；`core/checker/InRedisNonceChecker.java:6` 直接 `import org.springframework.data.redis.core.RedisTemplate`。`docs/architecture/encryptor-core.md:11` 本来写对了。

### P3-2 `README.md` 声称的网关 gzip 不存在 🟩（2026-10-16 已修）

- `README.md:17` 曾声称支持"网关 gzip encode/decode"，全仓无 gzip 代码（仅此一行提及）。
- **已修**：删除该特性行（README 特性列表不再包含 gzip）。同时更新了引用它的 `AGENTS.md`、`encryptor-starter-development/SKILL.md`、`docs/architecture/encryptor-gateway-starter.md`。若要真做 gzip，需从零实现（`encode/decode` 两面 + 配置开关）。

### P3-3 `README.md` 依赖坐标与残留注释 🟩（2026-10-16 已修）

- groupId 写成 `io.github.cuukenn.encryptor`（实际 `io.github.cuukenn`）；含 `dynamic-mongodb-database-starter` 的复制残留注释。
- **已修**：三处 `groupId` 全部改为 `io.github.cuukenn`；三个 `mvnrepository` 提示链接补全为 `.../artifact/io.github.cuukenn/<artifactId>`（含被污染的 gateway 那条）；残留注释删除。

### P3-4 `black*` 命名与语义相反，且是正则 🟨

- `blackUris` / `blackMethods` / `blackReqContentType` / `blackResContentType` 实为"跳过加密名单"；`StrKit.anyMatch` → `ReUtil.isMatch`（**正则**，非通配符）。建议新增 `skip*` 并保留旧名 alias。

### P3-5 `.github` 模板为单文件形式 🟨

- `issue_template.md` / `pull_request_template.md`，未使用 `.github/ISSUE_TEMPLATE/*.md` 的 front-matter 模板选择器。低优先级。

## 建议动手顺序

1. **P3-1、P0-3、P3-2、P3-3** —— ✅ 已完成（零风险，文档 / 配置类）
2. **P0-1、P0-5、P1-1（Redis 侧）、P1-5、P1-7、P2-4、P2-6** —— ✅ 已落盘（2026-10-16，含回归用例，**全部未经 `mvn` 验证**）；P2-1 已从 surefire 排除
3. **P1-8（WebContext 不重置）、P1-1（InMemory 侧并发）、P2-2（PR CI）** —— ✅ 已落盘（2026-10-16，含回归用例；仍然**未经 `mvn` 验证**）
4. **P2-1（`HttpTest` 加断言）** —— 已从 surefire 排除（不再挡构建），但"无断言"本身还没治
5. **P0-2、P0-4、P1-3、P1-6** —— 涉及行为/协议变更，需先定默认值与兼容策略（见 `security-review.md`）

> 第 2、3 项的全部改动**必须在装有 JDK 8 + Maven 的机器上跑 `mvn -Pmain-module clean install` 才算验完**（本机无工具链，见顶部警告）。

## 与机制级问题的对应

| 代码级 | 机制级（`security-review.md`） |
| --- | --- |
| P0-2 | S4、S12（同一密钥承担多用途 / 无版本协商） |
| P0-4、P0-5、P1-1 | S5、S6（防重放默认关闭、校验先于验签、容量驱逐） |
| P1-2 | S10（熵源） |
| P1-3 | S2（MD5 签名） |
| P1-4 | S8（PKCS1 v1.5 + 1024 位） |
| P1-6 | S3（客户端可降级算法） |
| — | S1（无客户端身份认证）、S7（签名覆盖面）、S9（跳过开关）、S11（错误处理）、S13（响应方向） |
