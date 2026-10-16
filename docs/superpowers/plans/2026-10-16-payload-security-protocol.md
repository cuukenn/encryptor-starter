# 报文层安全协议重实现 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 用对齐 JOSE/JWE（RFC 7516）的标准报文层安全替换现有自研混合加密（RSA-PKCS1v15 包客户端自选 AES key + AES-CBC + `AES_K(MD5)` 签名），实现**机密性 + 防篡改**；**不做身份认证、不做 v1 兼容**。

**Architecture:** `encryptor-core` 提供 `ServerKeyStore`（多 `kid`、并发安全）、`ContextAad`、`JweCodec`（nimbus-jose-jwt）、`ReplayGuard`、`EncryptorRuntime`（运行期旁路）、`EncryptorListener`；两个自动装配只把 core 的默认协议装成 bean（servlet / reactive 共用同一份 core 实现，消灭逐字重复）；web / gateway 过滤器退化为"取 `jwe` → 解密 → 交业务 / 业务响应 → 封装 `jwe`"，并各自暴露 JWKS 发现端点。

**Tech Stack:** Java 8、Maven 多模块、Spring Boot 2.4.2（`META-INF/spring.factories` 自动装配）、Spring Cloud Gateway 2020.0.1、`com.nimbusds:nimbus-jose-jwt`、hutool 5.8.25、JUnit 5、前端 WebCrypto。

**Spec:** `docs/superpowers/specs/2026-10-16-payload-security-protocol-design.md`（**执行前必读**；本计划是它的实现，任何冲突以 spec 为准并停下来问）

## Global Constraints

- **Java 8** 语言级别；**Maven 多模块**；每个任务结束时 `mvn -Pmain-module clean install` 必须 **BUILD SUCCESS**。收尾任务另跑 `mvn -Pall-modules clean install`。
- Maven 不在 PATH：`/usr/local/maven/3.8.9/bin/mvn`。排障加 `-DtrimStackTrace=false`。
- **Spring Boot 2.4.2 ⇒ 自动装配用 `META-INF/spring.factories`**，**不是** `AutoConfiguration.imports`。
- 新增依赖**只允许** `com.nimbusds:nimbus-jose-jwt`，版本在 `encryptor-dependencies` 的 `<dependencyManagement>` 里统一管理。**必须选一个 Java 8 可编译的版本**（nimbus-jose-jwt `10.x` 起要求 Java 11 ⇒ 用 `9.x`，并在 T1 用 `mvn -Pmain-module clean install` 实证）。`bcpkix-jdk18on` **必须保留**（国密 SM2/SM4 用例依赖 BC 提供的 JCA provider，源码里没有直接引用——删了会 `SM4 KeyGenerator not available`）。
- **不用 Lombok**。配置类 `@ConfigurationProperties(prefix = ...)` + 显式 getter/setter。自动装配类 `@Configuration(proxyBeanMethods = false)` + `@ConditionalOnProperty` / `@ConditionalOnMissingBean`。类头保留 `@author changgg`，注释与 Javadoc 用**中文**。
- **`encryptor-core` 不得新增 Spring 依赖**（唯一例外：`core/checker/InRedisNonceChecker` 的 optional `spring-boot-starter-data-redis`）。
- **servlet / reactive 双写必须同步**（`AGENTS.md` 的"必须同步修改的地方"表）：protocol 行为若要两侧一致，只允许实现在 core；两侧只做装配。
- 测试 JUnit 5；根 POM 已固定 `maven-surefire-plugin:2.22.2`；`**/HttpTest.java` 是需先起服务的端到端脚本，**已在 surefire 排除**（不要把它接回来）。
- 破坏性变更：v1 报文（`nonce/timestamp/signature/key/data` 五字段）**不再支持**，一律按非法报文处理；相关类、测试、前端 js、示例 yml 一并删除。
- 任何写进配置/文档的算法名使用 JOSE 规范名：`RSA-OAEP-256`、`A256GCM`、`dir`。

## Review Focus

以下 5 类是 spec 隐含、但没有任何任务的测试天然覆盖、且最可能坑到使用者的输入/失效模式。每条都已指到拥有该代码的任务，并在该任务里加了测试。

1. **命中范围的接口返回非 JSON / 流式内容**（SSE、文件下载、空 body、`204`、重定向）：期望**不包装**、可流式、不整段缓冲堆内存。→ T10（servlet）、T12（gateway）。
2. **请求体的退化输入**（空 body、`application/json` 但非 `jwe` 结构、超 `max-request-size`、`Content-Length` 与实际不符、chunked）：期望一致地 413 或 400，**不 NPE、不读到死**。→ T9。
3. **`crypto-config` 的 uri 正则 key 含 `.` 却没写 `[key]` 括号**：Spring Boot 会**静默**把 key 改坏（实测 `^/test/secret.*` → `testsecret`，不报错）。期望启动 fail-fast 或至少被测试钉住。→ T8。
4. **并发**：同一 `kid` 的 RSA 运算不得退化为全局串行（现状 hutool `BaseAsymmetric` 的实例级 `ReentrantLock` 把私钥运算串行化了）；nonce 存储在并发下不得误判重放。→ T5（nonce）、T14（RSA 并行基准）。
5. **时间戳单位与时钟偏移**（客户端发毫秒 vs 服务端按秒比、`ts` 落在窗口边缘、客户端时钟慢/快）：期望单位统一为**毫秒**、窗口容差明确、误差写入 README。→ T2、T5。

## File Structure

**core（新增，包名与现有 `kit/`、`core/`、`facade/` 平级）**

| 文件 | 职责 |
| --- | --- |
| `encryptor-core/.../jose/ServerKeyStore.java` | 多 `kid` 密钥库：按 `kid` 取私钥、导出 JWK/SPKI 公钥、提供线程安全的 RSA `Cipher`；构造期 fail-fast |
| `encryptor-core/.../jose/PublicKeyInfo.java` | 对外公钥描述（`kid`/`alg`/`jwk`/`active`），**只含公钥** |
| `encryptor-core/.../jose/ContextAad.java` | AAD 规范化（`uri`/`method`/方向/`ts`/`nonce`）+ `Direction` 枚举 |
| `encryptor-core/.../jose/JweCodec.java` | 唯一协议实现：解请求 JWE、封响应 JWE；算法白名单在此**内部强制** |
| `encryptor-core/.../jose/JweContext.java` | 解密结果值对象：明文 + `cek` + `kid` + `alg` + `enc` |
| `encryptor-core/.../jose/ReplayGuard.java` | `ts` 窗口 + nonce 消费（顺序：先验 tag 后消费 nonce） |
| `encryptor-core/.../runtime/EncryptorRuntime.java` | 运行期旁路开关（`bypassRequest`/`bypassResponse`）+ 缓存失效联动 |
| `encryptor-core/.../facade/FacadeResolver.java` | `uri → facade` 解析与缓存 + `invalidate()` |
| `encryptor-core/.../audit/EncryptorListener.java` | 默认 no-op 的加解密成功/失败回调（指标/审计接入点） |
| `encryptor-core/.../audit/EncryptorFailure.java` | 失败分类枚举（`MISSING`/`BAD_HEADER`/`UNKNOWN_KID`/`ALG_NOT_ALLOWED`/`DECRYPT_FAILED`/`AAD_MISMATCH`/`EXPIRED`/`REPLAY`/`TOO_LARGE`） |

**core（删除）**：`pojo/EncryptorDataWrapper.java`、`core/signer/{HtlSigner,DigestWithEncryptSigner}.java`、`core/ISignerStrategy.java`、`core/SignerStrategy.java`、`core/encoder/SignerEncoder.java`、`core/digester/HtlDigester.java`、`core/DigesterStrategy.java`、`core/IDigesterStrategy.java`、`core/encryptor/GroupEncryptor.java`、`core/encoder/HexEncoder.java`，以及 `kit/EncryptorKit.java` 里的协议编排（`nonce`/`timestamp`/签名输入）。

**servlet**：`encryptor-starters/encryptor-starter/.../configuration/EncryptorAutoConfiguration.java`（装配 core 默认协议）、`encryptor-starters/encryptor-web-starter/.../filter/{EncryptorWebFilter,EncryptorResponseFilter,EncryptorSkipFilter}.java`、`.../config/*EncryptorConfig.java`、新增 `.../discovery/{JwksEndpoint,JwksProperties}.java`。

**gateway**：`encryptor-starters/encryptor-starter-reactive/.../configuration/EncryptorReactiveAutoConfiguration.java`、`encryptor-starters/encryptor-gateway-starter/.../filter/rewrite/{EncryptorGatewayFilter,EncryptorResponseFilter}.java`、`.../filter/*`（新增 JWKS 处理）、`.../config/GatewayEncryptorConfig.java`。

**examples / JS**：`encryptor-examples/web-example/front/encryptor/jwe.js`（新）、删 `md5withaes.signature.js` + 改写 `random.js`/`aes.js`/`rsa.js`/`index.js`（两个示例同改）、`encryptor-examples/*/src/test/**/HttpTest.java`、两个示例的 `application.yml`。

**bench（新模块，不进发布）**：`encryptor-bench/`（JMH）。

---

## Phase A — core 协议内核

### Task 1: 依赖 + `ServerKeyStore`

**Files:** modify `encryptor-dependencies/pom.xml`（`<dependencyManagement>` 加 nimbus）、`encryptor-core/pom.xml`（引依赖）；create `encryptor-core/src/main/java/io/github/cuukenn/encryptor/jose/{ServerKeyStore,PublicKeyInfo}.java`；test `encryptor-core/src/test/java/io/github/cuukenn/encryptor/jose/ServerKeyStoreTest.java`

**Interfaces:**
- `static ServerKeyStore fromBase64(String kid, String privPkcs8Base64, String pubX509Base64, boolean active)` — 解析失败立刻抛 `EncryptorException`（fail-fast）
- `PrivateKey privateKey(String kid)` / `boolean contains(String kid)` / `String activeKid()`
- `String spkiBase64(String kid)` — X.509 SubjectPublicKeyInfo，无 PEM 头
- `Map<String,Object> jwk(String kid)` — `kty/use=enc/alg=RSA-OAEP-256/kid/n/e`，**绝不含 `d` 等私钥字段**
- `Cipher rsaCipher()` — `ThreadLocal<Cipher>`，同线程复用、跨线程绝不共享单实例
- `List<PublicKeyInfo> publicKeys()`

**测试（`ServerKeyStoreTest`）：** 多 `kid` 并存按 `kid` 取私钥、未知 `kid` 返回 `null`；`jwk()` 无 `d`；`spkiBase64()` 能被 JDK 重新导入并成功 OAEP 加密；非法 base64 ⇒ 构造抛 `EncryptorException`；8 线程并发 `rsaCipher()` 返回**互不相同**的实例。测试密钥用 `KeyPairGenerator` 现场生成后再 base64，不硬编码。

**完成条件：** `mvn -pl encryptor-core test -Dtest=ServerKeyStoreTest` 绿，且 `mvn -Pmain-module clean install` 绿（证明所选 nimbus 版本 Java 8 可编译）。

### Task 2: `ContextAad` + `Direction`

**Files:** create `.../jose/{ContextAad,Direction}.java`；test `.../jose/ContextAadTest.java`

**Interfaces:**
- `enum Direction { REQUEST("req"), RESPONSE("res") }`
- `static String canonicalPath(String requestUri, String contextPath)` — 去掉 `contextPath`、百分号解码、UTF-8、**不含 query**
- `static Map<String,Object> claims(String uri, String method, Direction dir, long ts, String nonce)` — 放进 JWE **protected header** 的成员（`uri`/`m`/`dir`/`ts`/`nonce`）
- `static void verify(Map<String,Object> header, String uri, String method, Direction dir)` — 不匹配抛 `EncryptorException`（分类 `AAD_MISMATCH`）

**关键约束：** `ts` 单位是**毫秒**（与今天 `new Date().getTime()` 一致）；`method` 一律大写。

**测试：** `canonicalPath("/app/a%20b", "/app")` → `/a b`；`verify` 缺 `uri`/`m`/`dir` 任一 ⇒ 抛；换 `uri` 或改 `dir` ⇒ 抛；`claims` 的 `ts` 数量级 = 毫秒（`> 10^12`）。

### Task 3: `JweCodec` 解密请求

**Files:** create `.../jose/{JweCodec,JweContext}.java`；test `.../jose/JweCodecTest.java`

**Interfaces:**
- `JweCodec(ServerKeyStore keys, Set<String> allowedAlgs, Set<String> allowedEncs)`
- `JweContext decryptRequest(String compact, String uri, String method)` — 失败抛 `EncryptorException`（带 `EncryptorFailure`）
- `JweContext`：`byte[] plaintext()`、`byte[] cek()`、`String kid()`、`String alg()`、`String enc()`、`long ts()`、`String nonce()`

**顺序（不可变）：** 解析 header → `alg`/`enc` 白名单（**集合为空 = 只接受 `RSA-OAEP-256` / `A256GCM`**）→ `kid` 存在 → `ContextAad.verify` → OAEP-256 解封 CEK → AES-GCM 解密（tag 校验）→ 返回。

**测试：** 客户端用 nimbus 自建 JWE ⇒ 解出原文；分别改 `ciphertext`/`iv`/`tag`/protected header 一个字节 ⇒ 全部失败；`alg=RSA1_5`、`enc=A128CBC-HS256`、未知 `kid` ⇒ 失败；换 `uri`/`method` ⇒ `AAD_MISMATCH`；空串/非 JWE ⇒ `MISSING`/`BAD_HEADER`。

### Task 4: `JweCodec` 封装响应

**Files:** modify `.../jose/JweCodec.java`；modify `.../jose/JweCodecTest.java`

**Interfaces:** `String encryptResponse(byte[] body, byte[] cek, String uri, String method, long ts, String nonce)` — 产出 `alg=dir`、**每次新随机 IV**、`enc=A256GCM` 的 compact。

**测试：** 用同一 CEK 解回原文（`dir` 的 `encrypted_key` 段为空）；响应 AAD 用 `dir=res` ⇒ 拿请求 AAD 去解会失败；CEK 长度 ≠ 32 ⇒ 抛 `EncryptorException`。

### Task 5: `ReplayGuard`

**Files:** create `.../jose/ReplayGuard.java`；test `.../jose/ReplayGuardTest.java`

**Interfaces:** `ReplayGuard(long ttlMillis, NonceChecker checker)`；`void verify(long ts, String nonce)` — `|now - ts| > ttl` ⇒ `EXPIRED`；`checker.check(nonce)` 返回已用过 ⇒ `REPLAY`。

**关键：** 只能在 GCM tag 校验**通过之后**调用（T3 的调用点负责），否则未认证输入会污染 nonce 存储。

**测试：** 窗口内通过；过去/未来超窗 ⇒ `EXPIRED`；同 nonce 第二次 ⇒ `REPLAY`；100 线程并发同一 nonce ⇒ 恰好 1 个通过。

### Task 6: `EncryptorRuntime` + `FacadeResolver`

**Files:** create `.../runtime/EncryptorRuntime.java`、`.../facade/FacadeResolver.java`；test 同名 `*Test.java`

**Interfaces:**
- `EncryptorRuntime`：`boolean bypassRequest()`、`boolean bypassResponse()`、`void setBypass(boolean req, boolean res)`（触发 `invalidate()`）
- `FacadeResolver`：`EncryptorFacade resolve(String uri)`（内部缓存）、`void invalidate()`

**测试：** 切换 `bypassRequest` 后**同一进程内下一次读取即为新值**；`setBypass` 后 `resolve` 重新计算（用计数假 factory 断言缓存确实被清）。

### Task 17: `CipherSuite` SPI + `JceCipherSuite`（现有 RSA/AES 下沉）

**Files:** create `.../jose/{CipherSuite,JceCipherSuite}.java`；modify `.../jose/JweCodec.java`（构造期接收套件列表并按 `alg`/`enc` 分派；响应改为手工拼 compact，才能支持 nimbus 不认识的 `enc`）；test `.../jose/JceCipherSuiteTest.java`、modify `.../jose/JweCodecTest.java`

**Interfaces:**
- `CipherSuite`：`Set<String> algorithms()`、`Set<String> encryptionMethods()`、`byte[] unwrapCek(ServerKeyStore, String kid, String alg, byte[] encryptedKey)`、`byte[] aeadDecrypt(String enc, byte[] cek, byte[] iv, byte[] cipherText, byte[] authTag, byte[] aad)`、`byte[] aeadEncrypt(String enc, byte[] cek, byte[] iv, byte[] plaintext, byte[] aad)`、`int keyLength(String enc)`
- `JceCipherSuite`：alg = `RSA-OAEP-256`；enc = `A128GCM`/`A192GCM`/`A256GCM`
- `JweCodec(ServerKeyStore, List<CipherSuite>, Set<String> allowedAlgs, Set<String> allowedEncs)`（保留 3 参构造 = 仅 JCE 套件）；新增 `encryptResponse(..., String enc, ...)` 重载（旧签名按 CEK 长度推断）

**测试：** 用"假套件"（alg=`TEST-ALG`/enc=`TEST-ENC`）装配 `JweCodec` 并能解出该套件生产的报文 ⇒ 证明分派来自套件、白名单不硬编码；`aeadEncrypt/aeadDecrypt` 往返；响应显式 `enc` 生效、不支持的 `enc` ⇒ `ENCRYPT_FAILED`。

### Task 18: `SmCipherSuite` + SM2 密钥类型 + JWKS 国密表示

**Files:** create `.../jose/SmCipherSuite.java`；modify `.../jose/ServerKeyStore.java`（`type: RSA|SM2`）、`.../jose/PublicKeyInfo.java`（`jwk` 支持 `crv=SM2`）；test `.../jose/SmCipherSuiteTest.java`、modify `.../jose/ServerKeyStoreTest.java`

**Interfaces:**
- `SmCipherSuite`：alg = `SM2`（C1C3C2）、enc = `SM4-GCM`；只用 BC 轻量级 API，不注册 Provider
- `ServerKeyStore` 密钥项增加 `type`（缺省 `RSA`）；SM2 私钥 PKCS#8、公钥 SPKI 或裸 64 字节 `x||y`

**测试：** SM2 封装/解封往返（钉住 C1C3C2 排列）；SM4-GCM 往返 + 篡改 tag/密文失败；密钥/长度非法 ⇒ fail-fast；装配 JCE+SM 两套件的端到端解密成功、JWKS 出现 `crv=SM2`。

> **执行顺序**：Task 17、18 必须在 **Task 8（配置 + 自动装配）之前**——T8 的 `allowed-algs/encs` 要包含 `SM2`/`SM4-GCM`，`keys[]` 要带 `type`。

## Phase B — servlet 侧

### Task 7: `EncryptorListener` + `EncryptorFailure` + `StrKit` 正则缓存

**Files:** create `.../audit/{EncryptorListener,EncryptorFailure}.java`；modify `.../kit/StrKit.java`；test `.../audit/EncryptorListenerTest.java`、modify `.../kit/StrKitTest.java`

**Interfaces:** `EncryptorListener`（默认方法全 no-op：`onDecryptSuccess(JweContext)`、`onDecryptFailure(EncryptorFailure, Throwable)`、`onEncryptFailure(EncryptorFailure, Throwable)`）；`StrKit.matches(String regex, String input)` 内部 `ConcurrentHashMap<String,Pattern>` 缓存 + `invalidate()`。

**测试：** 失败路径回调触发且分类正确；同一 `regex` 连续两次 `matches` 复用同一 `Pattern` 实例（用包内可见的 `pattern(String)` 断言）；缓存可失效。

### Task 8: 配置形态 + 自动装配（servlet）

**Files:** modify `encryptor-starters/encryptor-starter/.../{configuration/EncryptorAutoConfiguration.java,config/CryptoConfig.java,config/EncryptorConfig.java,constant/EncryptorConstant.java}`；test `.../config/EncryptorConfigBindingTest.java`

**Interfaces:** 配置项 `encryptor.config.{enable,keys[{kid,private-key,public-key}],active-kid,allowed-algs,allowed-encs,ttl,failure-status,max-request-size,max-response-size,require-encrypted,discovery{enable,path,cache-max-age}}`；新增 core 纯 Java `DefaultProtocol` bean 装配 `ServerKeyStore`/`JweCodec`/`ReplayGuard`/`InMemoryNonceChecker`（两侧自动装配只 `new` 它）；`uri` 级 `crypto-config` 覆盖语义改为"该 uri 只接受哪些 `kid`"。

**测试：** 绑定测试用 `[key]` 括号写法覆盖含 `.` 的正则 key（**Review Focus 3**）；非法密钥 ⇒ 启动抛异常；`allowed-algs` 覆盖生效；启动摘要包含 `kid` 列表与公钥指纹。

**完成条件：** 两侧 autoconfig 不再各写一份算法栈（`grep` 断言无 `new RSA(` / `new AES(` 在 autoconfig 内）。

### Task 9: 请求过滤器（servlet）

**Files:** modify `encryptor-starters/encryptor-web-starter/.../filter/{EncryptorWebFilter,EncryptorSkipFilter}.java`、`.../converter/*`；test `.../filter/EncryptorWebFilterTest.java`

**行为：** 三个载体统一取 `jwe`（query / `application/json` body `{"jwe":…}` / form 字段）→ `JweCodec.decryptRequest` → 明文作为参数/body 交给后续链；**明文 body 不再被无脑包装**；`require-encrypted=true` 且无合法 `jwe` ⇒ `failure-status`；`max-request-size` 超限 ⇒ **413**；空 body / `Content-Length` 不符 / chunked 一律 400 或 413，**不 NPE**。

**测试（含 Review Focus 2）：** 正常 GET、JSON body、form（含 `;charset=UTF-8`）三条通路；缺 `jwe` ⇒ 400 且**不进业务链**；超 `max-request-size` ⇒ 413；空 body ⇒ 400。

### Task 10: 响应过滤器（servlet）

**Files:** modify `.../filter/EncryptorResponseFilter.java`；test `.../filter/EncryptorResponseFilterTest.java`

**行为：** **仅当**本请求协商到 `cek` **且**响应方向未被 `bypass.response`/skip 名单/content-type 命中时才包装；`max-response-size`（默认 4MiB）超限 ⇒ 500 + `logger.warn`（不静默、不发明文）。

**测试（含 Review Focus 1）：** 明文请求的响应**不**被加密；`text/event-stream` 与下载类 content-type **不被整段缓冲**（断言未读取/未替换 body）；超限 ⇒ 500 且有日志。

### Task 11: JWKS 发现端点（web）

**Files:** create `encryptor-starters/encryptor-web-starter/.../discovery/{JwksEndpoint,JwksProperties}.java`（或在 `EncryptorWebFilter` 前置处理）；test `.../discovery/JwksEndpointTest.java`

**行为：** `GET ${discovery.path}`（默认 `/.well-known/encryptor-keys`）→ `{"keys":[{kty,use,alg,kid,n,e}],"activeKid":…}`；**自身免加密**（请求侧不要求 `jwe`、响应不加密，且不参与 `require-encrypted`）；`Cache-Control: public, max-age=…` + `ETag`（`If-None-Match` ⇒ 304）；`discovery.enable=false` ⇒ 路径不存在（放行给业务）。

**测试：** 无 `jwe` 也能 200；响应体**不含 `d`**；ETag 生效（304）；关闭后 404/交给业务；上游换了 `active-kid` 后响应里的 `activeKid` 跟着变。

## Phase C — gateway 侧与性能

### Task 12: gateway 对齐

**Files:** modify `encryptor-starters/encryptor-starter-reactive/.../{configuration/EncryptorReactiveAutoConfiguration.java,reactive/config/*}`、`encryptor-starters/encryptor-gateway-starter/.../filter/rewrite/{EncryptorGatewayFilter,EncryptorResponseFilter}.java`、`.../config/GatewayEncryptorConfig.java`、`.../converter/*`

**行为：** reactive 侧装配**同一份 core**（`DefaultProtocol`），不再自写算法栈；`max-request-size` **真正生效**并兜 `DataBufferLimitException` → 413（不是 500）；密码学运算跑在**专用有界执行器**（固定 = CPU 核数、有界队列、拒绝 ⇒ `failure-status`）；`MessageReader/Writer` 的 `contentType → class` 映射在**构造期预计算**；请求/响应两侧的 skip 语义与 servlet **一致**。

**测试：** 与 T9/T10 对齐的用例各一条（缺 `jwe` ⇒ 400、超限 ⇒ 413、content-type skip 语义两侧一致），以及"响应只包装一次"（避免重复加密）。

### Task 13: 网关 JWKS 端点

**Files:** modify `.../filter/*`（新增 discovery 处理）；test `.../discovery/GatewayJwksTest.java`

**行为：** 网关**自己**响应 `discovery.path`，**不转发下游**。

**测试：** 断言下游（mock route）**没有**收到该路径的请求；响应体与 servlet 侧同形。

### Task 14: `encryptor-bench`（JMH）

**Files:** create `encryptor-bench/pom.xml`、`encryptor-bench/src/main/java/.../RsaParallelBenchmark.java`、`.../E2eBenchmark.java`；根 `pom.xml` 的 `all-modules` profile 加模块（`main-module` **不加**）；CI 加阈值检查脚本

**测试/断言：** 4 线程吞吐 ≥ 2.5× 单线程（守住"RSA 单锁串行"不复发，**Review Focus 4**）；`bytes/op` 不超基线 +10%（硬件无关，可进 CI）；停机记录 P50/P99 到 `target/bench.json`。

## Phase D — 示例、前端与文档

### Task 15: JS 客户端（WebCrypto）+ 示例改造

**Files:** create `encryptor-examples/web-example/front/encryptor/jwe.js`、`encryptor-examples/gateway-example/gateway/front/encryptor/jwe.js`；modify 两处 `front/index.js`、`front/test.js`；delete 两处 `front/encryptor/{md5withaes.signature.js,aes.js,rsa.js,random.js}`；modify 两个 `front/package.json`（删 `crypto-js`、`node-forge`，`axios`/`qs` 保留）

**接口（两处一致）：** `encrypt(plaintext: string, keys: {kid, publicKeyJwk}) : Promise<string>`、`decrypt(jwe: string, cek: Uint8Array) : Promise<string>`、`fetchKeys(url)`（`kid → jwk`，带 `activeKid`，进程内缓存 + 首次 400 刷新重试一次）。

**行为：** CEK/IV/nonce 用 `crypto.getRandomValues`（**每请求新值**）；protected header 用 `claims` 同构（`uri`/`m`/`dir`/`ts`/`nonce`）；`ts` 毫秒。

**测试：** `node front/test.js` 对本地服务跑通 GET/POST/form/JWKS 四条；断言解回的明文含预期内容；断言 JS 生成的 JWE 能被 Java 侧解开（互操作）。

### Task 16: 示例配置、HttpTest、文档与残留清理

**Files:** modify 两个示例 `application.yml`、`encryptor-examples/web-example/src/test/**/HttpTest.java`、`encryptor-examples/gateway-example/gateway/src/test/**/HttpTest.java`、`README.md`、`AGENTS.md`、`docs/architecture/*.md`；delete `pojo/EncryptorDataWrapper.java` 等 T1 列出的 v1 类与其测试

**行为/断言：**
- 两个 `HttpTest` 改为构造/校验 JWE（不再拼 5 字段），保持"200 + 解出明文含预期内容"。
- `README.md`：特性表去掉 gzip 类不实声明，写清**承诺 = 机密性 + 防篡改**、**不承诺 = 防伪造**、`https://` 或 `localhost` 要求、轮换 SOP、新配置样例。
- `AGENTS.md` / `docs/architecture/*`：双写表、已知问题、P0–P3 与 S1–S17 逐条标注"新协议已消除 / 仍未消除"。
- **残留检查（必须全 0 命中）：** `grep -rn "EncryptorDataWrapper\|AES_K\|md5withaes\|DigestWithEncryptSigner\|GroupEncryptor\|HexEncoder" --include=*.{java,js,yml,md} .`
- 收尾：`mvn -Pall-modules clean install` 全绿；起 web-example 与 gateway-example 做一次真实端到端（网关下游用 `gateway-example/web`）。
