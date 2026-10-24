---
name: encryptor-starter-development
description: Use when touching ANY code, config, pom, docs, or tests in this repository (encryptor-starter, a JWE payload-security Spring Boot Starter family). Carries the full architecture map - modules, dependency direction, v2 data flow, task routing, the paired-file sync lists (servlet vs reactive, javax vs boot3 copy pairs), build/verify commands, CI guards, and the complete hard-constraint catalog. Read before editing anything.
---

# encryptor-starter 开发导航（v2 / JWE 协议）

报文层安全（机密性 + 防篡改）的 Spring Boot Starter 家族，协议对齐 JOSE/JWE（RFC 7516）。本 skill 是**架构与同步面的唯一聚合入口**：AGENTS.md 只有红线速查，其余都在这里。

> `docs/architecture/*.md` 是 v1 时代记录（已加失效横幅），只用于追溯；协议定义见 `docs/superpowers/specs/2026-10-16-payload-security-protocol-design.md`（§3.11 是演进通道契约）。**本文不写会变化的数字**（测试计数/基准/版本清单）——以 pom / 脚本 / CI 为准；历史明细见 git log 与 CHANGELOG。

## 构建与验证

```bash
mvn -B -Pmain-module clean install     # dependencies/core/starters（最低限度）
mvn -B -Pall-modules clean install     # 全量（含 examples + JMH bench）
mvn -B -Pboot3 clean install           # boot3 线（reactor 不含 core，需先 install 过 javax 线制品）
mvn -pl encryptor-core test            # 单模块（改 core 后先 install -DskipTests，下游编译用本地仓库 jar）
java -jar encryptor-bench/target/bench.jar -wi 2 -i 3 -f 1 -prof gc -rf json -rff encryptor-bench/target/bench.json && encryptor-bench/check-thresholds.sh   # JMH（阈值以脚本为准）
```

- 本机 Maven 在 `/usr/local/maven/`（不在 PATH）；brew 的 Maven 可做交叉验证。**改 POM 必须兼容 Maven 3.9+**（pluginManagement 重复声明 = 硬错误），改后双版本各跑一次。
- 根 pom 无 checkstyle/spotless；surefire 版本被 root pom 固定（与 JUnit Platform 组合的假绿坑见 pom 注释），boot3 复制对 pom 各自 pin——不要解析到 root 的版本。
- `**/HttpTest.java` 被 surefire 排除；`examples/*/front/test.js` 同理（都要先起服务，端口见各示例 `application.yml`）。surefire 默认 `trimStackTrace=true`，定位失败加 `-DtrimStackTrace=false`。
- ⚠️ `-Pmain-module,boot3` 组合激活会把 boot3 版本属性混进整个 reactor——**两条命令分先后跑**。
- 示例测试源码必须编过 JDK 8（`URLEncoder.encode(String, Charset)` 是 Java 10+，用 `(s, "UTF-8")`）。

## 模块 ↔ artifactId

| 目录 | artifactId | 类型 |
| --- | --- | --- |
| `encryptor-dependencies/` | `encryptor-dependencies` | pom（BOM，**独立 POM 无 parent**；nimbus/BC 版本锚点） |
| `encryptor-core/` | `encryptor-core` | jar（零 BouncyCastle / 零 Spring） |
| `encryptor-sm/` | `encryptor-sm` | jar（**可选**：SM2/SM4-GCM + BC，用户显式添加） |
| `encryptor-starters/encryptor-starter/` | `encryptor-spring-boot-starter` | jar |
| `encryptor-starters/encryptor-starter-reactive/` | `encryptor-spring-boot-starter-reactive` | jar |
| `encryptor-starters/encryptor-web-starter/` | `encryptor-web-spring-boot-starter` | jar |
| `encryptor-starters/encryptor-gateway-starter/` | `encryptor-gateway-spring-boot-starter` | jar |
| `encryptor-starters/encryptor-micrometer-starter/` | `encryptor-micrometer-spring-boot-starter` | jar（可选指标适配） |
| `encryptor-starters/encryptor-spring-boot3-starter/` 等 `-boot3-starter` | 同名 `-boot3` | jar（jakarta 复制对，自管版本，仅 `-Pboot3`） |
| `encryptor-examples/web-example/`、`gateway-example/{gateway,web}/` | 示例 | jar（`gateway-example/web` 是**不带 encryptor 的普通下游**） |
| `encryptor-examples/boot3-example/` | boot3 示例 | jar（不发布） |
| `encryptor-bench/` | `encryptor-bench` | jar（JMH，不随发布） |

## 依赖方向（只允许向下）

```text
encryptor-dependencies (BOM)
        │  import
encryptor-core            ← JWE 编解码/密钥库/防重放/协议栈（无 Spring 上下文，零 BC）
        ├── encryptor-sm ┈┈ optional ┈┈ SM2/SM4-GCM（唯一依赖 BC 的制品；不被任何 starter 传递）
        ├── encryptor-spring-boot-starter ──── encryptor-web-spring-boot-starter   (servlet)
        └── encryptor-spring-boot-starter-reactive ── encryptor-gateway-spring-boot-starter (reactive)
                                                        └── encryptor-examples（示例显式添加 encryptor-sm）
gateway-starter ┈┈ optional ┈┈ encryptor-micrometer-spring-boot-starter（core + micrometer-core）

boot3 分叉（锚点在 root profile 属性；boot3 pom 的 BOM import 一律经 `encryptor.javax.line.version`
property 引用 javax 线制品，禁止字面量）：
encryptor-core（单份共享，boot3 线从 ~/.m2 解析——reactive/micrometer 无 -boot3 副本，
Boot 3.x 下直接复用 javax 线 jar）
        ├── encryptor-spring-boot3-starter ── encryptor-web-boot3-starter
        └── encryptor-gateway-boot3-starter ── encryptor-examples/boot3-example（不发布）
```

**自动装配双注册**：各 starter 同时保留 `spring.factories`（Boot < 2.7 兜底）与 `AutoConfiguration.imports`（≥ 2.7），指向同一装配类；删除 spring.factories 前必须先决定放弃 Boot < 2.7 且各 starter（含 micrometer）同步。boot3 复制模块只保留 imports。

## 核心数据流（v2）

```text
客户端: CEK=CSPRNG(32B) → JWE{alg=RSA-OAEP-256|ECDH-ES|SM2, enc=A256GCM|SM4-GCM, kid, ts, nonce, uri, m, dir=req}
        ECDH-ES: 临时 P-256 密钥对 + epk(header) → Z → Concat-KDF(SHA-256) 派生 CEK，encrypted_key 段为空
        载体三选一: ?jwe=<compact> | {"jwe":"<compact>"} | form jwe=<compact>（编解码单点 core kit/CarrierKit）

服务端 (servlet filter / gateway GlobalFilter):
   ├─ skip 名单/bypass/content-type 跳过判定（机制单点 core config/base/SkipListsConfigBase）
   ├─ 取 jwe 载体 → protocol.openRequest(compact, uri, method)
   │     ├─ JweCodec: 白名单 → 套件 unwrapCek → AEAD 解密(tag+AAD 校验)
   │     └─ ReplayGuard: ttl 时间窗 + nonce 消费(必须在 tag 校验之后)
   ├─ uri 级 kid 白名单(crypto-config / routes，合并查找单点 core config/base/RouteRule)
   └─ 响应: codec().encryptResponse(body, 同一CEK, dir=res) → {"jwe":"<compact>"}
```

## 任务路由（源码位置）

| 任务 | 打开 |
| --- | --- |
| JWE 编解码 / AAD / 防重放 / 密钥库 / CipherSuite | `encryptor-core/.../jose/`、`protocol/`、`runtime/` |
| 默认协议栈组装（白名单联动/fail-fast） | `encryptor-core/.../protocol/DefaultProtocol.java` |
| skip 名单机制（alias/预编译/告警） | core `config/base/SkipListsConfigBase`（两侧配置类只继承） |
| 载体编解码（QUERY/FORM 语义、jwe 提取） | core `kit/CarrierKit`（两侧门面只做 I/O 装配） |
| per-route 策略（crypto-config/routes） | core `config/base/RouteRule`（`effectiveKids` 合并查找；**键结构已固定**） |
| servlet 过滤器链 / JWKS 端点 | `encryptor-web-starter/.../filter/`、`discovery/` |
| 网关链路 / 有界执行器 / JWKS | `encryptor-gateway-starter/.../gateway/` |
| 通用配置模型 / 自动装配 / 启动摘要 | core `config/base/EncryptorConfigBase` + 两侧 `EncryptorAutoConfiguration` / `config/EncryptorConfig`（只保留前缀，三件套同） |
| 指标/监听器（可选） | `encryptor-micrometer-starter/.../micrometer/`（读 `EncryptorListener` SPI + `CryptoExecutor`） |
| 新增 CipherSuite | core `.../jose/CipherSuite.java` SPI；内置 `JceCipherSuite`/`EcCipherSuite`；国密在 `encryptor-sm/.../sm/`（`META-INF/services` 注册；白名单须同步 `DefaultProtocol`） |
| 示例 / 前端 JS 客户端 | `encryptor-examples/*/front/encryptor/jwe.js`（WebCrypto 参考实现） |
| 性能回归 | `encryptor-bench/` + `check-thresholds.sh`（RSA 并行度、bytes/op 基线、ReplayGuard INFO 行） |

## 成对文件对照表（改一处必改另一处）

| servlet 侧 | reactive/gateway 侧 |
| --- | --- |
| `encryptor-starter/.../configuration/EncryptorAutoConfiguration.java` | `encryptor-starter-reactive/.../reactive/configuration/EncryptorReactiveAutoConfiguration.java` |
| `encryptor-starter/.../config/EncryptorConfig.java`（只留 `PREFIX`，字段继承 core base） | `encryptor-starter-reactive/.../reactive/config/EncryptorConfig.java`（同） |
| `encryptor-web-starter/.../filter/*`、`.../discovery/JwksEndpointFilter` | `encryptor-gateway-starter/.../gateway/filter/*`、`.../discovery/JwksEndpointFilter` |
| `encryptor-starter/.../constant/EncryptorConstant.java`（`JWE_PARAM`/`TRACE_HEADER`） | `encryptor-starter-reactive/.../reactive/constant/EncryptorConstant.java`（同名同值，CI parity 守卫；`GatewayConstant.JWE_PARAM` 也在守卫内） |
| `encryptor-web-starter/.../config/WebEncryptorConfig.java`（**模块特有字段**；skip 机制在 core base 不双写） | `encryptor-gateway-starter/.../config/GatewayEncryptorConfig.java`（同） |
| `encryptor-web-starter/src/test/.../SmJweTestSupport.java` | `encryptor-gateway-starter/src/test/.../SmGatewayTestSupport.java`（成对副本） |
| `encryptor-web-starter/src/test/.../filter/ResponseFilterHardeningTest.java` | `encryptor-gateway-starter/src/test/.../filter/GatewayJweTest.java`（同名用例族） |
| `encryptor-web-starter/src/test/.../configuration/FilterOrderValidationTest.java` | `encryptor-gateway-starter/src/test/.../configuration/GatewayEncryptorConfigurationTest.java`（链序用例族） |
| `encryptor-examples/web-example/front/encryptor/jwe.js` | `encryptor-examples/gateway-example/gateway/front/encryptor/jwe.js`（boot3-example 的第三份，CI pairwise） |
| `encryptor-examples/web-example/src/main/resources/application.yml` | `encryptor-examples/gateway-example/gateway/src/main/resources/application.yml` |

**协议变更（JWE 头字段、AAD claims、载体字段名 `jwe`、`kid` 语义）还要同步**：各示例 `HttpTest.java`、各份 front `jwe.js`、设计文档。

## boot3 复制对（`scripts/javax-to-jakarta.sh --diff`，CI 守卫）

- javax 源码经机械替换（`javax.servlet` → `jakarta.servlet`）后必须与 boot3 模块**逐字节一致**；starter/web 对零源码豁免；gateway 对登记少量 API 适配豁免文件（`getMethodValue()`/`getStatusCode()` 代际差异，清单 = ci.yml 的 `--expect-diff`）——豁免文件不参与红/绿，属**人审面**（CI 日志 `EXEMPT-FILES-INSPECT`）。
- 登记口径：pattern 以 `main/java/...` 起头；pom 与 `spring.factories` 差异默认豁免；`--exclude spring.factories` 同时断言 boot3 侧不得重新引入。
- 改 javax 复制对源文件 = 必须同步 boot3 对位；改协议 = javax servlet / reactive 共享线 / boot3 复制线三处一起。
- reactive / micrometer 无 boot3 副本——改动同时进两线，测试面在 `encryptor-examples/boot3-example`。

## 配置前缀与双线发布

| 场景 | 前缀 |
| --- | --- |
| 通用（servlet） | `encryptor.config.*` |
| 通用（reactive） | `encryptor.config.reactive.*`（failure-status/上限在此段） |
| web | `encryptor.config.web.*`（skip 名单/kid 白名单/routes/order） |
| gateway | `encryptor.config.reactive.gateway.*`（skip/开关/order/routes/crypto-executor） |

双线发布：发版只 bump root 的 `project.version` + `encryptor.javax.line.version`；boot3 pom 的 BOM/core 引用一律走 property（禁字面量）；`scripts/check-dual-line-versions.sh` 守卫；CHANGELOG 顶部有成对发布约定（javax 1.x ⇔ boot3 3.x 同一变更列车）。

## 硬性限定目录（按主题；违反即坏）

**协议面**
1. ECDH-ES：`encrypted_key` 段为空；epk 参与 AAD；只支持 P-256；apu/apv 进 Concat-KDF OtherInfo；Z 左补零 32 字节。
2. AAD 的 uri 输入口径**两侧有意不同**：servlet 用原始 `requestURI`（兼容百分号编码路径），网关用 `canonicalPath` 折叠形（`..`/`//`/`%2E%2E` 折叠防白名单绕过）——改前想清楚差异是有意的。
3. `JweContext.destroy()` 后访问抛 `IllegalStateException`；5 参 `encryptResponse`（按 CEK 长度猜 enc）在装配套件含非 AES-GCM 时拒绝。
4. crit 一律拒绝、typ 软锚点、演进通道 additive-claim-only（设计文档 §3.11）。

**实现面**
5. nimbus：`Base64URL` 无 `decode(String)` → `java.util.Base64.getUrlDecoder()`；parse base64url 段用 `JWEHeader.parse(new Base64URL(...))`。
6. BC 隔离与 SM：`encryptor-sm` 是唯一 BC 制品；SM 只用轻量级 API 不注册 Provider；无 encryptor-sm 时配置 SM2 启动期失败并提示；enforcer 禁 `*-jdk15on`（双 BC 血统），依赖树守卫为空。
7. QUERY/载体契约全部在 core `CarrierKit`（form 语义、明文=完整 query、jwe-in-query→QUERY）；servlet 门面的 `getParameter` 合并 query 与 form——载体判定看 `hasQueryJwe`。
8. skip content-type 按 media-type 段（剥 `;`、小写）整串正则；含大写或 `;` 的条目启动 WARN；black-* alias 机制在 core `SkipListsConfigBase`（新旧名单不能共用同一个 list——Spring 就地绑定互清）。
9. 链序契约：servlet jwks < 门面 < 参数 < 请求体 < 响应；网关 jwks < 请求、响应 < `NettyWriteResponseFilter`；参数过滤器 finally 清 WebContext（响应过滤器必须嵌其内，加密路径经所有权移交豁免）；`EncryptorRuntime` bean 必须与 `protocol.runtime()` 同实例（启动期校验）。
10. 审计不双计（codec 内 JweCodec 回调 / codec 外过滤器补发）；`EncryptorListener` 全 default（加回调零破坏的范本）。
11. servlet 请求体包装器 `setReadListener` 抛 `UnsupportedOperationException`；异步周期必须可终止（`setTimeout(0)` 且永不 complete 时 CEK/明文滞留到 GC，模型固有，无 per-request 兜底）。
12. 网关 `CryptoExecutor`：队列深度不能读 `Scannable.Attr.BUFFERED`（恒 0），`pendingTasks()` 自记账且先读 completed；Reactor 的 `Scheduler` 只 extends Disposable。
13. micrometer 的自动装配必须 `@AutoConfigureAfter` 网关装配（`@ConditionalOnBean(CryptoExecutor)` 对排序敏感，否则指标静默不注册）。
14. 流式响应（SSE/下载）不包装（skip 判定后再加密）；内存 nonce 存储启动 WARN（多实例重放窗口，单实例可忽略）。
15. 含 `.` 的 uri 正则 config key 必须整体括号写法（`"[/test/ec.*]"`，不可嵌套）；正则整串匹配。

**构建/验证面**
16. `bench.jar`：`EcdhEsBenchmark` 必须显式传 `allowedAlgs={ECDH-ES}`；JMH setup 失败只打日志、exit code 仍 0——必须看 `check-thresholds.sh` 输出；JMH 阈值脚本故意不进 CI（共享 runner 噪声）。
17. CI 守卫清单（数字以 CI 为准）：双线构建测试、boot3 复制对 diff、jwe.js pairwise、EncryptorConstant parity、servlet↔reactive 结构 parity（常量值/skip-base 继承/装配 bean 面）、双线版本守卫、BC 依赖树（双档）、守卫脚本自测。`publish.yml` 只发 javax 线；boot3 发布面结论见 `docs/architecture/open-issues-v2-history.md`。

## 动手前自检

- [ ] 我改的是 servlet 侧还是 reactive 侧？成对表里只改一边 = "servlet 正常、网关失败"。
- [ ] 跨协议边界了（claims/载体字段/`kid` 语义/alg/enc）？→ 同步各 HttpTest + 各 jwe.js + 设计文档；演进通道 additive-only。
- [ ] 新增算法：CipherSuite 解决"怎么算"，白名单解决"许不许"（两侧配置默认值联动）。
- [ ] 配置前缀写对（gateway 多一层 `reactive`）；正则括号写法；media-type 段匹配。
- [ ] `Cipher` 不缓存；防重放在 tag 之后；BC 不进 core/starter。
- [ ] 改 core 了？先 `install -DskipTests`。改 POM 了？Maven 3.9+ 兼容 + 双线版本只 bump property。
- [ ] 改完跑 `-Pmain-module`；动了 examples/前端跑 `-Pall-modules`；动了复制对源文件跑 diff 守卫。

## 不要做的事

- 不要在 core 引 Spring；不要"优化"掉每次新建的 Cipher；不要在 tag 校验前消费 nonce。
- 不要给网关下游接 encryptor（转发已是明文，下游再解 → 400）；不要注册 BC 全局 Provider。
- 不要在两侧门面写载体编解码/skip 机制本地实现（单点在 core CarrierKit / SkipListsConfigBase）。
- 不要改 `Map<正则, RouteRule>` 的值类型（扩展只加字段）；不要让 AGENTS.md/skill 出现会变化的数字。
