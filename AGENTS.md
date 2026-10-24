# AGENTS.md

本文件是给 AI 编码助手（以及新同学）的入口说明，只放"每次都要知道的**限定**"。完整架构文档在 `docs/architecture/`；依赖/框架版本锚点以根 `pom.xml` 与 `encryptor-dependencies`（BOM）为准，**本文件不复制任何会随开发变化的数字**；逐轮修复明细见 git log 与 `CHANGELOG.md`。

## 这是什么

`encryptor-starter`：一套**报文层安全**的 Spring Boot Starter（v2 协议，对齐 JOSE/JWE RFC 7516）。客户端用服务端公钥封装一把每请求新生成的 CEK——RSA-OAEP-256、国密 SM2，或 ECDH-ES（P-256 直接密钥协商）——业务数据用 AES-GCM（或 SM4-GCM）加密；服务端验上下文/防重放、解密、处理、再用同一 CEK 把响应回加密（`alg=dir`）。国密能力在**可选模块 `encryptor-sm`**，core/starter 本身不依赖 BouncyCastle。

- 语言/构建：javax 线 **Java 8** + Maven 多模块；boot3 线（`-Pboot3`）**Java 17 + Boot 3.x 代际**（`-boot3` 后缀 jakarta 复制对）。
- groupId `io.github.cuukenn`；javax 线与 boot3 线是**自管版本的两条发布线**，成对发布（见下「双线发布」）。
- ⚠️ **自动装配双注册**：每个 starter 同时保留 `spring.factories`（Boot < 2.7 兜底）与 `AutoConfiguration.imports`（Boot ≥ 2.7），指向同一装配类。**删除 `spring.factories` 前必须先决定放弃 Boot < 2.7**，且各 starter（含 micrometer）同步。**boot3 复制模块只保留 `imports`**（复制时删除 spring.factories 是 diff 守卫的登记豁免）。

## 安全边界（必须记住）

- **承诺**：机密性 + 完整性（AEAD 内建）+ 现代算法 + 密钥轮换（kid/JWKS）。
- **不承诺**：客户端身份认证/防伪造。认证交给 TLS + Spring Security——公钥公开、任何人可构造合法报文，是设计内 non-goal。
- 不是 TLS 的替代；客户端需 WebCrypto（浏览器 https/localhost，Node ≥16）。

## 构建与验证

```bash
mvn -B -Pall-modules clean install     # 全量（含 examples + JMH bench）
mvn -B -Pmain-module clean install     # dependencies/core/starters
mvn -B -Pboot3 clean install           # boot3 线（reactor 不含 core，需先 install 过 javax 线制品）
mvn -pl encryptor-core test            # 单模块（先 install 过 core 才能编下游）
java -jar encryptor-bench/target/bench.jar -wi 2 -i 3 -f 1 -prof gc -rf json -rff encryptor-bench/target/bench.json && encryptor-bench/check-thresholds.sh   # JMH（阈值以脚本为准）
```

- 本机 Maven 在 `/usr/local/maven/`（不在 PATH）；另有 brew 的 Maven 可做交叉验证。⚠️ **改 POM 必须兼容 Maven 3.9+**：`pluginManagement` 里同一插件重复声明在 3.9+ 是硬错误（3.8 仅告警覆盖）——改 POM 后建议双版本各跑一次。
- 根 pom 无 checkstyle/spotless；surefire 版本被 root pom 固定（与 JUnit Platform 组合的假绿坑见 pom 注释），boot3 复制对 pom 各自 pin 自己的版本——**不要**让它们解析到 root 的版本。
- `**/HttpTest.java` 被 surefire 排除（需先起服务）；`examples/*/front/test.js` 同理。surefire 默认 `trimStackTrace=true`，定位失败加 `-DtrimStackTrace=false`。
- **改 core 后必须先 `mvn -pl encryptor-core install -DskipTests`**，下游（reactive/gateway/boot3）编译用本地仓库 jar。
- ⚠️ `-Pmain-module,boot3` 组合激活会把 boot3 的版本属性混进整个 reactor、掀掉 javax 线 BOM 锚点——两个 profile 只能分两条命令先后跑。

## 模块 ↔ artifactId

| 目录 | artifactId | 类型 |
| --- | --- | --- |
| `.` | `encryptor-parent` | pom |
| `encryptor-dependencies/` | `encryptor-dependencies` | pom（BOM，**独立 POM，无 parent**） |
| `encryptor-core/` | `encryptor-core` | jar（零 BouncyCastle / 零 Spring） |
| `encryptor-sm/` | `encryptor-sm` | jar（**可选**：SM2/SM4-GCM + BouncyCastle，用户显式添加） |
| `encryptor-starters/` | `encryptor-starters` | pom |
| `encryptor-starters/encryptor-starter/` | `encryptor-spring-boot-starter` | jar |
| `encryptor-starters/encryptor-starter-reactive/` | `encryptor-spring-boot-starter-reactive` | jar |
| `encryptor-starters/encryptor-web-starter/` | `encryptor-web-spring-boot-starter` | jar |
| `encryptor-starters/encryptor-gateway-starter/` | `encryptor-gateway-spring-boot-starter` | jar |
| `encryptor-starters/encryptor-micrometer-starter/` | `encryptor-micrometer-spring-boot-starter` | jar（可选：Micrometer 指标适配） |
| `encryptor-starters/encryptor-spring-boot3-starter/` | `encryptor-spring-boot3-starter` | jar（boot3 线：jakarta 复制对，自管版本，仅 `-Pboot3`） |
| `encryptor-starters/encryptor-web-boot3-starter/` | `encryptor-web-boot3-starter` | jar（boot3 线：web 复制对） |
| `encryptor-starters/encryptor-gateway-boot3-starter/` | `encryptor-gateway-boot3-starter` | jar（boot3 线：gateway 复制对） |
| `encryptor-examples/web-example/` | `web-example` | jar |
| `encryptor-examples/gateway-example/gateway/` | `gateway-example` | jar |
| `encryptor-examples/gateway-example/web/` | `gateway-example-web` | jar（普通下游，**不引入 encryptor**） |
| `encryptor-examples/boot3-example/` | `boot3-gateway-example` | jar（boot3 线示例，**不发布**） |
| `encryptor-bench/` | `encryptor-bench` | jar（JMH，仅 all-modules，**不随发布**） |

## 依赖方向（只允许向下）

```text
encryptor-dependencies (BOM: nimbus/bouncycastle 版本在此)
        │  import
encryptor-core            ← JWE 编解码/密钥库/防重放/协议栈（无 Spring 上下文，零 BC）
        ├── encryptor-sm ┈┈ optional ┈┈ SM2/SM4-GCM（唯一依赖 BC 的制品；不被任何 starter 传递）
        ├── encryptor-spring-boot-starter ──── encryptor-web-spring-boot-starter   (servlet)
        └── encryptor-spring-boot-starter-reactive ── encryptor-gateway-spring-boot-starter (reactive)
                                                        └── encryptor-examples（示例显式添加 encryptor-sm）

gateway-starter ┈┈ optional ┈┈ encryptor-micrometer-spring-boot-starter
        （可选模块：core + micrometer-core；servlet 应用引它不会被拖进 Spring Cloud Gateway）

boot3 分叉（锚点在 root profile 属性；boot3 模块 pom 的 BOM import 一律经
`encryptor.javax.line.version` property 引用 javax 线制品，禁止字面量）：
encryptor-core（单份共享，boot3 线从 ~/.m2 解析同名 jar——reactive/micrometer 无 -boot3 副本）
        ├── encryptor-spring-boot3-starter ── encryptor-web-boot3-starter
        └── encryptor-gateway-boot3-starter ── encryptor-examples/boot3-example（不发布）
```

## 核心数据流（v2）

```text
客户端: CEK=CSPRNG(32B) → JWE{alg=RSA-OAEP-256|ECDH-ES|SM2, enc=A256GCM|SM4-GCM, kid, ts, nonce, uri, m, dir=req}
        ECDH-ES: 临时 P-256 密钥对 + epk(header) → Z → Concat-KDF(SHA-256) 派生 CEK，encrypted_key 段为空
        载体三选一: ?jwe=<compact> | {"jwe":"<compact>"} | form jwe=<compact>
        （载体编解码口径单点在 core kit/CarrierKit：form 语义解码 + URI 形态编码）

服务端 (servlet filter / gateway GlobalFilter):
   ├─ skip 名单/bypass/content-type 跳过判定（机制单点在 core config/base/SkipListsConfigBase）
   ├─ 取 jwe 载体 → protocol.openRequest(compact, uri, method)
   │     ├─ JweCodec: 白名单 → 套件 unwrapCek → AEAD 解密(tag+AAD 校验)
   │     └─ ReplayGuard: ttl 时间窗 + nonce 消费(必须在 tag 校验之后)
   ├─ uri 级 kid 白名单(crypto-config / routes，合并查找单点 core config/base/RouteRule)
   └─ 响应: codec().encryptResponse(body, 同一CEK, dir=res) → {"jwe":"<compact>"}
```

协议定义见 `docs/superpowers/specs/2026-10-16-payload-security-protocol-design.md`（含 §3.11 演进通道）。

## 按任务路由：先读哪个文件

| 你要做的事 | 先读 |
| --- | --- |
| 改 JWE 编解码/AAD/防重放/密钥库/协议默认栈 | `encryptor-core/.../jose/`、`protocol/` |
| 改 skip 名单机制 / alias / 不可命中告警 | core `config/base/SkipListsConfigBase`（两侧配置类只继承，不改名单逻辑） |
| 改载体编解码（QUERY/FORM 语义、jwe 提取） | core `kit/CarrierKit`（两侧门面只做 I/O 装配） |
| 改 per-route 策略（crypto-config/routes） | core `config/base/RouteRule`（`effectiveKids` 合并查找单点；**键结构已固定，扩展只加字段**） |
| 改 servlet 侧过滤器链/失败面/JWKS 端点 | `encryptor-web-starter/.../filter/`、`discovery/` |
| 改网关链路/有界执行器/响应改写/JWKS | `encryptor-gateway-starter/.../gateway/` |
| 改通用配置模型/自动装配/启动摘要 | core `config/base/EncryptorConfigBase` + 两侧 `EncryptorAutoConfiguration` / `config/EncryptorConfig`（只保留前缀） |
| 改指标/监听器适配（可选） | `encryptor-micrometer-starter/.../micrometer/`（读 `EncryptorListener` SPI + `CryptoExecutor`） |
| 改默认算法组合/加 CipherSuite | core `.../jose/`（SPI + JceCipherSuite/EcCipherSuite + ConcatKdf；`META-INF/services` 注册） |
| 改国密 SM2/SM4-GCM 或 BC 相关解析 | `encryptor-sm/.../sm/`（`SmCipherSuite` + `SmKeyEntryParser`；**core 不得出现 `org.bouncycastle`**） |
| 跑起来验证/改示例/前端 JS | `encryptor-examples/`（front/encryptor/jwe.js 是 JS 客户端参考实现） |
| 性能回归 | `encryptor-bench/` + `check-thresholds.sh` |

需要多步任务时，先用 `.opencode/skills/encryptor-starter-development/SKILL.md` 里的同步清单自检。

## 必须同步修改的地方（v2 双写面）

协议/行为变更时，以下**成对**文件必须同改（否则"servlet 正常、网关失败"）：

| servlet 侧 | reactive/gateway 侧 |
| --- | --- |
| `encryptor-starter/.../configuration/EncryptorAutoConfiguration.java` | `encryptor-starter-reactive/.../reactive/configuration/EncryptorReactiveAutoConfiguration.java` |
| `encryptor-starter/.../config/EncryptorConfig.java`（只保留 `PREFIX`；字段/默认值继承 core `EncryptorConfigBase`，三件套同） | `encryptor-starter-reactive/.../reactive/config/EncryptorConfig.java`（同，只差 `PREFIX`） |
| `encryptor-web-starter/.../filter/*`、`.../discovery/JwksEndpointFilter` | `encryptor-gateway-starter/.../gateway/filter/*`、`.../discovery/JwksEndpointFilter` |
| `encryptor-starter/.../constant/EncryptorConstant.java`（`JWE_PARAM`/`TRACE_HEADER`） | `encryptor-starter-reactive/.../reactive/constant/EncryptorConstant.java`（同名同值，CI parity 守卫） |
| `encryptor-web-starter/.../config/WebEncryptorConfig.java`（**模块特有字段**；skip 机制在 core base，无需双写） | `encryptor-gateway-starter/.../config/GatewayEncryptorConfig.java`（同） |
| `encryptor-web-starter/src/test/.../SmJweTestSupport.java` | `encryptor-gateway-starter/src/test/.../SmGatewayTestSupport.java`（成对副本） |
| `encryptor-web-starter/src/test/.../filter/ResponseFilterHardeningTest.java` | `encryptor-gateway-starter/src/test/.../filter/GatewayJweTest.java`（同名用例族） |
| `encryptor-web-starter/src/test/.../configuration/FilterOrderValidationTest.java`（链序契约） | `encryptor-gateway-starter/src/test/.../configuration/GatewayEncryptorConfigurationTest.java`（同构用例族） |
| `encryptor-examples/web-example/front/encryptor/jwe.js` | `encryptor-examples/gateway-example/gateway/front/encryptor/jwe.js` |
| `encryptor-examples/web-example/src/main/resources/application.yml`（EC/SM2 演示密钥 + 白名单） | `encryptor-examples/gateway-example/gateway/src/main/resources/application.yml` |

**协议变更（JWE 头字段、AAD claims、载体字段名 `jwe`、`kid` 语义）还要同步：** 各示例的 `HttpTest.java`、各份 front `jwe.js`（web / gateway / boot3-example，CI pairwise diff）、设计文档。演进通道限定见「坑 11」。

### boot3 复制对（`scripts/javax-to-jakarta.sh --diff`，CI 守卫）

javax 线源码经脚本机械替换（`javax.servlet` → `jakarta.servlet`）后必须与 boot3 模块**逐字节一致**；三对复制对（starter / web / gateway）在 CI 逐对比对：

- web/starter 对**零源码豁免**；gateway 对登记了少量 API 签名适配豁免文件（`getMethodValue()`/`getStatusCode()` 代际差异，清单=ci.yml 的 `--expect-diff`）——豁免文件不参与红/绿判定，属**人审面**（CI 日志有 `EXEMPT-FILES-INSPECT` 标记）。
- 登记口径：`--expect-diff` pattern 以 `main/java/...` 起头（带 `src/` 前缀恒不命中）；pom 与 `spring.factories` 差异默认豁免；keyed `--exclude spring.factories` 同时断言 boot3 侧不得重新引入 spring.factories。
- 改 javax 线任一复制对源文件 = 必须同步 boot3 对位；改协议 = javax servlet / reactive 共享线 / boot3 复制线三处一起。
- reactive / micrometer **无 boot3 副本**（main 源码零 `javax.*`，Boot 3.5 直接复用 javax 线 jar）——改动同时进两线，测试面在 `encryptor-examples/boot3-example`。

## 配置前缀一览

| 场景 | 前缀 |
| --- | --- |
| 通用（servlet） | `encryptor.config.*` |
| 通用（reactive） | `encryptor.config.reactive.*` |
| web（skip 名单/kid 白名单/routes/order） | `encryptor.config.web.*` |
| gateway（skip 名单/开关/order/routes/crypto-executor） | `encryptor.config.reactive.gateway.*`（failure-status/上限在 reactive 通用段） |

## 双线发布（必须成对）

- root pom 的 `encryptor.javax.line.version` property = javax 线版本，**发版时与 `project.version` 同步 bump**；boot3 模块 pom 的 BOM/core 引用一律经该 property（禁止字面量）。
- `scripts/check-dual-line-versions.sh`（CI 已接）断言三者一致——防"core 修复漏发 boot3 线"。
- CHANGELOG 顶部有双线成对发布约定；两线条目成对标注。

## 硬性限定（坑清单——违反即坏，按主题归组）

**协议面**
1. 🟩 v1 协议已全部删除，残留 grep 必须 0 命中：`EncryptorDataWrapper|AES_K|md5withaes|DigestWithEncryptSigner|GroupEncryptor|HexEncoder`。
2. ECDH-ES：`encrypted_key` 段**为空**（`header..iv.ct.tag`）；`epk` 属 protected header **参与 AAD**（改 epk 解析口径=改 AAD）；只支持 **P-256**；`apu`/`apv` 存在时必须进 Concat-KDF OtherInfo；共享秘密 Z 左补零到 32 字节再派生。
3. `ReplayGuard.verify` 必须在 **AEAD tag 校验之后**调用（未认证输入不得污染 nonce 存储）；`InMemoryNonceStore` 的 retention ≥ 2·ttl 在构造期强制。
4. AAD 的 uri 输入口径**两侧有意不同**：servlet 用原始 `requestURI`（兼容百分号编码路径/不预归一化客户端），网关用 `canonicalPath` 折叠形（`..`/`//`/`%2E%2E` 折叠——防 uri 级白名单绕过）。改任一侧前先想清楚这个差异是有意的。
5. `JweContext.destroy()` 之后 `cek()`/`plaintext()` 抛 `IllegalStateException`（全零是合法 AES 密钥，不得静默返回）。
6. 协议演进通道**唯一**：additive claim + 服务端软接受；`crit` 一律 fail-closed 拒绝（不作演进通道）；`typ` 是软版本锚点（`JweCodec.PROTOCOL_TYPE`，未知值记 INFO 不拒绝）——详见设计文档 §3.11。

**实现面**
7. `Cipher` 非线程安全：每次新建，**不要**缓存单例；`CipherSuite.pairsWith` 默认 true，KDF 型套件必须覆写。
8. nimbus：`Base64URL` 无 `decode(String)` → 用 `java.util.Base64.getUrlDecoder()`；parse base64url 段用 `JWEHeader.parse(new Base64URL(...))`。
9. BC 隔离：SM 路径只用 BC 轻量级 API、不注册全局 Provider；`encryptor-sm` 是唯一允许 BC 的制品；core（main/test）与各 starter main 源码零 `org.bouncycastle`（starter 的 SM 集成测试可用 test scope 的 sm/bcprov）；没有 encryptor-sm 时配置 SM2 密钥必须启动期失败并提示。enforcer 禁止 `*-jdk15on`（防双 BC 血统），依赖树守卫保持为空。
10. 网关下游必须是**不带 encryptor 的普通应用**（网关转发的已是明文，下游再解一次 → 400）。
11. QUERY 载体契约：明文是 **form 语义** urlencoded 文本（`+`=空格）且**即完整 query**（jwe 外的原始参数被丢弃）；jwe 出现在 query string 上一律按 QUERY 载体（`getParameter` 会合并 query 与 form）。编解码只走 core `CarrierKit`，两侧不得再写本地实现。
12. skip content-type 名单按 **media-type 段**（剥 `;` 参数、小写归一）整串正则匹配；含大写或 `;` 的配置条目启动 WARN（永不命中提示）。
13. 过滤器 order 全部可配，但**相对链序启动期校验**（servlet：jwks < 门面 < 参数 < 请求体 < 响应；网关：jwks < 请求、响应 < NettyWriteResponseFilter）——顺序错=启动失败而非静默明文。参数过滤器的 finally 清 WebContext，响应过滤器必须嵌其内（加密路径经所有权移交豁免）。
14. 审计口径：codec 内失败由 `JweCodec` 回调；codec 外失败分支（缺载体/超限/kid 白名单/执行器拒绝/非法 query/响应侧失败出口）由两侧过滤器补发——**不得双计**。`EncryptorListener` 全 default 方法（加回调零破坏，是本库 API 演进的范本模式）。
15. `EncryptorRuntime` bean 必须与 `protocol.runtime()` 同一实例（启动期身份校验；用户覆盖同类型 bean 会 fail-fast）。
16. servlet 请求体包装器 `setReadListener` 抛 `UnsupportedOperationException`（明文在内存，非阻塞读会静默挂死）；异步周期**必须可终止**（`setTimeout(0)` 且永不 complete 时 CEK/明文滞留到 GC，Servlet 模型固有，无 per-request 兜底）。
17. 网关 `CryptoExecutor` 队列深度不能读 Reactor 的 `Scannable.Attr.BUFFERED`（任务派进执行器内部队列后不可见，恒 0）——`pendingTasks()` 是自记账（先读 completed 再读 submitted，防 gauge 瞬时负值）。Reactor 的 `Scheduler` 只 extends Disposable，覆写 `scanUnsafe` 编译失败。
18. micrometer 的 `EncryptorMicrometerAutoConfiguration` 必须 `@AutoConfigureAfter` 网关装配（`@ConditionalOnBean(CryptoExecutor)` 在 spring.factories 双注册场景下对排序敏感，否则指标静默不注册）。
19. 流式响应（SSE/下载）不包装（skip 名单判定后再加密）；内存 nonce 存储启动 WARN（多实例重放窗口，单实例可忽略）。

**构建/验证面**
20. 含 `.` 的 uri 正则 config key 必须**整体**包在括号里（`"[/test/ec.*]"`）；括号不能嵌套；正则**整串匹配**。black-* 旧名 alias 机制在 core `SkipListsConfigBase`（新旧名单不能共用同一个 list——Spring 就地绑定会互清）。
21. 示例测试源码必须能编过 JDK 8（`URLEncoder.encode(String, Charset)` 是 Java 10+，用 `(s, "UTF-8")` 包一层）；两份 `HttpTest.java` 是成对文件。
22. `bench.jar`：`EcdhEsBenchmark` 必须显式传 `allowedAlgs={ECDH-ES}`；JMH setup 失败只打日志、**exit code 仍 0**——必须看 `check-thresholds.sh` 输出。JMH 阈值脚本**故意不进 CI**（共享 runner 噪声大）；阈值与基准数字以脚本和 README 为准。

## 约定

- 注释/Javadoc 用中文，类头保留 `@author changgg`。
- 配置类：`@ConfigurationProperties` + getter/setter（不用 Lombok，Java 8）；**共享机制一律下沉 core `config/base` 继承**（EncryptorConfigBase / SkipListsConfigBase / RouteRule 三个先例），两侧只留前缀与模块特有字段。
- 自动装配：`@Configuration(proxyBeanMethods = false)` + 条件注解；非法配置启动期 fail-fast + 生效摘要日志。
- core 里**不要新增** Spring 依赖。
- 改完至少跑 `mvn -B -Pmain-module clean install`；改 examples/前端后跑 `-Pall-modules`；改 POM 后双 Maven 版本各跑一次。

## CI 与守卫（清单，数字以 CI 为准）

`.github/workflows/ci.yml`（JDK 矩阵与 profile 以文件为准）执行：双线构建测试、三对 boot3 复制对 diff 守卫、jwe.js 三份 pairwise、`EncryptorConstant` 逐字节 parity、servlet↔reactive 结构 parity（常量值/skip-base 继承/装配 bean 面）、双线版本同步守卫、BC 依赖树守卫（javax 与 boot3 两档）、守卫脚本自测。`publish.yml` 只发 javax 线；boot3 发布面结论见 `docs/architecture/open-issues-v2-history.md`。端到端（HttpTest / front/test.js / 双 BC 客户端）为手动验证：先起示例服务（端口见各示例 `application.yml`），历史基线结论见 git log。
