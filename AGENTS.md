# AGENTS.md

本文件是给 AI 编码助手（以及新同学）的入口说明。**完整架构文档在 `docs/architecture/`**，按模块拆分，本文件只放"每次都要知道"的部分。

## 这是什么

`encryptor-starter`：一套**报文层安全**的 Spring Boot Starter（v2 协议，对齐 JOSE/JWE RFC 7516）。客户端用服务端公钥封装一把每请求新生成的 CEK——RSA-OAEP-256、国密 SM2，或 ECDH-ES（P-256 直接密钥协商）——业务数据用 AES-GCM（或 SM4-GCM）加密；服务端验上下文/防重放、解密、处理、再用同一 CEK 把响应回加密（`alg=dir`）。

- 语言/构建：**Java 8** + Maven 多模块
- 版本：Spring Boot `2.4.2`、Spring Cloud `2020.0.1`、Spring Cloud Alibaba `2021.1`、hutool `5.8.25`、nimbus-jose-jwt `9.37.3`、bcprov/bcpkix `1.78.1`
- groupId：`io.github.cuukenn`，版本 `1.0.0`（发布版；`v1.0.0` 标签已打）
- ⚠️ **Boot 2.4 用的是 `META-INF/spring.factories` 自动装配**，不是 2.7+ 的 `AutoConfiguration.imports`

## 安全边界（必须记住）

- **承诺**：机密性 + 完整性（防篡改，AEAD 内建）+ 现代算法 + 密钥轮换（kid/JWKS）。
- **不承诺**：客户端身份认证/防伪造。认证交给 TLS + Spring Security（JWT/mTLS）——任何人都能拿到公钥构造合法报文，这是设计内的 non-goal。
- 不是 TLS 的替代；客户端需 WebCrypto（浏览器 https/localhost，Node ≥16）。

## 构建与验证

```bash
mvn -B -Pall-modules clean install     # 全量（含 examples + JMH bench 模块声明）
mvn -B -Pmain-module clean install     # 只构建 dependencies/core/starters，跳过 examples
mvn -pl encryptor-core test            # 单模块 + 它的依赖（先 install 过 core 才能编下游）
java -jar encryptor-bench/target/bench.jar -wi 2 -i 3 -f 1 -prof gc -rf json -rff encryptor-bench/target/bench.json && encryptor-bench/check-thresholds.sh   # JMH（RSA 并行度≥2.5x、bytes/op 基线±10%）
```

- Maven 在 **`/usr/local/maven/3.8.9/bin/mvn`**（不在 PATH）；`java` 11。
- 根 `pom.xml` **没有** checkstyle/spotless；surefire 固定 `2.22.2`。
- `**/HttpTest.java` 被 surefire 排除（需先起服务）；`encryptor-examples/*/front/test.js` 也需先起服务。
- surefire 默认 `trimStackTrace=true`，定位失败加 `-DtrimStackTrace=false`。
- **改 reactive/gateway 前必须先 `mvn -pl encryptor-core install -DskipTests`**（下游编译用本地仓库 jar）。

## 模块 ↔ artifactId

| 目录 | artifactId | 类型 |
| --- | --- | --- |
| `.` | `encryptor-parent` | pom |
| `encryptor-dependencies/` | `encryptor-dependencies` | pom（BOM，**独立 POM，无 parent**） |
| `encryptor-core/` | `encryptor-core` | jar |
| `encryptor-starters/` | `encryptor-starters` | pom |
| `encryptor-starters/encryptor-starter/` | `encryptor-spring-boot-starter` | jar |
| `encryptor-starters/encryptor-starter-reactive/` | `encryptor-spring-boot-starter-reactive` | jar |
| `encryptor-starters/encryptor-web-starter/` | `encryptor-web-spring-boot-starter` | jar |
| `encryptor-starters/encryptor-gateway-starter/` | `encryptor-gateway-spring-boot-starter` | jar |
| `encryptor-starters/encryptor-micrometer-starter/` | `encryptor-micrometer-spring-boot-starter` | jar（可选：Micrometer 指标适配） |
| `encryptor-examples/web-example/` | `web-example` | jar |
| `encryptor-examples/gateway-example/gateway/` | `gateway-example` | jar |
| `encryptor-examples/gateway-example/web/` | `gateway-example-web` | jar（普通下游，**不引入 encryptor**） |
| `encryptor-bench/` | `encryptor-bench` | jar（JMH，仅 all-modules，**不随发布**） |

## 依赖方向（只允许向下）

```text
encryptor-dependencies (BOM: nimbus-jose-jwt/bouncycastle 版本在此)
        │  import
encryptor-core            ← JWE 编解码/密钥库/防重放/协议栈（无 Spring 上下文）
        ├── encryptor-spring-boot-starter ──── encryptor-web-spring-boot-starter   (servlet)
        └── encryptor-spring-boot-starter-reactive ── encryptor-gateway-spring-boot-starter (reactive)
                                                        └── encryptor-examples

encryptor-spring-boot-starter-reactive（或其 gateway-starter）┈┈ optional ┈┈ encryptor-micrometer-spring-boot-starter
        （可选模块：依赖 core + micrometer-core，并 optional 依赖 gateway-starter 仅为读 CryptoExecutor；
          servlet 应用引它不会被拖进 Spring Cloud Gateway；core/两个 starter 的依赖面保持零 metrics）
```

## 核心数据流（v2）

```text
客户端: CEK=CSPRNG(32B) → JWE{alg=RSA-OAEP-256|ECDH-ES|SM2, enc=A256GCM|SM4-GCM, kid, ts, nonce, uri, m, dir=req}
        ECDH-ES: 临时 P-256 密钥对 + epk(header) → Z → Concat-KDF(SHA-256) 派生 CEK，encrypted_key 段为空
        载体三选一: ?jwe=<compact> | {"jwe":"<compact>"} | form jwe=<compact>

服务端 (servlet filter / gateway GlobalFilter):
   ├─ 黑名单/bypass/content-type 跳过判定
   ├─ 取 jwe 载体 → protocol.openRequest(compact, uri, method)
   │     ├─ JweCodec: kid 白名单 → 套件 unwrapCek → GCM 解密(tag+AAD 校验)
   │     └─ ReplayGuard: ttl 时间窗 + nonce 消费(必须在 tag 校验之后)
   ├─ uri 级 kid 白名单(crypto-config) → 明文进业务链
   └─ 响应: codec().encryptResponse(body, 同一CEK, dir=res) → {"jwe":"<compact>"}
```

详细定义见 `docs/architecture/encryptor-core.md` 与设计文档 `docs/superpowers/specs/2026-10-16-payload-security-protocol-design.md`。

## 按任务路由：先读哪个文件

| 你要做的事 | 先读 |
| --- | --- |
| 改 JWE 编解码/AAD/防重放/密钥库/协议默认栈 | `encryptor-core/.../jose/`、`protocol/` |
| 改 servlet 侧过滤器链/三载体/失败面/JWKS 端点 | `encryptor-web-starter/.../filter/`、`discovery/` |
| 改网关链路/有界执行器/响应改写/JWKS | `encryptor-gateway-starter/.../gateway/` |
| 改配置形态/自动装配/启动摘要 | 两侧 `EncryptorAutoConfiguration` + `config/EncryptorConfig` |
| 改指标/监听器适配（可选） | `encryptor-starters/encryptor-micrometer-starter/.../micrometer/`（读 `EncryptorListener` SPI + `CryptoExecutor`） |
| 改默认算法组合/加 CipherSuite | `encryptor-core/.../jose/`（CipherSuite SPI + JceCipherSuite/SmCipherSuite/EcCipherSuite + ConcatKdf） |
| 跑起来验证/改示例/前端 JS | `encryptor-examples/`（front/encryptor/jwe.js 是 JS 客户端参考实现） |
| 性能回归 | `encryptor-bench/` + `check-thresholds.sh` |

需要多步任务时，先用 `.opencode/skills/encryptor-starter-development/SKILL.md` 里的同步清单自检。

## 必须同步修改的地方（v2 双写面）

协议/行为变更时，以下**成对**文件必须同改（否则"servlet 正常、网关失败"）：

| servlet 侧 | reactive/gateway 侧 |
| --- | --- |
| `encryptor-starter/.../configuration/EncryptorAutoConfiguration.java` | `encryptor-starter-reactive/.../reactive/configuration/EncryptorReactiveAutoConfiguration.java` |
| `encryptor-starter/.../config/EncryptorConfig.java`（+ KeyMaterial/Discovery/BypassConfig） | `encryptor-starter-reactive/.../reactive/config/EncryptorConfig.java`（同三件套） |
| `encryptor-web-starter/.../filter/*`、`.../discovery/JwksEndpointFilter` | `encryptor-gateway-starter/.../gateway/filter/*`、`.../discovery/JwksEndpointFilter` |
| `encryptor-starter/.../constant/EncryptorConstant.java`（`JWE_PARAM`/`TRACE_HEADER`） | `encryptor-starter-reactive/.../reactive/constant/EncryptorConstant.java`（同名同值） |
| `encryptor-web-starter/src/test/.../SmJweTestSupport.java`（国密手拼客户端） | `encryptor-gateway-starter/src/test/.../SmGatewayTestSupport.java`（成对副本） |
| `encryptor-web-starter/src/test/.../filter/ResponseFilterHardeningTest.java` | `encryptor-gateway-starter/src/test/.../filter/GatewayJweTest.java`（同名用例族） |
| `encryptor-examples/web-example/front/encryptor/jwe.js` | `encryptor-examples/gateway-example/gateway/front/encryptor/jwe.js` |
| `encryptor-examples/web-example/src/main/resources/application.yml`（`ec-2026` EC + `sm-2026` SM2 演示密钥 + `/test/ec.*`、`/test/sm.*` 白名单） | `encryptor-examples/gateway-example/gateway/src/main/resources/application.yml`（`ec-gw-2026` + `sm-gw-2026`） |

**协议变更（JWE 头字段、AAD claims、载体字段名 `jwe`、`kid` 语义）还要同步：** 两份 `HttpTest.java`（`encryptor-examples/*/src/test/**/HttpTest.java`，里面手工拼 compact 与解析逻辑）、两份 front 的 `jwe.js`、设计文档。

## 配置前缀一览

| 场景 | 前缀 |
| --- | --- |
| 通用（servlet） | `encryptor.config.*` |
| 通用（reactive） | `encryptor.config.reactive.*` |
| web（uri 黑名单/kid 白名单） | `encryptor.config.web.*` |
| gateway | `encryptor.config.reactive.gateway.*`（只管黑名单/开关/order；failure-status/上限在 reactive 通用段） |

## 历史包袱与坑（v1 已删，但这些坑仍要防）

1. 🟩 v1 协议（自研 RSA-PKCS1v15+AES-CBC+MD5-AES 签名、`EncryptorDataWrapper` 5 字段、`EncryptorKit`、`GroupEncryptor`、签名/编码/摘要策略栈）**已全部删除**，残留 grep 必须 0 命中：`EncryptorDataWrapper|AES_K|md5withaes|DigestWithEncryptSigner|GroupEncryptor|HexEncoder`。
2. ⚠️ 含 `.` 的 uri 正则 config key 必须**整体**包在括号里，如 `"[/test/ec.*]"`（绑定后 key 是括号内那串）；**括号不能嵌套**（`"[/]test[/]ec.*"` 会被 Spring 静默改坏 → 规则失效）；正则是**整串匹配**，前缀匹配要写 `.*`。
2.1 ⚠️ ECDH-ES 的 `encrypted_key` 段**为空**（compact 里是 `header..iv.ct.tag`），`JweCodec` 不再把"空 encrypted_key"当结构错误；`epk` 属于 protected header，**参与 AAD**，服务端改动 `epk` 解析口径就等于改 AAD（会全量 AAD_MISMATCH）。只支持 **P-256**，`epk.crv` 不符一律拒；EC 密钥存在时 `allowed-algs` 才联动出 `ECDH-ES`，`enc` 走 AES-GCM 家族。
3. ⚠️ 网关的**下游必须是没有引入 encryptor 的普通应用**（`gateway-example/web`）：网关转发的已是明文，下游若也带 starter 会再解一次 → 400。
4. ⚠️ `Cipher` 非线程安全：JCE 路径每次新建 Cipher（`JceCipherSuite.unwrapCek/aead*`），**不要**缓存单例。
5. ⚠️ nimbus `Base64URL` 无 `decode(String)` → `java.util.Base64.getUrlDecoder()`；`JWEHeader.parse(String)` 收 JSON，parse base64url 段用 `JWEHeader.parse(new Base64URL(...))`。
6. ⚠️ BC 自产 SM2 PKCS#8 可能用显式曲线参数而非命名 OID（`ServerKeyStore.isSm2Algorithm` 已兼容三形态）；SM 路径只用 BC 轻量级 API，**不注册全局 Provider**。
7. ⚠️ 防重放 `ReplayGuard.verify` 必须在 **GCM tag 校验之后**调用（未认证输入不得污染 nonce 存储）。
8. ⚠️ 流式响应（SSE/下载）**不包装**：响应过滤器先判 content-type 黑名单再加密；不要无脑全量缓冲。
9. 🟩 设计文档里的“已完成”状态：P0–P3 修复与 S1–S17 处置见 `docs/architecture/open-issues.md` / `security-review.md` 顶部的状态表（v1 部分条目已随 v1 删除而消除）。
10. ⚠️ 网关 `CryptoExecutor` 的队列深度**不能**读 Reactor 的 `Scannable.Attr.BUFFERED`（`BoundedElasticScheduler.estimateSize()`）——任务被派进执行器内部队列后即不可见，实测恒为 0；`pendingTasks()` 是自己在包装 `Scheduler` 里按「提交数 − 完成数」记的。另：Reactor 3.4.2 的 `Scheduler` 只 `extends Disposable`（**不是** `Scannable`），覆写 `scanUnsafe` 会编译失败。

## 约定

- 注释/Javadoc 用中文，类头保留 `@author changgg`。
- 配置类：`@ConfigurationProperties(prefix = ...)` + `@EnableConfigurationProperties`，一律 getter/setter（不用 Lombok，Java 8）。
- 自动装配：`@Configuration(proxyBeanMethods = false)` + `@ConditionalOnProperty` / `@ConditionalOnMissingBean`；非法配置启动期 fail-fast + 生效摘要日志。
- core 里**不要新增** Spring 依赖（现状例外：无——redis 依赖已随 v1 删除）。
- 改完至少跑 `mvn -B -Pmain-module clean install`；改 examples/前端后跑 `-Pall-modules`。

## 构建状态（`master`）

- `mvn -B -Pall-modules clean install` → BUILD SUCCESS（core 98 + starter 10 + reactive 4 + web 40 + gateway 30 + micrometer 9 + 两示例 + JMH bench）。
- 全量单测 **191 绿**（core 98、starter 10、reactive 4、web 40、gateway 30、micrometer 9），fail/err 均 0。增量构成：web +2 / gateway +4 来自 P3-4（`skip-*` 正名 + 旧名 `black-*` alias）的绑定用例；web +7 来自 P2-5 的链序守卫 `FilterChainOrderTest`（向 `WebEncryptorConfiguration` 取生产注册的 bean 按 order 组链，跑三载体往返 + 响应回加密 + 链尾清 ThreadLocal；把 `encryptorReqParamsFilterOrder` 改 -9 会红 2 例）；gateway +3 来自 D3 的 `CryptoExecutorTest`；micrometer 8 是 D1/D3 新增的可选模块（监听器计数 3 + 自动装配条件 4 + 接线证明 1）。本轮多监听器支持 +9：core +6（`CompositeEncryptorListenerTest` 5：按序扇出/单监听器异常隔离/多监听器互不影响/空集合等价 NONE/异常 WARN 日志含回调名与异常栈；`JweCodecListenerTest` 1：直接 `new JweCodec(...)` 时监听器异常也不改变结果）、servlet starter +1 与 reactive starter +1（两处都验证两个 listener bean 全部接上协议栈）、micrometer +1（用户监听器与指标监听器同时收到回调）。
- CI（`.github/workflows/ci.yml`，temurin **JDK 8**）此前已按同命令在本地 1.8.0_461 复跑 182 绿（ECDH-ES 走 JDK 8 SunEC 的 `KeyAgreement ECDH`，含 nimbus `ECDHEncrypter` oracle 互通用例，全通过）；本轮多监听器改动后已在本地 JDK 11 跑 `-Pmain-module clean install` 191 绿，JDK 8 CI 待跑。CI 另加两步：`-Pall-modules -DskipTests package`（保证示例与 bench 能编译，此前 CI 完全不碰它们）与 `diff` 两份 `jwe.js`（双写面守卫）。JMH 阈值脚本**故意不进 CI**（共享 runner 上噪声大）。
- ⚠️ **示例测试源码必须能编过 JDK 8**（`mvn -Pall-modules` 会编 examples 的 test 源码）：`HttpTest.java` 曾用 `URLEncoder.encode(String, Charset)`（**Java 10+** 才有）→ JDK 8 下编译失败；已改为自带 `enc(String)` helper（`URLEncoder.encode(s, "UTF-8")` 包一层）。两份 `HttpTest.java` 是成对文件，改一处必须同步另一处。
- P3-4（`skip-*` 正名 + 旧名 alias）：⚠️ 新旧名单**不能共用同一个 list**——Spring Boot 对集合属性是"就地绑定（clear + 回填到 getter 返回的 list）"，共用时后绑定的会把先绑定的清掉。现为「旧名独立字段 + `InitializingBean.afterPropertiesSet()` 合并去重」。
- JMH（M1 Pro / JDK 11，三次运行中位数，`-wi 2 -i 3 -f 1 -prof gc`）：RSA 往返 1020 ops/s、ECDH-ES 往返 1438 ops/s（**≈1.4×，非数量级**，差值来自 P-256 协商 vs RSA-2048 私钥运算 ≈0.29 ms/op）；4 线程解封并行度 RSA 3.94× / ECDH-ES 3.99×（阈值 2.5×）；bytes/op 73018（基线 72792，+0.3%，阈值 +10%）。完整表与复现命令见 `README.md`「性能基准（JMH）」。
- ⚠️ `bench.jar` 的两个坑：①`EcdhEsBenchmark` 必须显式传 `allowedAlgs={ECDH-ES}`（空集合会取协议默认 `RSA-OAEP-256` → 构造期 fail-fast）；②JMH setup 失败时只在日志里打堆栈、**exit code 仍是 0**，必须查 `bench.log`/`check-thresholds.sh` 而不能只看退出码。
- ECDH-ES（P-256）端到端已复验（全 JIT 手起实例）：web-example `node front/test.js` 11/11、gateway-example 10/10；core 另以 nimbus `ECDHEncrypter` 为独立 oracle 做双向互通单测。
- 国密（SM2+SM4-GCM）在示例里已可自证：两个示例都自带 SM2 演示密钥，用独立 SM 客户端（手拼 SM2 C1C3C2 + SM4-GCM，不复用 core）打 `/test/hello` 各 **12/12 PASS**（含重放/篡改/未知 kid/AAD 不匹配四条拒绝面）；同一实例上 `node front/test.js` 仍全绿。
- ⚠️ 客户端 classpath 的 BC 版本与目标服务端无关：网关的 classpath 里含较老的 bcprov（缺 `ECDomainParameters(X9ECParameters)` 构造器），把用于 web 的 SM 客户端拿去跑会在客户端侧 `NoSuchMethodError`——换回客户端自己的 classpath 即可（服务端 SM2 解析/解密正常，启动摘要与 E2E 均可证）。
- 真实端到端（RSA 路径，全 JIT）：web-example(8081) 与 gateway-example(8080→8082) 的 JWE 三载体 + 篡改用例全 PASS；两个 JWKS 端点 200 + ETag。
- 评审修复的裁定（RF-1/2/3）与 5 条明确推迟的 Minor（D1–D5）见 `docs/architecture/open-issues.md` 文末「v2 整分支评审修复」章节。
