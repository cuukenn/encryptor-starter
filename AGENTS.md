# AGENTS.md

本文件是给 AI 编码助手（以及新同学）的入口说明。**完整架构文档在 `docs/architecture/`**，按模块拆分，本文件只放"每次都要知道"的部分。

## 这是什么

`encryptor-starter`：一套**报文层安全**的 Spring Boot Starter（v2 协议，对齐 JOSE/JWE RFC 7516）。客户端用服务端公钥封装一把每请求新生成的 CEK——RSA-OAEP-256、国密 SM2，或 ECDH-ES（P-256 直接密钥协商）——业务数据用 AES-GCM（或 SM4-GCM）加密；服务端验上下文/防重放、解密、处理、再用同一 CEK 把响应回加密（`alg=dir`）。国密能力在**可选模块 `encryptor-sm`** 中，core/starter 本身不依赖 BouncyCastle。

- 语言/构建：**Java 8** + Maven 多模块；boot3 线（`-Pboot3`）为 **Java 17 + Boot 3.5**（`-boot3` 后缀 jakarta 复制对）
- 版本：javax 线 Spring Boot `2.7.18`、Spring Cloud `2021.0.8`、Spring Cloud Alibaba `2021.1`；boot3 线 Boot `3.5.16`、Cloud `2025.0.3`、SCA `2025.0.0.0`；hutool `5.8.25`、nimbus-jose-jwt `9.37.3`、bcprov/bcpkix `1.78.1`
- groupId：`io.github.cuukenn`，版本 `1.0.0`（发布版；`v1.0.0` 标签已打；boot3 模块自管 `3.0.0`）
- ⚠️ **自动装配现在双注册**：每个 starter 同时保留 `META-INF/spring.factories`（旧机制，Boot < 2.7 兜底）与 `META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports`（新机制，Boot ≥ 2.7 推荐），指向同一装配类（Boot 会去重，不会重复注册）。**彻底删除 `spring.factories` 前必须先确认放弃 Boot < 2.7 兼容**，且需同步 5 个 starter（含 micrometer）。**boot3 复制模块只保留 `AutoConfiguration.imports`**（Boot 3 已移除 spring.factories 机制，复制时删除该文件是 diff 守卫的登记豁免）

## 安全边界（必须记住）

- **承诺**：机密性 + 完整性（防篡改，AEAD 内建）+ 现代算法 + 密钥轮换（kid/JWKS）。
- **不承诺**：客户端身份认证/防伪造。认证交给 TLS + Spring Security（JWT/mTLS）——任何人都能拿到公钥构造合法报文，这是设计内的 non-goal。
- 不是 TLS 的替代；客户端需 WebCrypto（浏览器 https/localhost，Node ≥16）。

## 构建与验证

```bash
mvn -B -Pall-modules clean install     # 全量（含 examples + JMH bench 模块声明）
mvn -B -Pmain-module clean install     # 只构建 dependencies/core/starters，跳过 examples
mvn -B -Pboot3 clean install           # boot3 线（JDK 17/21；reactor 不含 core，需先 install 过 javax 线制品 ~/.m2 才能解析 encryptor-core:1.0.0）
mvn -pl encryptor-core test            # 单模块 + 它的依赖（先 install 过 core 才能编下游）
java -jar encryptor-bench/target/bench.jar -wi 2 -i 3 -f 1 -prof gc -rf json -rff encryptor-bench/target/bench.json && encryptor-bench/check-thresholds.sh   # JMH（RSA 并行度≥2.5x、bytes/op 基线±10%）
```

- Maven 在 **`/usr/local/maven/3.8.9/bin/mvn`**（不在 PATH）；`java` 11。⚠️ **GitHub runner 的 Maven 已升到 3.9+（2026-10-24 CI 全红根因）**：3.9 对 `pluginManagement` 里同一插件重复声明从"后者覆盖"变成硬错误——根 POM 曾有两份 `maven-source-plugin`，已合并；本地 3.8.9 与 brew 的 3.10（`/opt/homebrew/bin/mvn`）现在都能过，改 POM 后建议双版本各跑一次。
- 根 `pom.xml` **没有** checkstyle/spotless；surefire 固定 `2.22.2`（boot3 复制对 pom 各自 pin `3.5.4`，root 2.22.2 × JU Platform 1.12 会 Tests run: 0 假绿，见 pom 注释）。
- `**/HttpTest.java` 被 surefire 排除（需先起服务）；`encryptor-examples/*/front/test.js` 也需先起服务。
- surefire 默认 `trimStackTrace=true`，定位失败加 `-DtrimStackTrace=false`。
- **改 reactive/gateway 前必须先 `mvn -pl encryptor-core install -DskipTests`**（下游编译用本地仓库 jar）。

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
| `encryptor-starters/encryptor-spring-boot3-starter/` | `encryptor-spring-boot3-starter` | jar（**boot3 线**：jakarta 复制对，Boot 3.5 代际，`3.0.0` 自管版本，仅 `-Pboot3`） |
| `encryptor-starters/encryptor-web-boot3-starter/` | `encryptor-web-boot3-starter` | jar（boot3 线：`encryptor-web-starter` 的 jakarta 复制对） |
| `encryptor-starters/encryptor-gateway-boot3-starter/` | `encryptor-gateway-boot3-starter` | jar（boot3 线：`encryptor-gateway-starter` 的 jakarta 复制对） |
| `encryptor-examples/web-example/` | `web-example` | jar |
| `encryptor-examples/gateway-example/gateway/` | `gateway-example` | jar |
| `encryptor-examples/gateway-example/web/` | `gateway-example-web` | jar（普通下游，**不引入 encryptor**） |
| `encryptor-examples/boot3-example/` | `boot3-gateway-example` | jar（boot3 线示例，**不发布**） |
| `encryptor-bench/` | `encryptor-bench` | jar（JMH，仅 all-modules，**不随发布**） |

## 依赖方向（只允许向下）

```text
encryptor-dependencies (BOM: nimbus-jose-jwt/bouncycastle 版本在此)
        │  import
encryptor-core            ← JWE 编解码/密钥库/防重放/协议栈（无 Spring 上下文，零 BouncyCastle）
        ├── encryptor-sm ┈┈ optional ┈┈ SM2/SM4-GCM 实现（唯一依赖 BC 的制品；不被任何 starter 传递）
        ├── encryptor-spring-boot-starter ──── encryptor-web-spring-boot-starter   (servlet)
        └── encryptor-spring-boot-starter-reactive ── encryptor-gateway-spring-boot-starter (reactive)
                                                        └── encryptor-examples（示例显式添加 encryptor-sm）

encryptor-spring-boot-starter-reactive（或其 gateway-starter）┈┈ optional ┈┈ encryptor-micrometer-spring-boot-starter
        （可选模块：依赖 core + micrometer-core，并 optional 依赖 gateway-starter 仅为读 CryptoExecutor；
          servlet 应用引它不会被拖进 Spring Cloud Gateway；core/两个 starter 的依赖面保持零 metrics）

boot3 分叉（`-Pboot3`，Boot 3.5 / SC 2025.0 / SCA 2025.0 锚点在 root profile 属性；每个 boot3 模块 pom 内显式 import 本 BOM 1.0.0 兜底 ${project.version} 插值错位）：
encryptor-core（1.0.0 单份共享，boot3 线也从 ~/.m2/仓库解析同名 jar——reactive/micrometer 无 -boot3 副本，Boot 3.5 下直接复用 javax 线 jar）
        ├── encryptor-spring-boot3-starter（jakarta 复制自 encryptor-spring-boot-starter，3.0.0 自管版本）── encryptor-web-boot3-starter（复制自 encryptor-web-starter）
        └── encryptor-gateway-boot3-starter（复制自 encryptor-gateway-starter；3 文件最小 API 签名适配见「必须同步修改」boot3 守卫行）
                └── encryptor-examples/boot3-example（不发布；加密线 = 复制 3.0.0 + 共享 micrometer 1.0.0）
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
| 改配置形态/自动装配/启动摘要 | core `config/base/EncryptorConfigBase` + 两侧 `EncryptorAutoConfiguration` / `config/EncryptorConfig`（只保留前缀） |
| 改指标/监听器适配（可选） | `encryptor-starters/encryptor-micrometer-starter/.../micrometer/`（读 `EncryptorListener` SPI + `CryptoExecutor`） |
| 改默认算法组合/加 CipherSuite | `encryptor-core/.../jose/`（CipherSuite SPI + JceCipherSuite/EcCipherSuite + ConcatKdf；SPI 实现用 `META-INF/services` 注册） |
| 改国密 SM2/SM4-GCM 或 BC 相关解析 | `encryptor-sm/.../sm/`（`SmCipherSuite` + `SmKeyEntryParser`，包名 `io.github.cuukenn.encryptor.sm`；**core 不得再出现 `org.bouncycastle`**） |
| 跑起来验证/改示例/前端 JS | `encryptor-examples/`（front/encryptor/jwe.js 是 JS 客户端参考实现） |
| 性能回归 | `encryptor-bench/` + `check-thresholds.sh` |

需要多步任务时，先用 `.opencode/skills/encryptor-starter-development/SKILL.md` 里的同步清单自检。

## 必须同步修改的地方（v2 双写面）

协议/行为变更时，以下**成对**文件必须同改（否则"servlet 正常、网关失败"）：

| servlet 侧 | reactive/gateway 侧 |
| --- | --- |
| `encryptor-starter/.../configuration/EncryptorAutoConfiguration.java` | `encryptor-starter-reactive/.../reactive/configuration/EncryptorReactiveAutoConfiguration.java` |
| `encryptor-starter/.../config/EncryptorConfig.java`（只保留 `PREFIX`；字段/默认值继承 core `config/base/EncryptorConfigBase`，三件套同样继承） | `encryptor-starter-reactive/.../reactive/config/EncryptorConfig.java`（同，只差 `PREFIX`） |
| `encryptor-web-starter/.../filter/*`、`.../discovery/JwksEndpointFilter` | `encryptor-gateway-starter/.../gateway/filter/*`、`.../discovery/JwksEndpointFilter` |
| `encryptor-starter/.../constant/EncryptorConstant.java`（`JWE_PARAM`/`TRACE_HEADER`） | `encryptor-starter-reactive/.../reactive/constant/EncryptorConstant.java`（同名同值） |
| `encryptor-web-starter/src/test/.../SmJweTestSupport.java`（国密手拼客户端） | `encryptor-gateway-starter/src/test/.../SmGatewayTestSupport.java`（成对副本） |
| `encryptor-web-starter/src/test/.../filter/ResponseFilterHardeningTest.java` | `encryptor-gateway-starter/src/test/.../filter/GatewayJweTest.java`（同名用例族） |
| `encryptor-web-starter/src/test/.../configuration/FilterOrderValidationTest.java`（链序契约） | `encryptor-gateway-starter/src/test/.../configuration/GatewayEncryptorConfigurationTest.java`（validateFilterOrder 用例族） |
| `encryptor-web-starter/.../config/WebEncryptorConfig.java`（skip 名单/告警） | `encryptor-gateway-starter/.../config/GatewayEncryptorConfig.java`（+ `CryptoExecutorConfig`，容量配置） |
| `encryptor-examples/web-example/front/encryptor/jwe.js` | `encryptor-examples/gateway-example/gateway/front/encryptor/jwe.js` |
| `encryptor-examples/web-example/src/main/resources/application.yml`（`ec-2026` EC + `sm-2026` SM2 演示密钥 + `/test/ec.*`、`/test/sm.*` 白名单） | `encryptor-examples/gateway-example/gateway/src/main/resources/application.yml`（`ec-gw-2026` + `sm-gw-2026`） |

**协议变更（JWE 头字段、AAD claims、载体字段名 `jwe`、`kid` 语义）还要同步：** 两份 `HttpTest.java`（`encryptor-examples/*/src/test/**/HttpTest.java`，里面手工拼 compact 与解析逻辑）、两份 front 的 `jwe.js`（现为**三份**，含 `encryptor-examples/boot3-example/front/encryptor/jwe.js`，CI pairwise diff）、设计文档。

### boot3 复制对（`scripts/javax-to-jakarta.sh --diff` CI 守卫）

javax 线源码经脚本机械替换（`javax.servlet` → `jakarta.servlet`）后，必须与 boot3 模块**逐字节一致**；守卫命令已在 CI boot3 job（JDK 17 档）执行：

| javax 侧（源） | boot3 侧（复制对） | 守卫口径 |
| --- | --- | --- |
| `encryptor-starter/src` | `encryptor-spring-boot3-starter/src` | 零豁免（`--exclude spring.factories`，uniform=9） |
| `encryptor-web-starter/src` | `encryptor-web-boot3-starter/src` | 零豁免（同上，uniform=24） |
| `encryptor-gateway-starter/src` | `encryptor-gateway-boot3-starter/src` | `--expect-diff` 登记 3 文件的 API 签名适配（`getMethodValue()` → `getMethod().name()` ×4 处、`getStatusCode()` → `HttpStatusCode` ×2 处 + import），uniform=14 exempt=3 |

- 改 javax 线任一复制对源文件 = 必须同步改 boot3 对位（机械替换口径；CI 守卫会红）。改协议 = 三处一起（javax servlet / reactive 共享线 / boot3 复制线）。gateway 对的 3 个 `--expect-diff` 豁免文件不参与红/绿判定，属人审面（守卫脚本对它们非失败地打印 Eye-diff 输出在 CI 日志，汇总尾部有 `EXEMPT-FILES-INSPECT` 行标记）。另：keyed `--exclude spring.factories` 同时断言 boot3 侧不得重新引入 `spring.factories`（`SPRING-FACTORIES-CREEP` → 红）。
- 登记口径：`--expect-diff` pattern 以 `main/java/...` 起头（src 级 diff 的相对路径无 `src/` 前缀，带 `src/` 前缀的登记恒不命中）；pom 与 `spring.factories` 差异默认豁免。
- reactive / micrometer **无 boot3 副本**（main 源码零 `javax.*`，Task 2 实测 Boot 3.5 直接复用 javax 线 jar 共享）——它们的改动既影响 javax 线也直接进 boot3 线，无需复制同步，但测试面在 `encryptor-examples/boot3-example`（共享线对等用例）。

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
6. ⚠️ BC 自产 SM2 PKCS#8 可能用显式曲线参数而非命名 OID（`SmKeyEntryParser.isSm2Algorithm` 已兼容三形态）；SM 路径只用 BC 轻量级 API，**不注册全局 Provider**。SM2 解析/套件都在可选模块 `encryptor-sm` 的 `io.github.cuukenn.encryptor.sm` 包（经 `KeyEntryParser`/`CipherSuite` 的 `ServiceLoader` 接线，避免与 core 的 `jose` 包形成 split package）。**core（main/test）与 starter 的 main 源码都不得出现 `org.bouncycastle`**；starter 的 SM 集成测试允许用 `<scope>test</scope>` 的 `encryptor-sm`/bcprov，但不得进入 compile/runtime 依赖树。没有 `encryptor-sm` 时配置 SM2 密钥必须启动期失败并提示添加该依赖。
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

- `mvn -B -Pall-modules clean install` → BUILD SUCCESS（core 126 + sm 18 + starter 11 + reactive 5 + web 92 + gateway 62 + micrometer 10 + 两示例 + JMH bench）。
- **2026-10-23 二轮扫描修复（全部落实）**，`-Pmain-module` 324 绿（core 126 / sm 18 / starter 11 / reactive 5 / web 92 / gateway 62 / micrometer 10），`-Pboot3` **181 绿**（spring-boot3 11 / web-boot3 92 / gateway-boot3 62 / boot3-example 16），三对复制对 diff 守卫 UNIFORM。本轮**行为契约变更**（升级注意）：
  - ⚠️ micrometer 装配顺序修复：`EncryptorMicrometerAutoConfiguration` 补 `@AutoConfigureAfter(GatewayEncryptorConfiguration)`——此前两者都走 spring.factories 时按类名排序 micrometer 先求值，`@ConditionalOnBean(CryptoExecutor)` 恒不满足，D3 的 pending/rejected 指标**静默不注册**；同时 `EncryptorListener` 新增 `onEncryptSuccess` 回调（micrometer 新增 `encryptor.encrypt{result=success}` 指标）。
  - ⚠️ QUERY 载体明文口径统一为 **form 语义**（与 servlet `parseQuery` 的 URLDecoder 一致，`+`=空格）：网关按 form 语义解出参数再以 URI 形态（空格=%20）重建 query，参数视图给**解码值**（此前网关给编码形态、`+` 保留，与 servlet 分叉）；非法 urlencoded（如尾部残缺 `%`）按失败面拒绝。网关解密 uri 统一走 `ContextAad.canonicalPath`（空路径归 `/`）。
  - ⚠️ servlet 门面载体判定：jwe 出现在 query string 上时一律按 QUERY（`getParameter` 会合并 query 与 form body，此前 form content-type + query jwe 会误判 FORM 并用明文顶掉真实 form body）；`getParameterMap` 返回 unmodifiable（Servlet 规范）；`max-request-size<=0` 启动告警。
  - ⚠️ servlet 注册的 `EncryptorRuntime` bean 必须与 `protocol.runtime()` 同一实例（启动期身份校验）：用户覆盖同类型 bean 会让启动期 bypass 配置/热开关落空。
  - 网关：响应 content-type 黑名单小写归一（与请求侧同口径）；请求侧明文 body 在 decorate 时 clone（防 doFinally 清零与 Retry 二次订阅竞态，同响应侧 `cek.clone()`）；响应加密的 CEK 副本终态清零；**codec 之外的失败分支（缺载体/kid 白名单/执行器拒绝/超限/非法 query）统一补发 `onDecryptFailure` 审计**（codec 路径不重复计数）；JWKS 端点支持 HEAD、`If-None-Match` 多值/弱比较（`JwksDocument.etagMatch`，RFC 7232）、路径 canonicalPath 归一；`crypto-executor.threads/queue-capacity` 非法配置报错带配置项名；`pendingTasks` 先读 completed 防 gauge 瞬时负值。
  - servlet：请求体包装器 `setReadListener` 改为抛 `UnsupportedOperationException`（明文在内存中，非阻塞读会静默挂死）；响应未包装（旁路/透传）的异步请求不再在 finally 提前清零明文（`WebContext.clear(request)` 异步感知重载）。
  - 存疑面确认未改（契约文档化）：skip 头只判 containsKey（启动告警已明示）；AAD 不绑 query（防重放依赖 nonce）；QUERY 明文=完整 query（jwe 外参数被丢弃，javadoc 已写明）。
- **2026-10-23 全量扫描修复（P0/P1/P2 全落实）**，`-Pmain-module` 324 绿（core 126 / sm 18 / starter 11 / reactive 5 / web 92 / gateway 62 / micrometer 10），`-Pboot3` **181 绿**（spring-boot3 11 / web-boot3 92 / gateway-boot3 62 / boot3-example 16），三对复制对 diff 守卫 UNIFORM。本轮**行为契约变更**（升级注意）：
  - ⚠️ `JweContext.destroy()` 之后 `cek()`/`plaintext()` 抛 `IllegalStateException`（此前返回全零数组；全零是合法 AES 密钥，静默使用会产出客户端解不开的报文）。
  - ⚠️ `ReplayGuard` 构造期强制 `InMemoryNonceStore` 的 retention ≥ 2*ttl（约束从 `DefaultProtocol.build()` 下沉到构造器兜底）。
  - ⚠️ 过滤器 order **启动期链序校验**：servlet 侧 `WebEncryptorConfiguration.validateFilterOrder`（jwks < 门面 < 参数 < 请求体 < 响应）、网关侧（jwks < 请求，响应 < `NettyWriteResponseFilter.WRITE_RESPONSE_FILTER_ORDER`）——顺序改错从"静默明文"变成启动失败；两侧装配期打印生效链序日志。
  - ⚠️ JWE `crit` 头非空一律拒绝（RFC 7516 §4.1.13）；ECDH-ES 的 `apu`/`apv` 进入 ConcatKDF OtherInfo（此前恒空，与发 apu/apv 的合规客户端互通会静默失败）；ECDH 共享秘密左补零到 32 字节。
  - ⚠️ `CipherSuite` SPI 新增默认方法：`pairsWith(alg, enc)`（ECDH-ES 只配自家 AES 家族，交叉组合在解封前被拒并给精确分类）与 6 参 `unwrapCek(..., headerJson)`（复用 JweCodec 已序列化的 header，省一次热路径 `toJSONObject`）。
  - 5 参 `encryptResponse`（按 CEK 长度猜 enc）在装配套件含非 AES-GCM enc 时抛 `ENCRYPT_FAILED`（防 SM4 CEK 被猜成 A128GCM）；`CryptoExecutor` 容量配置化：`encryptor.config.reactive.gateway.crypto-executor.threads/queue-capacity`（默认 CPU 核数/1000）；`EncryptorRuntime` 改 volatile 快照整包换面 + 失效器异常隔离；`StrKit` 正则缓存上限 256；`JweCodec` 死代码（`decode(Base64URL)`/`claims`）删除；SM4-GCM tag 失败异常带 BC cause。
- **2026-10-24 三轮扫描修复（全部落实）**：servlet 响应过滤器异步启动后链上抛异常改走 AsyncListener 收尾（不再在初始线程 reset/commit）；`BoundedContentCachingResponseWrapper.getWriter` 对非法字符集名回退 UTF-8；`finish()` 的 isCommitted 早退分支补 WARN（明文可能已出网）；jwe.js（三份 pairwise）：`b64urlEncode` 分块拼接、`fetchKeys` 校验 HTTP 状态与 keys 结构、`decrypt` 增加可选响应新鲜度校验（`opts.maxResponseAgeMs`，默认 5 分钟，0 关闭——防整条旧响应重放）、导出 `zeroize()`；test.js（web 八组/gateway 八组）新增 QUERY 共存与载体判定锁定用例，头注释组数修正。**确认的契约**：异步周期必须可终止（setTimeout/complete），否则 CEK/明文缓存滞留到 GC（Servlet 异步模型固有限制，无 per-request 兜底）；响应方向防重放由客户端 ts 新鲜度校验承担（服务端 AAD 只保证头-密文绑定）。
- **2026-10-24 五轮扫描（终轮，残余面已收敛）**：`SmKeyEntryParser` 曲线等价性比对补齐 a/b（用模数值比对，BC FieldElement 跨实例 equals 不可靠）+ SPKI 公钥分支显式比对公钥曲线与私钥域参数；skip-methods 匹配输入大写归一（配置写 get/Get/GET 都能命中）；两侧 skip content-type 配置条目含大写字符时启动告警（正则不能安全自动转小写，只能提示）；`open-issues.md` 的 jwe.js 计数"两份→三份"。HttpTest 成对同构、示例 yml kid/白名单一致性、security-review.md 状态表均核对无脱节。**无新增缺陷**。
- **2026-10-24 delta 代码评审（独立 reviewer）**：修复 4 项——① `foldDotSegments` 连空段（`//`）一并折叠（Tomcat 归一化 `//pay`→`/pay`，与 `..` 同一白名单绕过面），canonicalPath 改"折叠→解码→再折叠"次序（`URI.create` 会把开头 `//` 当 authority 解析丢段；解码产出的新 dot/空段由第二轮兜住）；② kid 白名单拒绝路径的日志/异常消息补 `JweCodec.sanitize`（此前只覆盖 codec 内部消息，javax/boot3 四份复制同步）；③ 网关响应明文 `bytes` 的清零移进加密阶段 `doFinally`（成功/失败/取消全覆盖，此前只在成功路径）；④ 网关响应 AAD 的 uri 改走 `canonicalPath`（与请求验证同口径，claim 不再分叉）。**已知口径差异（有意保留）**：servlet 侧 AAD 输入是原始 `requestURI`（claim 绑原始形态即过，兼容不预归一化的客户端），网关侧是 `canonicalPath` 折叠形（不归一化客户端在非常规路径上 fail-closed）——百分号编码的 CJK 路径在 servlet 侧 raw==claim 可过、网关侧解码后比对（预存行为）；`sanitize` 升级为 public 并覆盖 U+2028/U+2029、codePoint 安全截断。
- **2026-10-24 六轮（终轮）完整扫描**：一致性核对（README 6 处/spec 2 处/AGENTS 双写清单 2 处/check-thresholds 头注释/jwe.js 计数）全部修齐；新鲜视角安全复审**无高危**，修复 1 中 2 低：① `ContextAad.canonicalPath` 折叠 `.`/`..` 段（解码后折叠，`%2E%2E` 一并覆盖、尾斜杠保留）——此前 uri 级 kid 白名单可被 `/x/../pay` 穿越形态绕过（过滤器不命中白名单=不限 kid，下游归一化后落到受保护资源）；② `JweCodec` 头字段（alg/enc/kid/crit）进异常消息前 `sanitize`（控制字符→`·`、128 截断），关日志伪造面；③ 网关响应侧 CEK 副本改为**全链终态清零**（skip/无 body/超限 fail/取消均覆盖）+ 响应明文 `bytes` 构造完 JWE 即清零 + 请求明文克隆登记进 `GatewayContext.destroy` 一并清零。观察项维持文档化：SSE 默认 skip（有启动告警）、web 异步 `setTimeout(0)` 滞留（Servlet 模型固有）、`isCommitted` 分支不可补救仅 WARN、web 响应明文缓存在 Spring `ContentCachingResponseWrapper` 内部（best-effort 口径已声明）。
- **2026-10-24 五维评审处置（P0/P1 全落 + P2 小项）**：① servlet 门面 codec 外失败分支（缺载体/坏 JSON/超限×3/kid 白名单/query 非法）统一补发 `onDecryptFailure` 审计（对齐网关模式，`fail` 加审计重载；codec 路径不重复计数）——修复两侧 micrometer 统计口径漂移；② CI 新增 `EncryptorConstant` 双份（servlet/reactive）除 package 行外逐字节一致守卫；③ 测试补盲区：网关订阅取消（doFinally CANCEL 清理+CEK 清零）、请求侧 executor 拒绝→503、ECDH×过滤器层（`JweTestSupport.Ec` 内嵌 nimbus oracle）、QUERY×SSE 明文透传；④ **行为修复：skip content-type 匹配改为 media-type 段（剥 `;charset=` 等参数）后再整串正则匹配**（`StrKit.mediaType`，两侧+boot3）——此前默认 `text/event-stream` 对 `text/event-stream;charset=UTF-8` 的真实 SSE 头永不命中（默认 SSE 跳过实际失效，SSE 测试抓出）；⑤ `DefaultProtocol` 用内存 nonce 存储时启动 WARN（多实例重放窗口此前只有文档拦截）；⑥ 新增 `ReplayGuardBenchmark`（单/4 线程 verify，补 E2e 基准无法携带 ReplayGuard 的盲区）。
- **2026-10-24 delta 再评审（271628e 处置的复核）**：评审抓出 9 条（1 必须 4 建议 4 提问），全部处置——① 首轮处置脚本中途断言失败导致 TOO_LARGE×3 审计调用**实际未落盘**（AGENTS/commit 均过度声明），本轮补齐；② 两侧 skip content-type 配置条目含 `;` 参数段时启动 WARN（media-type 剥参数口径下此类条目永不命中，存量配置静默失配的迁移提示）；③ 网关响应侧/servlet 响应侧的 codec 外失败出口补 `onEncryptFailure`（两侧此前对称留白，超限→TOO_LARGE、其余 INTERNAL、消息携带状态码）；④ 请求侧 503 测试补 recording listener 断言（审计出口有守护）、取消测试删死代码 latch；⑤ `check-thresholds.sh` 接入 ReplayGuardBenchmark 的 INFO 行（1/4 线程吞吐与比率，不设闸门）；⑥ 内存 nonce 存储的启动 WARN 消息加"单实例可忽略"；⑦ INTERNAL 分支恢复异常栈、双 javadoc 叠放修复。**匹配语义补充**：`text/event-stream;.*` 等带 `;` 的存量正则在新口径下需改写为纯 media-type（启动会 WARN）。
- **2026-10-24 前瞻性评审落地（三项）**：① **双线版本同步**——root pom 新增 `encryptor.javax.line.version` property（= javax 线版本，发版与 `project.version` 同步 bump），三个 boot3 pom 的 BOM import 改经 property 引用；`scripts/check-dual-line-versions.sh`（CI 已接）断言 root 版本==property==boot3 引用无字面量，防"core 修复漏发 boot3 线"的安全事件；CHANGELOG 顶部固化双线成对发布约定（1.0.x ⇔ 3.0.x）。② **协议版本化软锚点**——`JweCodec.PROTOCOL_TYPE="encryptor+jwe"`：服务端软解析 typ（未知记 INFO 不拒绝，兼容不发 typ 的旧客户端），演进通道固定为 additive claim + 软接受（spec §3.11）；crit 保持 fail-closed 不作为演进通道。③ **servlet↔reactive 结构 parity 守卫入 CI**：wire 常量三处同值（两份 EncryptorConstant + GatewayConstant.JWE_PARAM）、skip 配置类字段/助手清单一致、两侧 AutoConfiguration 公共 bean 面含 defaultProtocol/encryptorRuntime。**待下轮**：crypto-config 的 routes 平行键（per-route 策略前置）依赖 config 下沉 core base（收敛 TOP1）再动，避免 4 份复制。
- **2026-10-24 收敛轮（TOP1+TOP2 落地）**：① **skip/config 机制下沉 core**——新增 `config/base/SkipListsConfigBase`（skip-* 字段 + black-* alias 合并 + precompile + 大写/`;` 参数告警，`initSkipLists(prefix)` 单点），两侧 `WebEncryptorConfig`/`GatewayEncryptorConfig` 继承之（各自只留模块特有字段）；今后 skip 口径变更 4 文件→1 文件，CI parity 守卫同步改为"两侧必须 extends base + base 四助手齐全"。② **载体字符串逻辑下沉 core**——新增 `kit/CarrierKit`（`hasQueryJwe`/`decodeFormComponent`/`encodeQueryComponent`/`parseUrlencoded`/`jweFromFormBody`，form 语义解码 + URI 形态编码的互逆契约有单测钉住），两侧门面删除本地 `parseQuery`/`urlDecode`/`hasQueryJwe`/`uriEncode`/`jweFromForm` 实现、改调 core——QUERY 口径分叉这一回归类从此结构性消除。Carrier 枚举有意保留在两侧 Context（boot3 diff 守卫覆盖，测试 API 不动）。**下一轮**：`crypto-config` 的 `routes` 平行键（per-route 策略）——前置已就绪，可直接在 core base 建模。
- **2026-10-24 routes 平行键落地（#2 破坏性风险闭环）**：core 新增 `config/base/RouteRule`（当前实现 `kids`；**键结构 `Map<正则, RouteRule>` 从此固定**，后续 enc/ttl/require-encrypted 往里加字段都是增量绑定）+ `effectiveKids(cryptoConfig, routes, uri)` 合并查找单点（跨两个正则空间最长命中、同长并集、无命中不限）。两侧配置类新增 `routes` 键（precompile/启动校验 kid 存在性对齐 crypto-config），两侧门面的 kid 白名单统一改走 `effectiveKids`。`crypto-config` 原样保留不弃用（同语义并存，迁移期无限长）。测试：core `RouteRuleTest` 4 例契约 + web/gateway 过滤器层执行用例（含并集放行）。
- 依赖版本：根 POM 现在先 import `encryptor-dependencies`、再 import Spring Boot BOM，`nimbus-jose-jwt` 在 web/gateway/bench 也统一解析为 **9.37.3**；`hutool-all` 已从 core 下移到 web/gateway starter（core 不再传递）。**bcprov/bcpkix 1.78.1 只由 `encryptor-sm` 显式声明**（版本在 BOM 管理）：`encryptor-core` 与各 starter 的 runtime 依赖树里没有 BouncyCastle；SM2 用户必须显式添加 `io.github.cuukenn:encryptor-sm`。
- 全量单测 **251 绿**（core 104、sm 18、starter 10、reactive 4、web 63、gateway 43、micrometer 9），fail/err 均 0。SM 相关用例（`SmCipherSuiteTest` 7、`SmKeyEntryParserTest` 6、`SmDefaultProtocolTest` 5）已从 core 迁到 `encryptor-sm`；core 另新增「SM2 无解析器时提示 encryptor-sm」的 fail-fast 用例（本轮双写面抽取再 +2：`JwksDocument`/`ProtocolAssembler`；配置模型随后下沉 core `config/base`，两侧 `EncryptorConfig` 只保留前缀，未新增用例；`InMemoryNonceStore` 分片 +2；servlet 异步响应加密 +1）。评审修复再加 4：core +1（`nonce-retention ≥ 2*ttl`）、web +2（JSON 明文透传 body 保留、异步交接后请求明文延迟清零）、gateway +1（JSON 明文透传 body 保留）；Minor 收尾 +2：core +2（`MAX_NONCE_LENGTH` 按 UTF-8 字节、`Builder.keys(null)` 明确错误）。此前的 P0/P1 加固（过滤器注册名、`JweContext`/`WebContext`/`GatewayContext` 清零、网关链路清理、网关 HEAD/204 无 body、网关 302 空/带 body、摘要工具与套件 IV 长度、`StrKit` 具名正则诊断、`sendError` 字符集/已提交响应）：core +7（nonce 上限、ReplayGuard 复用、retention 校验/边界、RSA 2048、IV 12、自定义 checker）、web +15（P0 的 204/304/HEAD、sendError/sendRedirect、近上限、302+body、业务异常兜底、reset/302 超限、配置校验，以及 P1 的表单 Content-Length 早检、空 JSON + `require-encrypted=false` 透传）、gateway +6（P0 的 chunked 请求/响应、配置校验，以及 P1 的 writeAndFlushWith 加密/黑名单透传）。增量构成：web +2 / gateway +4 来自 P3-4（`skip-*` 正名 + 旧名 `black-*` alias）的绑定用例；web +7 来自 P2-5 的链序守卫 `FilterChainOrderTest`（向 `WebEncryptorConfiguration` 取生产注册的 bean 按 order 组链，跑三载体往返 + 响应回加密 + 链尾清 ThreadLocal；把 `encryptorReqParamsFilterOrder` 改 -9 会红 2 例）；gateway +3 来自 D3 的 `CryptoExecutorTest`；micrometer 8 是 D1/D3 新增的可选模块（监听器计数 3 + 自动装配条件 4 + 接线证明 1）。本轮多监听器支持 +9：core +6（`CompositeEncryptorListenerTest` 5：按序扇出/单监听器异常隔离/多监听器互不影响/空集合等价 NONE/异常 WARN 日志含回调名与异常栈；`JweCodecListenerTest` 1：直接 `new JweCodec(...)` 时监听器异常也不改变结果）、servlet starter +1 与 reactive starter +1（两处都验证两个 listener bean 全部接上协议栈）、micrometer +1（用户监听器与指标监听器同时收到回调）。
- CI（`.github/workflows/ci.yml`，temurin **8/11/17 矩阵**）已在本地 JDK 8/11/17 各跑过 `-Pmain-module clean install`（此前 228 绿）；本轮摘要工具/套件 IV/`StrKit`/`sendError` 改动后 JDK 11 为 **236 绿**，引入 `encryptor-sm` 拆分后 JDK 11 为 240 绿，双写面抽取（`JwksDocument`/`ProtocolAssembler`）后为 **242 绿**，`InMemoryNonceStore` 分片后为 244 绿，servlet 异步响应加密后为 **245 绿**，评审修复后为 249 绿，Minor 收尾及 `encryptor-sm` 包名迁移后 JDK 8/11/17 均为 **251 绿**（ECDH-ES 走 SunEC 的 `KeyAgreement ECDH`，含 nimbus `ECDHEncrypter` oracle 互通用例）；JDK 8 任务的 `-Pall-modules -DskipTests package` 也已在评审修复后复跑通过（保证示例与 bench 能编译），两份 `jwe.js` 的 `diff` 一致（双写面守卫）。JMH 阈值脚本**故意不进 CI**（共享 runner 上噪声大）。
- CI 的 JDK 8 任务新增**依赖面守卫**：core + 四个 starter 的 runtime 依赖树不得出现 `org.bouncycastle` 或 `encryptor-sm`（`dependency:tree -Dincludes=... -Dscope=runtime -DoutputFile=...`），防止 BC/可选模块重新传递到消费者。
- **boot3 线（2026-10-22 落地）**：`JAVA_HOME=…/jdk-17 mvn -B -Pboot3 clean install` → BUILD SUCCESS **181 绿**（spring-boot3-starter 11 / web-boot3 92 / gateway-boot3 62 / boot3-example 16，与 javax 线逐类对等）。CI 新 job `boot3`（temurin **17/21 矩阵**：先 `-Pmain-module -DskipTests install` 预装 javax 制品，再 build+test；复制对 diff 守卫与 boot3 依赖树守卫跑在 17 档）。⚠️ `-Pmain-module,boot3` 组合激活会把 boot3 的 `spring-boot.version=3.5.16` 等属性混进整个 reactor、掀掉 javax 线 BOM 锚点——两个 profile 只能分两条命令先后跑。
- **发布面（boot3）**：`publish.yml` 仍只发 javax 线（`-P '!all-modules,main-module,release' deploy`）；boot3 线真实 `deploy` 命令与发布面 spike dry-run 结论见 `open-issues-v2-history.md`「2026-10-22 boot3 双线」。
- `mvn -B -Pall-modules -DskipTests package` → BUILD SUCCESS：示例（web-example / gateway-example）与 bench 都能在"core/starters 无 BC、示例显式带 encryptor-sm"的依赖形态下编译打包；bench 的 runtime 树仍无 BC。
- ⚠️ **示例测试源码必须能编过 JDK 8**（`mvn -Pall-modules` 会编 examples 的 test 源码）：`HttpTest.java` 曾用 `URLEncoder.encode(String, Charset)`（**Java 10+** 才有）→ JDK 8 下编译失败；已改为自带 `enc(String)` helper（`URLEncoder.encode(s, "UTF-8")` 包一层）。两份 `HttpTest.java` 是成对文件，改一处必须同步另一处。
- P3-4（`skip-*` 正名 + 旧名 alias）：⚠️ 新旧名单**不能共用同一个 list**——Spring Boot 对集合属性是"就地绑定（clear + 回填到 getter 返回的 list）"，共用时后绑定的会把先绑定的清掉。现为「旧名独立字段 + `InitializingBean.afterPropertiesSet()` 合并去重」。
- JMH（M1 Pro / JDK 11，三次运行中位数，`-wi 2 -i 3 -f 1 -prof gc`）：RSA 往返 1020 ops/s、ECDH-ES 往返 1438 ops/s（**≈1.4×，非数量级**，差值来自 P-256 协商 vs RSA-2048 私钥运算 ≈0.29 ms/op）；4 线程解封并行度 RSA 3.94× / ECDH-ES 3.99×（阈值 2.5×）；bytes/op 73018（基线 72792，+0.3%，阈值 +10%）。完整表与复现命令见 `README.md`「性能基准（JMH）」。
- ⚠️ `bench.jar` 的两个坑：①`EcdhEsBenchmark` 必须显式传 `allowedAlgs={ECDH-ES}`（空集合会取协议默认 `RSA-OAEP-256` → 构造期 fail-fast）；②JMH setup 失败时只在日志里打堆栈、**exit code 仍是 0**，必须查 `bench.log`/`check-thresholds.sh` 而不能只看退出码。
- ECDH-ES（P-256）端到端已复验（全 JIT 手起实例）：web-example `node front/test.js` 11/11、gateway-example 10/10（2026-10-18 时点数；test.js 现为八组）；core 另以 nimbus `ECDHEncrypter` 为独立 oracle 做双向互通单测。
- 国密（SM2+SM4-GCM）在示例里已可自证：两个示例都自带 SM2 演示密钥，用独立 SM 客户端（手拼 SM2 C1C3C2 + SM4-GCM，不复用 core）打 `/test/hello` 各 **12/12 PASS**（含重放/篡改/未知 kid/AAD 不匹配四条拒绝面）；同一实例上 `node front/test.js` 仍全绿。
- ⚠️ 网关 starter 已显式排除 `spring-security-rsa` 传递的 `bcprov/bcpkix/bcutil-jdk15on`（旧的 1.69 系列）；新增依赖若重新把 `*-jdk15on` 带回 compile/runtime，会与 `encryptor-sm` 的 `*-jdk18on:1.78.1` 形成双 BC 血统。根 POM 的 enforcer 已禁止 `org.bouncycastle:*-jdk15on`，依赖树守卫也应保持为空。
- 真实端到端（RSA 路径，全 JIT）：web-example(8081) 与 gateway-example(8080→8082) 的 JWE 三载体 + 篡改用例全 PASS；两个 JWKS 端点 200 + ETag。
- 评审修复的裁定（RF-1/2/3）与 5 条明确推迟的 Minor（D1–D5）见 `docs/architecture/open-issues-v2-history.md` 的「v2 整分支评审修复」章节。
