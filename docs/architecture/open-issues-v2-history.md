# open-issues v2 复查记录

> 从 [open-issues.md](open-issues.md) 拆出，记录 v2 协议重做及之后的复查/修复；v1 原始记录见 [docs/archive/open-issues-v1.md](../archive/open-issues-v1.md)。

## 2026-10-22 boot3 双线

> 设计来源：`docs/superpowers/specs/2026-10-21-multi-boot-version-support-design.md`（§1 意图：单分支、每代独立 Maven 模块、artifact `-boot3` 后缀；javax 线 1.0.0 不动，boot3 线 3.0.0 自管版本）。用户拍板见该文档 §7。本节记录验证型裁定与发布面 spike。

### 拓扑裁定（验证先行）

- **gateway starter：复制为 `encryptor-gateway-boot3-starter`（共享 jar 实测失败）**。共享 javax 线 jar 在 Boot 3.5 / SCG 2025.0 下任何请求都无法处理——Spring 6 删改两个 reactive API，字节码级 `NoSuchMethodError`：`ServerHttpRequest.getMethodValue()` 已移除、`getStatusCode()` 返回类型 `HttpStatus`→`HttpStatusCode`；JWKS 过滤器是 order -14 的 WebFilter，第一个请求即断连。复制面随后做了**最小 API 签名适配**（7 处，语义零变更：`getMethod().name()` ×4、`HttpStatusCode` ×2 + import），并在 diff 守卫脚本以 `--expect-diff` 登记——机械替换脚本修不了字节码描述符变化，这类改写必须"复制时人工修订 + 守卫登记"，不能指望纯机械。
- **reactive starter：共享（实测通过）**。main 源码零 `javax.*`；Boot 3.5 下 `EncryptorReactiveAutoConfiguration` 装配、配置绑定、fail-fast、协议栈行为全对等（重放被 REPLAY 拒绝）。**micrometer starter：共享（实测通过）**——真实 Boot 3.5 应用内 `@AutoConfigureAfter(MetricsAutoConfiguration)` 被尊重、计数递增；跟进项：与真正提供 MeterRegistry 的 `SimpleMetricsExportAutoConfiguration` 之间无排序约束（靠全量 imports 排序偶然在后），扩名进**季度复盘**（javax 线不动）。成果：全项目只有 3 个 `-boot3` 模块（starter/web/gateway），reactive/micrometer 零复制。
- **三风险点全部落成正向 gate 用例**（在 `encryptor-examples/boot3-example`）：SCG 过滤器 ordering（三载体经真实 Netty+SCG 2025.0 链路）、`DataBufferLimitException` 413 路径（限宽内/超限两侧）、`@AutoConfigureAfter` 装配次序（计数递增证据）。

### 复制工程的两个最有价值事实

- 🟡 **Surefire 假绿坑**：boot3 复制模块继承根 pluginManagement 的 surefire `2.22.2`，其自带 launcher 与 Boot 3.5.16 的 JUnit Platform 1.12 不对齐 → `OutputDirectoryProvider not available`，**先是 "Tests run: 0" + BUILD SUCCESS 假绿**（一个测试都没跑也算成功）。修法：boot3 模块 pom 内显式 pin surefire `3.5.4`（模块内自含，不动 javax 线）。⚠️ 升 surefire/JUnit 平台代际冲突时，测试"静默 0 跑过"是常态而非异常，必须核对测试计数而非只看 BUILD SUCCESS。
- 🟡 **BOM 插值错位兜底**：root `pom.xml` 的 BOM import 写 `<version>${project.version}</version>`；boot3 模块自管 3.0.0 → 误解析成 `encryptor-dependencies:3.0.0`（不存在）→ 全部托管版本失效（首次构建 FATAL）。"属性覆写"（root `boot3` profile 锚 Boot/Cloud/SCA 版本）对**继承版本的普通子模块**可行，但覆盖不了自管版本子的 `${project.version}` 插值路径——每个 boot3 模块 pom 显式 import `encryptor-dependencies:1.0.0` 兜底。同理，gateway-boot3 换 SCG 正名坐标（`spring-cloud-starter-gateway-server-webflux`）后模块内需 import `spring-cloud-gateway-dependencies:4.3.5`（SC 2025.0.3 火车锚定值），否则单独 `-pl` 构建时 POM invalid。**教训：boot3 线每加一个新模块，都要自查"非 Boot-BOM 托管的依赖面"**。

### CI / 守卫落点

- CI 新 job `boot3`（temurin 17/21 矩阵）：先 `-Pmain-module -DskipTests install` 预装 javax 制品（`-Pboot3` reactor 不含 `encryptor-core`，从本地仓库解析），再 build+test（132 绿）；复制对 diff 守卫（三对：starter/web 零豁免、gateway 3 文件 expect-diff）与 boot3 依赖树守卫（三个 boot3 starter runtime 树零 BC / 零 encryptor-sm）跑 17 档。⚠️ `-Pmain-module,boot3` 组合激活会把 boot3 属性混进整个 reactor 掀掉 javax 线 BOM 锚点——两个 profile 只能分两条 Maven 命令先后跑，不得合并。

### 发布面 dry-run spike（2026-10-22，未触网上传）

插件为 `org.sonatype.central:central-publishing-maven-plugin:0.12.0`（root pom `release` profile）。问：parent 1.0.0 + boot3 3.0.0 **混合版本**在同一 reactor 的 bundle 上传是否可行。方法与结论：

- **插件无 `-DdryRun` 参数**（反编译 0.12.0 字节码核实：`publish` goal 有 `skipUpload` / `skipPublishing`，无 dryRun）。本地可证路径 = **`-DskipUpload=true`**：完整走 staging/bundle/checksum 流程，仅在 `ArtifactUploader.upload` 前 return，日志 `Skipping the upload of the bundle at user's request (skipUpload)`——对 Central 零请求，属安全 dry-run。
- **混合版本 bundle 组装成功**：`mvn -B -P'main-module,boot3,release' package + publish -DskipUpload=true`（JDK 17 JVM）→ `encryptor-dependencies/target/central-publishing/central-bundle.zip` 生成，内容含全部 javax 制品 1.0.0（BOM/core/sm/5 starter，sources 齐）+ 三个 boot3 starter **3.0.0（jar/sources/pom + checksums 齐）** + parent 1.0.0 pom，共 165 项。Central 接收的就是这一个 zip，混合 G/V 并存无结构性障碍。
- `-DexcludeArtifacts=boot3-gateway-example` 实测有效（bundle 零 example 条目）——boot3 示例不发布可在发布时传参排除，零 pom 改动。
- **过程坑（四条）**：①裸前缀 `central-publishing-maven-plugin:publish` 解析失败（插件的 group `org.sonatype.central` 不在默认 pluginGroups），要么 `-Prelease` 让插件进 build、要么写全限定 goal；②纯 `java ... publish` 独立目标对 jar 模块报 `The packaging for this project did not assign a file to the build artifact`——artifact 只在 `package`+ 阶段挂到 session，goal 必须与生命周期同跑；③`-P'main-module,boot3'` 若真跑生命周期，boot3 属性会污染 javax 模块编译（Boot 3.5 的 jakarta 类classpath）；④java 11 的 Maven JVM 加载不了 Boot 3.5 插件（class-file 61）→ 混合单命令必须 JDK 17 JVM + `-Dmaven.main.skip=true`（ javax 制品沿用既有 target 产物）。
- **推荐发布形态**：维持 publish.yml 的 javax 一条命令不动（`-P '!all-modules,main-module,release' deploy`，v1.0.0 已用同款命令发出）；boot3 线真实发布另开一条 `JAVA_HOME=17 mvn -B -P'!all-modules,main-module,boot3,release' deploy -DexcludeArtifacts=boot3-gateway-example`（每线一个 reactor，属性零污染；混合单命令的 SPIKE 形态已证可行但须四个非默认 flag，不适合做常态）。**是否把 `excludeArtifacts` 固化进 root pom 的插件配置，留一次真实发布演练时再定**（本次不动 pom）。
- **本地不可证，需 CI/真实发布人工验证**：①真实凭据上传（`publishingServerId=central` 的 Portal token 在 CI secrets，本地无凭据）；②Portal 校验段——本 dry-run bundle **零 `.asc`**（GPG 签名在 `verify` 阶段，dry-run 未跑签名），签名/javadoc 齐备性须真实 `verify` 流程出；③上传后 Portal 的校验/人工 Publish 按钮。判定：**bundle 组装与混合版本可行性本地已证；上传+校验留真实发布时人工验证**。

### 收尾状态

- 全量回归三绿（2026-10-22）：`-Pmain-module` 251 绿（JDK 11）、`-Pboot3` 132 绿（JDK 17）、`-Pall-modules` 251 绿 + 两示例 + bench 编译打包成功（JDK 11）。
- 文档落地：README 选型表（Task 5）、AGENTS.md 模块表/依赖图/boot3 复制对守卫口径、`encryptor-dependencies.md` 双代升级口径（本节同批）。

## 2026-10-21 工程收尾

- **P2-2 翻绿**：`open-issues.md` 状态表更新——CI（`ci.yml`）已含 `mvn -B -Pall-modules -DskipTests package`（示例 + bench 编译闸门）与两份 `jwe.js` 的 `diff` 守卫（2026-10-18 落地，本日复核确认）。
- **`AutoConfiguration.imports` 迁移（保守双写）**：5 个 starter（starter/reactive/web/gateway/micrometer）各新增 `META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports`（内容为对应装配类 FQCN 单行），与既有 `spring.factories` 并存（Boot 去重，不重复注册）；不加 `@AutoConfiguration` 注解、零 main 源码改动。`mvn -B -Pmain-module clean install` → BUILD SUCCESS。删除 `spring.factories` 需先确认放弃 Boot < 2.7 兼容。

## 2026-10-20 当前分支整分支复核修复

> 对本轮 BC 可选化、双写面抽取、nonce 分片、servlet 异步响应加密的完整工作树做独立复核；无 Critical，Important 5 条已修，Minor 逐条记录。

- **网关 BC 泄漏**：`spring-cloud-starter-gateway` 经 `spring-security-rsa` 带入 `bcprov/bcpkix/bcutil-jdk15on:1.69`；gateway starter 已显式排除，根 POM enforcer 禁止 `org.bouncycastle:*-jdk15on`；`gateway-example` 去掉重复直连 gateway starter 的依赖。
- **servlet 异步写回时机**：新增 `TrackingAsyncContext`，在 `complete()/dispatch()` 前加密写回，`onComplete` 仅作兜底，避免容器已提交响应时得到空 200。
- **`require-encrypted=false` 明文 body 透传**：servlet 用 `CachedBodyHttpServletRequest` 回放缓存；gateway 用 `ServerHttpRequestDecorator` 重新提供 body。
- **防重放未来时间偏移**：内置 nonce 存储要求 `nonce-retention >= 2 * ttl`，未配置时默认 `2 * ttl`，关闭“未来 ts + 短保留期”的重放窗口；自定义 `NonceChecker` 不受此限制。
- **异步交接的明文所有权**：`startAsync` 时同时转移 `WebContext.bodyPlaintext`，参数过滤器 `finally` 不再提前清零；监听器完成后统一 `destroy()`。

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

### 明确推迟（Minor）——D1/D2/D3 已落地（表内 🟩），本表保留原推迟理由以便追溯

| 编号 | 内容 | 推迟理由 |
| --- | --- | --- |
| D1 🟩 | 无 Micrometer 适配器（只有 `EncryptorListener` SPI） | **2026-10-18 已实现（可选模块）**：新增 `encryptor-micrometer-spring-boot-starter`，metrics 依赖只在显式引入该模块时出现——core 与两个 starter 的依赖面仍为零 metrics |
| D2 🟩 | 204/重定向等空响应两侧行为不对称 | **已对齐**：servlet 的 204/304/HEAD、空 302 与带 body 302 均有测试（`EncryptorResponseFilterTest`）；gateway 的 204、空 302、带 body 302 同样有测试（`GatewayJweTest`）。空响应不包装，带 body 的 3xx 仍加密 |
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
- `EncryptorMicrometerAutoConfiguration`（`META-INF/spring.factories` 注册）：`@ConditionalOnClass(MeterRegistry)` + `@AutoConfigureAfter(name = "...MetricsAutoConfiguration")`（用字符串名避免硬依赖 actuator）；`EncryptorListener` bean 带 `@ConditionalOnBean(MeterRegistry)`，**不设** `@ConditionalOnMissingBean(EncryptorListener)`——用户自己的监听器与指标监听器并存，两侧 starter 用 `CompositeEncryptorListener` 按 `@Order`/注册顺序组合；内部 `@ConditionalOnClass(CryptoExecutor)` 子配置导出网关指标（`CryptoExecutor` 属 gateway starter，而它是本模块的 **optional** 依赖，故 servlet 应用不会被拖进 Spring Cloud Gateway）。
- pom：`encryptor-core` + `spring-boot-autoconfigure` + `micrometer-core`（版本由 spring-boot-dependencies 管）+ `encryptor-gateway-spring-boot-starter`（optional）+ `spring-boot-starter-test`。`encryptor-starters/pom.xml` 与 `encryptor-dependencies/pom.xml`（BOM）已登记。

**为什么不记耗时**：`EncryptorListener` 只有"结束时"回调，没有开始钩子；要加计时段就得改 core 热路径（`JweCodec`），收益配不上风险。端到端 P99 用 HTTP 层指标（`http.server.requests`）即可覆盖。

**D3 的记账方式（踩坑记录）**：最初想直接读 Reactor 的 `Scannable.Attr.BUFFERED`（`BoundedElasticScheduler.estimateSize()`），实测**恒为 0**——任务被 Reactor 从待派发队列抽进执行器内部队列后就不可见了。改为在 `CryptoExecutor` 内包一层记账 `Scheduler`：`submit` 成功才 `submitted++`、`count` 的 `finally` 里 `completed++`、`RejectedExecutionException` 时 `rejected++` 并原样抛出（不计入 pending）；`pendingTasks()` = submitted − completed。另一个 API 事实：Reactor 3.4.2 的 `Scheduler` 只 `extends Disposable`（**不是** `Scannable`），抽象方法仅 `schedule(Runnable)`/`createWorker()`，覆写 `scanUnsafe` 会编译失败。

**同时改动的生产码（网关侧 D3 hook）**：新增 `reactive/gateway/runtime/CryptoExecutor`（`SCHEDULER_NAME`、`DEFAULT_QUEUE_CAPACITY=1000`、`create()`）；两个网关过滤器不再各自持有 `private static final Scheduler`，改为注入**同一个** `CryptoExecutor`（构造器 4 参）；`GatewayEncryptorConfiguration` 新增 `@Bean @ConditionalOnMissingBean CryptoExecutor`（两过滤器共用、指标模块读同一实例、用户可覆盖）。

**证据**：

- `JAVA_HOME=…jdk-1.8.0_461 mvn -B -Pall-modules clean install` → BUILD SUCCESS，**182 绿**（core 92、starter 9、reactive 3、web 40、gateway 30、micrometer 8），fail/err 均 0。
- gateway 30 = 原 27 + `CryptoExecutorTest` 3（默认取值 / 待执行数记账 / 被拒记账）。
- micrometer 8 = `MicrometerEncryptorListenerTest` 3（计数、分类预建、null→INTERNAL）+ `EncryptorMicrometerAutoConfigurationTest` 4（有/无 registry、用户监听器优先、网关指标导出）+ `MicrometerListenerWiringTest` 1（**接线证明**：真实 reactive starter 与本模块同时装配，`DefaultProtocol.openRequest("not-a-jwe", …)` 抛异常后 `encryptor.decrypt{result=failure}` == 1，且恰好一个分类被计数）。
- 未做：Micrometer 的 Timer/耗时（理由见上）；D2 已于 2026-10-20 对齐（见上表）。

> **2026-10-19 多监听器支持后的增量**：`EncryptorListener` 从单选改为组合（core `CompositeEncryptorListener`，按 `@Order` 扇出；监听器异常记 WARN 后隔离；`JweCodec` 构造器也会自动包装直接传入的监听器）。`EncryptorMicrometerAutoConfigurationTest` 的“用户监听器优先”改为“用户监听器与指标监听器并存”，`MicrometerListenerWiringTest` 新增 1 条两者同时收到回调的接线用例 → micrometer **9**；全量 **191 绿**（core 98、starter 10、reactive 4、web 40、gateway 30、micrometer 9）。
