# AGENTS.md

本文件是给 AI 编码助手（以及新同学）的入口说明。**完整架构文档在 `docs/architecture/`**，按模块拆分，本文件只放"每次都要知道"的部分。

## 这是什么

`encryptor-starter`：一套**数据传输加解密**的 Spring Boot Starter。客户端用 RSA 公钥协商出 AES 参数并加密业务数据、签名，服务端（普通 Web 应用或 Spring Cloud Gateway）验签、解密、处理、再把响应加密回去。

- 语言/构建：**Java 8** + Maven 多模块
- 版本：Spring Boot `2.4.2`、Spring Cloud `2020.0.1`、Spring Cloud Alibaba `2021.1`、hutool `5.8.25`
- groupId：`io.github.cuukenn`，版本 `1.0.0-SNAPSHOT`
- ⚠️ **Boot 2.4 用的是 `META-INF/spring.factories` 自动装配**，不是 2.7+ 的 `AutoConfiguration.imports`

## 构建与验证

```bash
mvn -Pall-modules clean install     # 全量（含 examples）；all-modules 是默认 profile
mvn -Pmain-module clean install     # 只构建 dependencies/core/starters，跳过 examples
mvn -pl encryptor-core -am test     # 单模块 + 它的依赖
mvn -Prelease ...                   # 发布（source/javadoc/gpg/nexus-staging → s01.oss.sonatype.org）
```

- 根 `pom.xml` **没有配置** checkstyle/spotless 之类的静态检查，别去找 lint 任务。
- `encryptor-core` 下的 `*StrategyTest` 是纯单测；`encryptor-examples` 下的 `HttpTest` 是**需要先启动服务**的端到端脚本（在 CI 里会失败，别误判为回归）。
- 发布流程见 `.github/workflows/publish.yml`；push / PR 由 `.github/workflows/ci.yml` 跑 `mvn -B -Pmain-module clean install`。

## 模块 ↔ artifactId（很容易搞错）

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
| `encryptor-examples/web-example/` | `web-example` | jar |
| `encryptor-examples/gateway-example/gateway/` | `gateway-example` | jar |
| `encryptor-examples/gateway-example/web/` | `gateway-example-web` | jar |

## 依赖方向（只允许向下）

```text
encryptor-dependencies (BOM)
        │  import
encryptor-core            ← 加解密内核（无 Spring 上下文；例外：core/checker 带 optional 的 Spring Data Redis）
        ├── encryptor-spring-boot-starter ──── encryptor-web-spring-boot-starter   (servlet)
        └── encryptor-spring-boot-starter-reactive ── encryptor-gateway-spring-boot-starter (reactive)
                                                        └── encryptor-examples
```

## 核心数据流

```text
客户端 ── 用 RSA 公钥加密参数JSON( AES 的 mode/padding/key/iv ) ──► 放进报文的 key 字段
       └─ 用该 AES 加密业务数据 ──► data 字段
       └─ 对 (nonce + timestamp + data) 的 UTF-8 字节签名 ──► signature 字段

报文 = EncryptorDataWrapper{ nonce, timestamp, signature, key, data }
（JSON body 里的字段，或直接摊成 query/form 参数）

服务端 Filter/GatewayFilter → EncryptorFacade
   ├─ negotiateEncoder 用 RSA 私钥解 key → 参数 JSON
   ├─ 按参数构造 AES 加密器 / 签名器
   └─ CheckerStrategy 校验 → 验签 → 解密 → 交业务
```

详细定义见 `docs/architecture/encryptor-core.md`。

## 按任务路由：先读哪个文件

| 你要做的事 | 先读 |
| --- | --- |
| 新增/替换加密、编码、签名、摘要算法；改报文格式或签名内容 | `docs/architecture/encryptor-core.md` |
| 改 servlet 侧 Filter、contentType 白名单、uri 级密钥、请求参数/请求体解密 | `docs/architecture/encryptor-web-starter.md` |
| 改网关链路、query 参数解密、跳过加密、响应改写、gzip（**尚未实现**） | `docs/architecture/encryptor-gateway-starter.md` |
| 改默认算法组合、`IEncryptorFacadeFactory`、`CheckerStrategy` 注册 | `docs/architecture/encryptor-starter.md`（reactive 侧见 `encryptor-starter-reactive.md`） |
| 新增一个 starter 模块 / 改版本与依赖管理 | `docs/architecture/encryptor-dependencies.md` + 对照 `encryptor-starter.md` |
| 跑起来验证、改示例、改前端 Demo | `docs/architecture/encryptor-examples.md` |

需要多步任务时，先用 `.opencode/skills/encryptor-starter-development/SKILL.md` 里的同步清单自检。

## 必须同步修改的地方（双写）

改任一处，另一处必须一起改，否则会出现"servlet 正常、网关失败"：

| servlet 侧 | reactive 侧 |
| --- | --- |
| `encryptor-starter/.../config/CryptoConfig.java` | `encryptor-starter-reactive/.../reactive/config/CryptoConfig.java` |
| `encryptor-starter/.../config/EncryptorConfig.java` | `encryptor-starter-reactive/.../reactive/config/EncryptorConfig.java` |
| `encryptor-starter/.../constant/EncryptorConstant.java` | `encryptor-starter-reactive/.../reactive/constant/EncryptorConstant.java` |
| `encryptor-web-starter/.../converter/*`、`.../filter/*` | `encryptor-gateway-starter/.../reactive/gateway/converter/*`、`.../filter/*` |
| `encryptor-web-starter/.../config/WebEncryptorConfig.java` | `encryptor-gateway-starter/.../gateway/config/GatewayEncryptorConfig.java` |

**协议变更（`EncryptorDataWrapper` 字段、参数 JSON 的 `mode`/`padding`/`key`/`iv`、`x-key` attribute、签名输入）还要同步：**
**`encryptor-examples/*/front/encryptor/*.js` 与 `encryptor-examples/web-example/src/test/**/HttpTest.java`、`encryptor-examples/gateway-example/gateway/src/test/**/HttpTest.java`（两个 HttpTest 里也硬编码了 mode/padding）。**

## 配置前缀一览

| 场景 | 前缀 |
| --- | --- |
| 通用（servlet） | `encryptor.config.*` |
| 通用（reactive） | `encryptor.config.reactive.*` |
| web | `encryptor.config.web.*`（含 `failure-status`、`max-request-size`） |
| gateway | `encryptor.config.reactive.gateway.*`（含 `failure-status`、`max-request-size`） |

## 已知问题（详见各模块文档的"坑"）

1. 🟩（2026-10-16 已修，**经 `mvn` 验证**）`EncryptorWebFilter.java:49-50`（web）与 `EncryptorGatewayFilter.java:48-49`（gateway）**曾**用 `config.getCryptoConfig().get(uri)` 而不是 `get(bestMatchStr)`，导致 uri 级 `crypto-config` 正则匹配失效；两处均已改并各配了回归用例。（gateway 那条用例当时是坏的——它让工厂 `return null`，撞上 `MockServerWebExchange` 的 `ConcurrentHashMap` 不接受 null value 而 NPE，已改。）
2. 🟩（2026-10-16 已实现 → **当批又改为不再泄漏**，经 `mvn` 验证）`GroupEncryptor.encrypt/decrypt` **曾**直接 `return null`；后来按 `EncryptorStrategyTest` 契约实现，但"按**明文**分组独立加密"等于分组 ECB（相同明文块 → 相同密文块）。**现已改为"整段只加解密一次、分组只切分编码后的密文"**，泄漏消失、往返不变；⚠️ 语义变更：`groupSize` 现在数的是**密文字符数**（见 `open-issues.md` P2-8）。
3. 🟩（2026-10-16 已修）`README.md` 曾声称支持**网关 gzip encode/decode**（代码里从未实现），该错误声明已从特性列表删除。
4. `black*` 配置项名字与"跳过加密名单"语义相反，且匹配是**正则**不是通配符（**且是整串匹配**：`ReUtil.isMatch` 等价 `Pattern.matches`，要前缀匹配得写 `.*`，实证见 `open-issues.md` P3-6）。另：`crypto-config` 的 uri 正则 key **含 `.` 时必须用 `[key]` 括号写法**，否则 Spring Boot 会静默把 key 改坏（实测 `^/test/secret.*` → `testsecret`，不报错），见 P3-7 与 `encryptor-examples/web-example` 的 `CryptoConfigBindingTest`。
5. 🟩（2026-10-16 已修）`GatewayEncryptorConfiguration` 的 logger 误用了 `EncryptorReactiveAutoConfiguration.class`，已改用本类。
6. 🟩（2026-10-16 已修）`README.md` 里的依赖坐标 groupId 曾写成 `io.github.cuukenn.encryptor`（实际 `io.github.cuukenn`），已全部改正，并补全了三个 mvnrepository 链接。
7. 🟩（2026-10-16 第三批扫描发现 → **当批全部修完，经 `mvn` 验证 + 真实端到端跑通**）网关侧 `x-gateway-encryptor-enable` 与 `x-gateway-encryptor-request-enable` 两个常量**值相同**，导致 `black-req-content-type` 在网关侧静默失效（已给 request 侧独立值）；`EncryptorKit.decrypt` 提前拆箱 `Long timestamp`，缺字段直接 NPE（已改为先做字段存在性校验，统一抛 `EncryptorException`）；带 `;charset=UTF-8` 的表单请求识别失败（两侧 `canRead` 改用 `isCompatibleWith`）。**同批当时未修、现已全部修完**：`black-res-content-type` 求值时机（P1-9）、参数包装器只覆写一半（P1-11）、错误面统一 + 新增 `failure-status` 配置（P1-12）、报文大小上限 `max-request-size` + 网关切 `boundedElastic`（P1-13）、每请求重建 RSA/AES 与响应重复 RSA（P2-7）、`GroupEncryptor` 分组泄漏（P2-8）、死代码清理（P2-9）、`@ComponentScan` → `@ConditionalOnMissingBean`（P2-10）、`StrKit` 契约（P3-6）、pom `<name>` 去重 + enforcer（P3-8）。完整条目见 `docs/architecture/open-issues.md` 的 **P0-6 / P0-7 / P1-9 ~ P1-13 / P2-1 / P2-7 ~ P2-10 / P3-6 / P3-8**，机制级见 `security-review.md` 的 **S14 ~ S17**（S1/S3 已补可执行证据）。
8. 🛠️ **教训（P2-9 自我更正）**：`bcpkix-jdk18on` 曾被判定为"无引用 = 无用依赖"并删除，结果 4 个国密用例立刻报 `CryptoException: SM4 KeyGenerator not available`——**hutool 的 SM2/SM4 依赖 BC 提供的 JCA provider，源码里没有直接引用**。已加回 `encryptor-core/pom.xml` 并注释用途。**删依赖前要跑全量测试，别只看 grep。**
9. ⚠️（2026-10-16 端到端发现）网关的**下游必须是没有引入 encryptor 的普通应用**（`encryptor-examples/gateway-example/web`）：网关转发给下游的已是**明文**参数，下游若自己也带 starter 会再解一次密 → `key=null` → P1-12 之后是 **400**（架构约束，见 `security-review.md` S16）。另：网关示例 `application.yml` 的 `skip-able:` 曾是**空值**导致 boolean 绑定失败、网关**根本起不来**（已改 `false`）。

**完整清单（P0–P3，含修法与验证方式）见 `docs/architecture/open-issues.md`；机制级（密码学/协议）审查见 `docs/architecture/security-review.md` —— 首要结论：本机制不提供客户端身份认证，签名只保证报文自洽（公钥是公开的，任何人都能伪造合法请求）。**

**✅ 构建状态（2026-10-16）**：本机跑通了 `mvn -B clean install`（默认 all-modules，含 examples）——**BUILD SUCCESS，73 个测试全绿**（core 43 / reactive 1 / web 17 / gateway 10 / web-example 2）。此外示例已**真实起服务跑通端到端**：web-example（8081，含 uri 级 `crypto-config` 正向/反向两条）、gateway（8080，下游用 `encryptor-examples/gateway-example/web`）。Maven 在 **`/usr/local/maven/3.8.9/bin/mvn`**（不在 PATH），`java`/`javac` 11.0.28。排障提示：surefire 默认 `trimStackTrace=true` 会把栈裁到只剩测试方法一行，定位失败请加 `-DtrimStackTrace=false`。**第一批 ~ 第三批已落盘的修复（P0-1/P0-2/P0-5/P0-6/P0-7/P1-1/P1-5/P1-7/P1-8/P1-9/P1-10/P1-11/P1-12/P1-13/P2-1/P2-4/P2-6/P2-7/P2-8/P2-9/P2-10/P3-6/P3-7/P3-8）均已随这次构建验证通过。**
- 新增配置项：`encryptor.config.web.failure-status` / `encryptor.config.reactive.gateway.failure-status`（报文非法时的 HTTP 状态，默认 400）、`encryptor.config.web.max-request-size` / `encryptor.config.reactive.gateway.max-request-size`（字节，默认 1MiB，`<=0` 不限）。

**🧪 机制行为已固化为可执行断言**：`encryptor-core/src/test/java/io/github/cuukenn/encryptor/audit/CryptoMechanismAuditTest.java`（5 条）钉住了签名输入歧义（S7）、固定 (K,IV) 的确定性（S14）、篡改可检出、畸形签名逃逸为 `CryptoException`（S15）、`GroupEncryptor` **不再**明文分组泄漏（P2-8）；`encryptor-core/src/test/java/io/github/cuukenn/encryptor/audit/ClientAuthAuditTest.java`（2 条）钉住了两条"设计非目标"：**S1** 只持公钥即可伪造合法请求、**S3** 服务端接受任意客户端自选算法（无白名单）——**改这些行为时它们会报警**，请连同 `security-review.md` 一起更新。

## 约定

- 注释/Javadoc 用中文，类头保留 `@author changgg`。
- 配置类：`@ConfigurationProperties(prefix = ...)` + `@EnableConfigurationProperties`，一律提供 getter/setter（不用 Lombok，Java 8 项目无 Lombok 依赖）。
- 自动装配类：`@Configuration(proxyBeanMethods = false)` + `@ConditionalOnProperty` / `@ConditionalOnMissingBean`，让使用方能覆盖。
- 新增策略实现放 `encryptor-core` 对应子包；core 里**不要新增** Spring 依赖（现状例外：`core/checker/InRedisNonceChecker` 依赖 optional 的 `spring-boot-starter-data-redis`）。
- 改完至少跑 `mvn -Pmain-module clean install`（根 POM 已固定 `maven-surefire-plugin:2.22.2`，JUnit5 测试才会真正执行；`**/HttpTest.java` 是需要先起服务的端到端脚本，已从 surefire 排除）。
