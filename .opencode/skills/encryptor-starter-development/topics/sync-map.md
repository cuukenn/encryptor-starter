# 同步面全景（成对文件 + boot3 复制对 + 协议变更扩散）

改任何"成对"文件只改一边 = "servlet 正常、网关失败"或 CI 红。协议/行为变更前**全文必读**。

## 成对文件对照表（servlet ↔ reactive/gateway）

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
| `encryptor-examples/web-example/front/encryptor/jwe.js` | `encryptor-examples/gateway-example/gateway/front/encryptor/jwe.js`（boot3-example 第三份，CI pairwise） |
| `encryptor-examples/web-example/src/main/resources/application.yml` | `encryptor-examples/gateway-example/gateway/src/main/resources/application.yml` |

**协议变更（JWE 头字段、AAD claims、载体字段名 `jwe`、`kid` 语义、alg/enc 取值）额外同步**：各示例 `HttpTest.java`（成对，surefire 排除仅编译级守护）、各份 front `jwe.js`、设计文档（含 §3.11 演进通道——additive claim + 软接受，勿破坏）。

## boot3 复制对（`scripts/javax-to-jakarta.sh --diff`，CI 守卫）

- javax 源码经机械替换（`javax.servlet` → `jakarta.servlet`）后必须与 boot3 模块**逐字节一致**；starter/web 对零源码豁免；gateway 对登记少量 API 适配豁免文件（`getMethodValue()`/`getStatusCode()` 代际差异，清单 = ci.yml 的 `--expect-diff`）——豁免文件不参与红/绿，属**人审面**（CI 日志 `EXEMPT-FILES-INSPECT` 标记），改这些文件时 javax↔boot3 差异要人工核对。
- 登记口径：pattern 以 `main/java/...` 起头（带 `src/` 前缀恒不命中）；pom 与 `spring.factories` 差异默认豁免；`--exclude spring.factories` 同时断言 boot3 侧不得重新引入（`SPRING-FACTORIES-CREEP`）。
- **改 javax 复制对源文件 = 必须同步 boot3 对位**（机械替换口径）；改协议 = javax servlet / reactive 共享线 / boot3 复制线三处一起。
- reactive / micrometer **无 boot3 副本**（main 零 `javax.*`，Boot 3.x 直接复用 javax 线 jar）——改动同时进两线，测试面在 `encryptor-examples/boot3-example`。
- 自动装配双注册：各 starter 同时留 `spring.factories`（Boot < 2.7）与 `AutoConfiguration.imports`；boot3 复制模块只留 imports。删除 spring.factories 前必须先决定放弃 Boot < 2.7 且各 starter 同步。

## 示例与端到端（同步对象 + 手动验证）

- 三份 front `jwe.js`（WebCrypto 参考实现）逐字节一致（CI pairwise）；test.js 只做语法检查，组数语义靠人审。
- 端到端（HttpTest / test.js / 独立 SM 客户端）为手动验证：先起示例服务（端口见各示例 `application.yml`；gateway 下游是**不带 encryptor 的普通应用**）；示例测试源码必须编过 JDK 8。
