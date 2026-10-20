# encryptor-examples

> ⚠️ **本文是 v1 协议时代的架构记录（2026-10-16）；v2 JWE 协议重做（2026-10-17）后大部分内容已失效。**
> 当前事实以源码为准：入口 `AGENTS.md`，协议定义 `docs/superpowers/specs/2026-10-16-payload-security-protocol-design.md`，v1→v2 处置见 `open-issues.md`/`security-review.md` 顶部状态表。


> 三个可运行的示例应用 + 两套 JS 前端 Demo。**这是验证改动的端到端靶场**，也是唯一跑真实 HTTP 的地方。

| 目录 | artifactId | 作用 |
| --- | --- | --- |
| `encryptor-examples/web-example/` | `web-example` | Spring MVC 服务端示例（网关场景里的"下游服务"也复用它这套代码） |
| `encryptor-examples/gateway-example/gateway/` | `gateway-example` | Spring Cloud Gateway 示例（含限流外的加解密网关） |
| `encryptor-examples/gateway-example/web/` | `gateway-example-web` | 网关后面的普通业务服务（**未引入 encryptor**） |
| `encryptor-examples/` | `encryptor-examples`（`pom`） | 聚合模块 |

> **依赖提示**：`web-example` 与 `gateway-example/gateway` 的 `pom.xml` 都显式添加了可选模块
> `encryptor-sm`（它们的 `application.yml` 带 SM2 演示密钥）；starter 本身不传递该依赖。
> `gateway-example/web` 依旧完全不引入 encryptor。

## web-example

| 文件 | 内容 |
| --- | --- |
| `src/main/java/.../example/web/WebApplication.java` | `@SpringBootApplication`；注册 `@Bean CheckerStrategy nonceChecker() = new InMemoryNonceChecker(1000, Duration.ofSeconds(30))` |
| `src/main/java/.../example/web/web/TestController.java` | `GET /test/hello?name=`、`POST /test/hello`(JSON)、`POST /test/hello`(form-urlencoded)、`GET /test/secret?name=`（**uri 级 `crypto-config` 的演示端点**，见下） |
| `src/main/resources/application.yml` | `server.port=8081`，`encryptor.config.crypto-config.{private-key,public-key}`；**外加一条 uri 级覆盖** `encryptor.config.web.crypto-config."[^/test/secret.*]"`（括号写法，另一对密钥） |
| `src/test/java/.../example/web/CryptoConfigBindingTest.java` | `@SpringBootTest(RANDOM_PORT)`：断言含 `.` 的正则 key 被**原样绑定**（括号写法必需性的证据），CI 可跑 |
| `src/test/java/.../HttpTest.java` | ❗**不是单元测试而是端到端脚本**：手工构造 RSA/AES 报文打真实端口（`http://127.0.0.1:8081/test/hello`，另有 `/test/secret` 走 uri 级密钥）。**需要先启动应用**，否则失败；2026-10-16 起带真断言 |
| `front/` | Node Demo 客户端：`encryptor/rsa.js`、`encryptor/aes.js`、`encryptor/random.js`、`encryptor/md5withaes.signature.js`，`index.js`/`test.js` 是入口；依赖 `axios`、`crypto-js`、`node-forge`、`qs` |

## gateway-example

- `gateway/`：端口 `8080`，路由 `Path=/test/**` → `http://127.0.0.1:8081`；配置里写的是 `encryptor.config.reactive.crypto-config.*` 和 `encryptor.config.reactive.gateway.skip-able`（**注意多一层 `reactive`**）。`GatewayApplication` 同样注册 `InMemoryNonceChecker(1000, 30s)`。
- `web/`：端口 `8081` 的普通服务，只有 `spring-boot-starter-web` 和 `TestController`，没有 encryptor 依赖 → **加密在网关上终结，下游看到的是明文**。
- `gateway/front/`：与 web-example 同款的 JS Demo 客户端。
- `gateway/src/test/java/.../HttpTest.java`：同样是需要两个应用都在跑的端到端脚本。

## 怎么用来验证改动

```text
终端 A：mvn -pl encryptor-examples/web-example -am install   # 先装 starter，再启动
        mvn -pl encryptor-examples/web-example org.springframework.boot:spring-boot-maven-plugin:2.7.18:run
终端 B：跑 web-example 的 HttpTest（见下方"怎么跑端到端"；当前它已带断言）
网关场景：
终端 A：gateway-example/web（8081，普通下游）→ mvn -pl encryptor-examples/gateway-example/web org.springframework.boot:spring-boot-maven-plugin:2.7.18:run
终端 B：mvn -pl encryptor-examples/gateway-example/gateway org.springframework.boot:spring-boot-maven-plugin:2.7.18:run（8080）
```

> ⚠️ `mvn spring-boot:run` 这个**前缀在本仓不可用**（POM 没有声明 `spring-boot-maven-plugin`，只能写全坐标 `org.springframework.boot:spring-boot-maven-plugin:2.7.18:run`）。
> ⚠️ 网关场景的**下游必须是没有引入 encryptor 的 `gateway-example/web`**；拿 `web-example` 当下游会 400（网关转发的是明文参数，下游 starter 会再解密，见 `security-review.md` S16）。
> ⚠️ 这两个 `HttpTest` 被 surefire **刻意排除**，要跑得显式放开：`-Dtest=HttpTest -Dsurefire.excludes= -DfailIfNoTests=false -DtrimStackTrace=false`。

> 这两个 `HttpTest` 用 `@Test` 暴露手工脚本：**在 CI 里没有先起服务时必然失败**，改动测试相关代码前先确认这一点，不要误判为回归。2026-10-16 起它们**都带真实断言**（HTTP 200 + 解出的明文内容），并已真实跑通（顺带修掉 3 个此前被"无断言"掩盖的示例 bug：网关 `application.yml` 的 `skip-able:` 空值导致起不来、web 的 `HttpTest` 误用网关密钥对、GET 查询串未做 URL 编码）。

## 坑

- `web-example/pom.xml` 里的 `<build><finalName>gateway</finalName></build>` 是复制粘贴遗留，产物名与模块名不符。
- 示例里的 RSA 密钥对是**明文硬编码在仓库和 yml 里**的 demo 密钥，只能用于示例。
- `encryptor-examples` 只在 `all-modules` profile（默认）里参与构建，`main-module` profile 会跳过它——所以 `mvn -Pmain-module install` 之后示例不会更新。
