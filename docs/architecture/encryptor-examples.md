# encryptor-examples

> 三个可运行的示例应用 + 两套 JS 前端 Demo。**这是验证改动的端到端靶场**，也是唯一跑真实 HTTP 的地方。

| 目录 | artifactId | 作用 |
| --- | --- | --- |
| `encryptor-examples/web-example/` | `web-example` | Spring MVC 服务端示例（网关场景里的"下游服务"也复用它这套代码） |
| `encryptor-examples/gateway-example/gateway/` | `gateway-example` | Spring Cloud Gateway 示例（含限流外的加解密网关） |
| `encryptor-examples/gateway-example/web/` | `gateway-example-web` | 网关后面的普通业务服务（**未引入 encryptor**） |
| `encryptor-examples/` | `encryptor-examples`（`pom`） | 聚合模块 |

## web-example

| 文件 | 内容 |
| --- | --- |
| `src/main/java/.../example/web/WebApplication.java` | `@SpringBootApplication`；注册 `@Bean CheckerStrategy nonceChecker() = new InMemoryNonceChecker(1000, Duration.ofSeconds(30))` |
| `src/main/java/.../example/web/web/TestController.java` | `GET /test/hello?name=`、`POST /test/hello`(JSON)、`POST /test/hello`(form-urlencoded) |
| `src/main/resources/application.yml` | `server.port=8081`，`encryptor.config.crypto-config.{private-key,public-key}` |
| `src/test/java/.../HttpTest.java` | ❗**不是单元测试而是端到端脚本**：手工构造 RSA/AES 报文打真实端口（`http://127.0.0.1:8081/test/hello`）。**需要先启动应用**，否则失败 |
| `front/` | Node Demo 客户端：`encryptor/rsa.js`、`encryptor/aes.js`、`encryptor/random.js`、`encryptor/md5withaes.signature.js`，`index.js`/`test.js` 是入口；依赖 `axios`、`crypto-js`、`node-forge`、`qs` |

## gateway-example

- `gateway/`：端口 `8080`，路由 `Path=/test/**` → `http://127.0.0.1:8081`；配置里写的是 `encryptor.config.reactive.crypto-config.*` 和 `encryptor.config.reactive.gateway.skip-able`（**注意多一层 `reactive`**）。`GatewayApplication` 同样注册 `InMemoryNonceChecker(1000, 30s)`。
- `web/`：端口 `8081` 的普通服务，只有 `spring-boot-starter-web` 和 `TestController`，没有 encryptor 依赖 → **加密在网关上终结，下游看到的是明文**。
- `gateway/front/`：与 web-example 同款的 JS Demo 客户端。
- `gateway/src/test/java/.../HttpTest.java`：同样是需要两个应用都在跑的端到端脚本。

## 怎么用来验证改动

```text
终端 A：mvn -pl encryptor-examples/web-example spring-boot:run          # 或先 install 再跑
终端 B：直接跑 web-example 的 HttpTest（当前是 JUnit 测试类，需要 A 已启动）
网关场景：
终端 A：web-example（8081）
终端 B：mvn -pl encryptor-examples/gateway-example/gateway spring-boot:run（8080）
```

> 这两个 `HttpTest` 用 `@Test` 暴露手工脚本：**在 CI 里没有先起服务时必然失败**，改动测试相关代码前先确认这一点，不要误判为回归。

## 坑

- `web-example/pom.xml` 里的 `<build><finalName>gateway</finalName></build>` 是复制粘贴遗留，产物名与模块名不符。
- 示例里的 RSA 密钥对是**明文硬编码在仓库和 yml 里**的 demo 密钥，只能用于示例。
- `encryptor-examples` 只在 `all-modules` profile（默认）里参与构建，`main-module` profile 会跳过它——所以 `mvn -Pmain-module install` 之后示例不会更新。
