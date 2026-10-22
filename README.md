# 数据传输加解密通用实现组件

## 简介

encryptor-starter 是一个基于 Spring Boot 的报文层安全启动器：为 HTTP 报文提供 **机密性 + 防篡改**（对齐 JOSE/JWE，RFC 7516），支持 servlet 与 Spring Cloud Gateway 两侧，支持国密（SM2/SM4-GCM）与 ECDH-ES（P-256 直接密钥协商）。

## 安全边界（先读这一段）

- **承诺**：机密性（内容对中间人不可读）+ 完整性（密文/上下文被篡改可检出，AEAD 内建）+ 现代算法（RSA-OAEP-256 / AES-GCM 或 SM2(C1C3C2) / SM4-GCM）+ 密钥可轮换（kid + JWKS）。
- **不承诺**：客户端身份认证 / 防伪造。报文由"谁"发出的不由本组件回答——把认证交给 TLS + Spring Security（JWT / mTLS）。任何人拿到服务端公钥都能构造合法报文，这是设计内的 non-goal。
- **不是 TLS 的替代**：它是 TLS 之上的纵深防御 / 合规外壳，不是安全边界。
- **客户端要求**：WebCrypto（RSA-OAEP + AES-GCM）。浏览器须在 `https://` 或 `localhost`（安全上下文）；Node ≥ 16（`require('crypto').webcrypto`）。

## 选型：按运行环境选 artifact

单仓双产品线：**原名 artifact = Boot 2.7 线（javax）**，**`-boot3` 后缀 = Boot 3 线（jakarta，版本从 3.0.0 起始）**。协议（core）只有一份，两线共享。

| 运行环境 | JDK | Spring Boot | Spring Cloud / Alibaba | 用哪条线 |
| --- | --- | --- | --- | --- |
| 存量/兜底（servlet） | 8/11/17 | 2.7.x | 2021.0.x / 2021.1 | **1.x 原名线** |
| 新项目（servlet） | 17/21 | 3.5.x | 2025.0.x | **3.0.0 `-boot3` 线** |

starter 对照（groupId `io.github.cuukenn`；两线 starter **不可混用**，否则装配/字节码代际错配）：

| 模块 | 1.x 线（Boot 2.7） | 3.0.0 线（Boot 3.5） |
| --- | --- | --- |
| 协议核心（两线同一份，JDK 8 编译通用） | `encryptor-core` | 同左 |
| 国密可选模块（两线同一份，显式添加） | `encryptor-sm` | 同左 |
| servlet 通用装配 | `encryptor-spring-boot-starter` | `encryptor-spring-boot3-starter` |
| servlet web | `encryptor-web-spring-boot-starter` | `encryptor-web-boot3-starter`（内部依赖上者） |
| 网关（SCG） | `encryptor-gateway-spring-boot-starter` | `encryptor-gateway-boot3-starter`（**复制线**，理由见下） |
| reactive 通用装配 | `encryptor-spring-boot-starter-reactive` | **共享同一 artifact**（实测 Boot 3.5 可用，不复制） |
| Micrometer 指标 | `encryptor-micrometer-spring-boot-starter` | **共享同一 artifact**（实测 Boot 3.5 可用；跟进项见下） |
| 网关示例 | `encryptor-examples/gateway-example`（Boot 2.7） | `encryptor-examples/boot3-example`（Boot 3.5） |

- **网关为何复制**：Spring 6.2 移除了 `ServerHttpRequest#getMethodValue()`（4 处调用点）且 `ServerHttpResponse#getStatusCode()` 返回类型变为 `HttpStatusCode`（3 处）——1.x 网关 jar 在 Boot 3.5 下任何请求都会链首 `NoSuchMethodError`；`encryptor-gateway-boot3-starter:3.0.0` 做了最小签名适配（语义零变更，diff 守卫按文件登记）。
- **reactive/micrometer 为何共享**：main 源码零被删 API，且在真实 Boot 3.5 应用/运行期验证装配与协议行为对等（三载体往返、防重放、计数器、JWKS）。micrometer 的跟进项：`@AutoConfigureAfter` 只声明了 `MetricsAutoConfiguration`，与 `SimpleMetricsExportAutoConfiguration` 之间无排序约束，当前全量 imports 排序下正确，季度复盘 Boot patch 时复核。
- **网关下游约束两线相同**：网关解密后转发的是明文，下游必须是**不带 encryptor** 的普通应用。boot3 示例自带一个 JDK HttpServer 回显下游（随机端口），也可换同形态的 8082 普通 web 应用。

## 特性

- **协议**：JWE Compact 单字段载体（query 参数 / JSON `{"jwe":…}` / form 字段 `jwe`），响应复用请求 CEK（`alg=dir`，客户端不需密钥对）。
- **算法**：请求 `alg=RSA-OAEP-256`（RSA 公钥）或 `alg=ECDH-ES`（P-256 公钥，直接密钥协商，`epk` 随 header 走、`encrypted_key` 段为空），`enc=A256GCM`（默认）；国密 `alg=SM2` + `enc=SM4-GCM` 需显式添加可选模块 `encryptor-sm`（只使用 BC 轻量级 API，不注册 Provider）。算法白名单服务端强制，客户端不可自选。
- **防重放**：服务端强制时间窗（`ttl`，默认 5 分钟）+ nonce 一次性消费。默认内存实现**只在本进程内有效**，多实例部署必须注册自己的 `NonceChecker` bean（Redis 等共享存储），见「运行须知」。
- **上下文绑定**：AAD 绑定 `uri/method/方向/ts/nonce`，密文不能跨接口/跨方向搬运。
- **密钥轮换**：多 kid 并存，JWKS 只读发现端点（`/.well-known/encryptor-keys`，免加密、只含公钥、ETag/缓存）。
- **失败面**：解密/上下文/防重放失败统一回 `failure-status`（默认 400）；请求超限 413、响应超限 500（不发明文）、网关密码学执行器饱和 503。失败响应带 `X-Encryptor-Trace` 头，其值与服务端日志里的 trace 同值，可直接对号排障。
- **上限**：请求 `max-request-size`（默认 1MiB，超限 413）；响应 `max-response-size`（默认 4MiB）—— servlet 侧是**有界缓冲**（超限即停止缓冲并回 500，绝不半截明文透传），网关侧在组装响应时判定（超限回 500，不发明文）。
- **可运维**：运行期旁路开关（`EncryptorRuntime.setBypass`，无需重启）；启动期生效配置摘要 + 公钥指纹；非法配置启动即失败（fail-fast）。
- **uri 级 kid 白名单**：`crypto-config` 可按 uri 正则限定"这条路由只接受哪几把 kid"（密钥轮换/灰度）。

## 使用方法

- 1、导入 pom（Boot 3 项目把 starter 坐标换成上表 3.0.0 线对位，如 `encryptor-web-boot3-starter` / `encryptor-gateway-boot3-starter`，协议 core/sm 坐标不变）
    - 普通项目
        ```xml
        <!-- 具体发布版本可通过以下地址查询 -->
        <!-- https://mvnrepository.com/artifact/io.github.cuukenn/encryptor-core -->
        <dependency>
          <groupId>io.github.cuukenn</groupId>
          <artifactId>encryptor-core</artifactId>
          <version>版本</version>
        </dependency>
        ```
    - web项目。
        ```xml
        <!-- 具体发布版本可通过以下地址查询 -->
        <!-- https://mvnrepository.com/artifact/io.github.cuukenn/encryptor-web-spring-boot-starter -->
        <dependency>
          <groupId>io.github.cuukenn</groupId>
          <artifactId>encryptor-web-spring-boot-starter</artifactId>
          <version>版本</version>
        </dependency>
        ```

    - gateway项目。

        ```xml
        <!-- 具体发布版本可通过以下地址查询 -->
        <!-- https://mvnrepository.com/artifact/io.github.cuukenn/encryptor-gateway-spring-boot-starter -->
        <dependency>
          <groupId>io.github.cuukenn</groupId>
          <artifactId>encryptor-gateway-spring-boot-starter</artifactId>
          <version>版本</version>
        </dependency>
        ```

    - **国密（SM2/SM4-GCM）需要额外显式添加可选模块**：`encryptor-core` 与各 starter **不依赖 BouncyCastle**，也不会传递 `encryptor-sm`。只有确实使用 `type: SM2` 的服务才需要：

        ```xml
        <dependency>
          <groupId>io.github.cuukenn</groupId>
          <artifactId>encryptor-sm</artifactId>
          <version>版本</version>
        </dependency>
        ```

        没有它时配置 SM2 密钥会在**启动期**失败，错误信息会提示添加 `encryptor-sm`；RSA / ECDH-ES 路径不受影响。`encryptor-sm` 只使用 BouncyCastle 轻量级 API，**不注册全局 JCA Provider**。

> **依赖版本提示**：项目自身已升级到 Spring Boot 2.7.18 / Spring Cloud 2021.0.8。Boot 2.4.x 的 BOM 会把 `nimbus-jose-jwt` 管到 9.1.3（含已知 CVE）；下游应用如果仍使用 Boot 2.4.x BOM，请在 `dependencyManagement` 中先 import `encryptor-dependencies`，或显式 pin `com.nimbusds:nimbus-jose-jwt:9.37.3`。

## 配置样例

```yaml
encryptor:
  config:                       # servlet 侧; reactive 侧前缀 encryptor.config.reactive
    enable: true
    keys:                       # 至少一把; 多钥并存支持轮换
      - kid: "2026-10"
        type: RSA               # RSA(默认) / EC / SM2（SM2 需显式依赖 encryptor-sm）
        private-key: <Base64 PKCS#8>
        public-key: <Base64 X.509/SPKI>   # SM2 可用 SPKI 或裸 64 字节 x||y（需 encryptor-sm）
      - kid: "2026-07"          # 旧钥保留只解不封, 客户端可自选 kid
        type: RSA
        private-key: <Base64 PKCS#8>
        public-key: <Base64 X.509/SPKI>
    active-kid: "2026-10"       # 不填取 keys 第一把
    allowed-algs: []            # 空 = 按密钥类型联动(RSA→RSA-OAEP-256, EC→ECDH-ES, SM2→SM2)
    allowed-encs: []            # 空 = 默认 [A256GCM]
    ttl: 5m                     # 防重放时间窗
    failure-status: 400
    max-request-size: 1048576
    max-response-size: 4194304
    require-encrypted: true     # 命中范围的请求缺合法 jwe ⇒ 400(fail-closed)
    bypass:                     # 运行期可经 EncryptorRuntime 热改
      request: false
      response: false
    discovery:                  # JWKS 只读发现端点(免加密, 只含公钥)
      enable: true
      path: /.well-known/encryptor-keys
      cache-max-age-seconds: 300
    web:                       # 仅 servlet 侧; gateway 前缀 encryptor.config.reactive.gateway
      skip-uris: []             # 跳过名单: 命中即不加密(正则整串匹配)
      skip-methods: []
      skip-req-content-type: []
      skip-res-content-type: []
      # 旧名 black-uris / black-methods / black-req|res-content-type 仍可绑定
      # (弃用 alias, 启动会 WARN), 新旧共存时合并去重
      crypto-config:            # uri 正则 → 该路由只接受哪些 kid
        "[^/pay/.*]": ["2026-10"]
```

> **含 `.` 的 uri 正则 key 必须用括号写法 `"[...]"`**，否则 Spring Boot 会静默把 key 改坏（如 `^/test/secret.*` → `testsecret`）。

## 密钥轮换 SOP

**前提**：密钥库（`ServerKeyStore`）在**启动期**构建、运行期不可变；JWKS 的 ETag 也是启动期算好的。所以**增删 kid 必须重启**（滚动重启即可），不存在"改配置立刻生效"。

1. 生成新密钥对，追加为新的一条 `keys[]`（新 kid），**不要**立刻改 `active-kid`。
2. 发布服务端（滚动重启）：重启后的实例同时持有新旧 kid。**注意顺序**——尚未重启的实例不认识新 kid，客户端必须等所有实例都升级完才开始用新 kid。
3. 客户端改造：从 JWKS 端点取公钥（`fetchKeys`），改用新 kid 加密（客户端自选 kid，服务端只按白名单校验）。
4. 客户端全部切换后，改 `active-kid` 为新 kid（供新接入方默认使用）；旧 kid 保留"只解不封"直到流量归零。
5. 移除旧 kid（再次重启）。

## 运行须知（部署前必读）

- **时钟**：`ttl` 时间窗比较的是**客户端与服务端各自的时钟**。两侧必须 NTP 同步，且 `ttl` 要大于最大时钟偏移（默认 5 分钟足够覆盖常见偏移）。客户端时钟快/慢超过窗口 ⇒ 报文一律 `EXPIRED` → `failure-status`。排查这类问题先看两侧 `date`。
- **多实例的 nonce**：默认 `InMemoryNonceStore` 只在单进程内消费 nonce。请求经负载均衡打到不同实例时，同一个 nonce 不会被识别为重放。多实例部署请注册自己的 `NonceChecker` bean（Redis 的 `SETNX + TTL` 即可）：
  ```java
  @Bean
  public NonceChecker nonceChecker(StringRedisTemplate redis) {
      return nonce -> Boolean.TRUE.equals(
          redis.opsForValue().setIfAbsent("enc:nonce:" + nonce, "1", Duration.ofMinutes(10)));
  }
  ```
  两侧自动装配都会用它替换内存实现（无需覆盖整个 `DefaultProtocol`）。`ttl` 与这里的 TTL 要对齐（存储 TTL ≥ `ttl`，否则过期 nonce 会被重新接受）。
- **大响应 / 流式接口**（下载、SSE、导出）：响应过滤器必须缓冲才能加密，缓冲上限就是 `max-response-size`（约束的是**业务明文**；加密后的 JWE 因 Base64 膨胀会略大，不按该值截断）。这类接口应把其 content-type 加入 `skip-res-content-type`，并把 `max-response-size` 设为 `<= 0` 关闭上限（启动会有告警）。注意：`skip-res-content-type` 只决定**最终是否加密**，响应仍会先经过包装器缓冲；若不关闭上限，超限仍会在缓冲阶段回 500。若确实要加密大响应，超限会回 500 且**不会**漏出半截明文。网关侧对 `writeAndFlushWith` 也会先聚合再加密；SSE 这类无限流必须进 skip 名单，否则会在上限处失败（不会降级成明文）。
- **报文头约束**：`nonce` 必填且最长 **128 字符**（超长按 `BAD_HEADER` 拒绝）；RSA 密钥模数最低 **2048 位**；AES-GCM / SM4-GCM 的 IV 固定 **12 字节**。这些都在解密/启动期校验，不依赖业务代码。
- **nonce 保留期**：使用内置 `InMemoryNonceStore` 时，`nonce-retention` 必须 **≥ `2 × ttl`**（默认即 `2 × ttl`），否则启动失败。时间窗是对称的，`ts` 偏未来的报文最晚会在 `ts + ttl` 被接受，因此 nonce 要保留到覆盖这段时间；注入自定义 `NonceChecker` 时该配置不生效，过期时间由实现方保证（见上一条）。
- **内置 nonce 存储的并发**：容量 ≥ 1024 时按 nonce 哈希分 16 片（进程内随机盐，避免定向打爆单个分片）降低全局锁竞争；总容量按分片精确分配，全局记录数仍不超过 `nonce-capacity`。分片内按插入顺序驱逐，因此大容量下“全局最早项”退化为“分片内最早项”；容量 < 1024 时保持单分片全局 FIFO。
- **响应边界（servlet / 网关）**：两侧都会跳过 `HEAD`、`1xx`、`204/205/304`（不加密、不写 body）。servlet 额外规则：`3xx` 仅在 body 为空时跳过，带说明性 body 的 3xx 仍会加密；`sendError` 的状态码保留，消息按 UTF-8 写入并作为加密 body 返回，响应已提交时按 Servlet 契约抛 `IllegalStateException`；`sendRedirect` 会清空已写入的 body，只保留状态与 `Location`，已提交时同样抛 `IllegalStateException`；业务抛异常时响应过滤器回 **500 空 body**（带 trace 头），不会落到容器的明文错误页；servlet 异步响应（`DeferredResult`/`Callable`）由响应过滤器包装 `AsyncContext`，在业务调用 `complete()` 前先加密写回，`onComplete` 仅作兜底，`onError`/`onTimeout` 回 500 空 body；异步 `dispatch()` 不会保留解密后的 `WebContext` 视图，转发目标看到的是原始请求上下文；业务自定义线程池仍不会自动传递 `WebContext`，需要自行传参。网关的 `3xx` 同样只在 body 为空时跳过，带 body 的 `3xx` 仍会加密。
- **敏感数据清理（best-effort）**：servlet 在请求链结束后（`WebContext.clear()`）清零 CEK 与请求明文；网关在链路终止（`doFinally`/失败分支）时清理 `GatewayContext` 并清零 CEK/明文。该清理只覆盖本进程持有的数组，JVM/GC 复制、日志、下游缓冲不在范围内；需要更强保证时请自行限制日志与堆转储。
- **启动期校验**：`skip-uris`、`skip-methods`、`skip-*-content-type`、`crypto-config` 里的正则在启动时统一编译，非法正则**直接启动失败**，错误信息包含配置项名与原始正则，不会等到第一个请求才 500。
- **请求上限的实际边界**：`max-request-size` 在 servlet 侧对 **JSON 载体**是真正的字节上限（starter 自己读 body 再判定，超限 413）；`FORM` 载体在读取参数前先按 `Content-Length` 判定（超限 413），chunked FORM 无法预知长度，字节上限仍由容器决定（Tomcat `maxPostSize`）；`QUERY` 载体走请求头，受容器 `maxHttpHeaderSize` 约束。注意 servlet 在解析载体前会先按 `Content-Length` 做 413 早检，因此 **QUERY 载体携带超大 body 也会 413**（即使该 body 不会被读取）。空 JSON body 视为无载体：`require-encrypted=false` 时透传，默认 `true` 时仍 400。网关侧 JSON/FORM 由 `readBody` 有界读取（超限 413），`QUERY` 同样受 Netty 请求头上限约束。要真正卡住整请求体积，必须同时配置容器/Netty 的上限，只调 `max-request-size` 不够。
- **危险开关**：`require-encrypted=false`、`bypass.request/response` 开启、`max-response-size<=0`、网关 `skip-able=true` 都会在启动期打 warn——它们都直接削弱报文安全，看到 warn 要确认是有意为之。
- **客户端**：JS 参考实现（`encryptor-examples/*/front/encryptor/jwe.js`）覆盖 RSA-OAEP-256 与 ECDH-ES（P-256，WebCrypto 原生 `ECDH` + 手写 Concat KDF），`enc` 支持 A128/A192/A256GCM，具体用哪个以服务端 `allowed-encs` 为准。浏览器 WebCrypto **没有** SM 算法，所以 JS 侧不含国密路径。
- **国密的客户端**：服务端国密路径（`alg=SM2` + `enc=SM4-GCM`）由 `encryptor-sm` 的国密套件/解析器测试与 web/gateway 过滤器测试共同覆盖（core 只保留 SPI 与 RSA/EC）。国密客户端需要自带 SM4-GCM 能力的 JS 库（常见 `sm-crypto` 只有 SM4-ECB/CBC，**不能**直接用于本协议的 `SM4-GCM`）。Java 客户端可显式依赖 `encryptor-sm` 并使用 `JweCodec`。两个示例都已自带 SM2 演示密钥（web-example `sm-2026`、gateway-example `sm-gw-2026`，pom 里显式添加了 `encryptor-sm`），用任意国密客户端打 `/test/hello` 即可验证；servlet 侧另有 `^/test/sm.*` 绑定 `sm-2026` 的 `GET /test/sm` 端点，用来演示「uri 级绑密钥类型」。
- **网关下游**：网关转发出去的是**已解密的明文**，下游服务**不要**再引入 encryptor starter（否则会被二次解密 → 400）。参考 `encryptor-examples/gateway-example/web`（普通应用）。

## 代码示例

- JS 客户端（WebCrypto）：`encryptor-examples/web-example/front/encryptor/jwe.js`（`encrypt`/`decrypt`/`fetchKeys`）。
- 端到端示例：`encryptor-examples/`（web-example: 8081；gateway-example: 8080，下游用普通应用 `gateway-example/web`，端口 8082）。
- 设计文档：`docs/superpowers/specs/2026-10-16-payload-security-protocol-design.md`。

### 跑起来（本地验证）

```bash
# 服务端（Maven 不在 PATH 时用全路径；示例未配 repackage，只能用插件全坐标）
mvn -B -pl encryptor-examples/web-example org.springframework.boot:spring-boot-maven-plugin:2.7.18:run
# 网关两个进程：先下游（8082），再网关（8080）
mvn -B -pl encryptor-examples/gateway-example/web     org.springframework.boot:spring-boot-maven-plugin:2.7.18:run
mvn -B -pl encryptor-examples/gateway-example/gateway org.springframework.boot:spring-boot-maven-plugin:2.7.18:run

# 客户端（Node ≥16；本仓库实测 Node 16，用 npm 而不是 pnpm）
cd encryptor-examples/web-example/front && npm install && node test.js     # 11 条断言
cd encryptor-examples/gateway-example/gateway/front && npm install && node test.js   # 10 条断言
```

`test.js` 覆盖：JWKS 可取公钥且不含 `d`、GET/POST(JSON)/POST(form) 三载体往返、ECDH-ES 往返（`alg=ECDH-ES` 且 `encrypted_key` 段为空）、uri 级 kid 绑定、未配置的 `enc` 被拒、篡改 IV 必须 400；全过 `exit 0`。

## 可观测性（可选模块）

默认零指标依赖：core 只暴露 `EncryptorListener` SPI（三个 no-op 回调），不引入任何指标库。要指标就加这个可选模块——**core 与两个 starter 的依赖面不变**：

```xml
<dependency>
  <groupId>io.github.cuukenn</groupId>
  <artifactId>encryptor-micrometer-spring-boot-starter</artifactId>
  <version>版本</version>
</dependency>
```

装配条件（条件装配）：应用里存在 `MeterRegistry`（如 actuator + 任一 registry）即可。**你可以同时注册自己的 `EncryptorListener`**——两侧 starter 会把容器里所有监听器按 `@Order`/注册顺序组合（`CompositeEncryptorListener`），指标与自定义审计并存。某个监听器抛异常时只会记一条 WARN（含回调名与异常栈）并继续，不影响其它监听器或加解密主流程。网关队列指标只在网关 starter 在场、且存在 `CryptoExecutor`（网关自动装配提供，可自行覆盖）时出现。

| 指标 | 类型 | 标签 | 含义 |
| --- | --- | --- | --- |
| `encryptor.decrypt` | Counter | `result=success`/`failure` | 请求解密总次数（成功/失败） |
| `encryptor.decrypt.failures` | Counter | `failure=<分类>` | 按失败分类计数，取 `EncryptorFailure` 枚举名（`MISSING`/`BAD_HEADER`/`UNKNOWN_KID`/`ALG_NOT_ALLOWED`/`ENC_NOT_ALLOWED`/`AAD_MISMATCH`/`DECRYPT_FAILED`/`EXPIRED`/`REPLAY`/`TOO_LARGE`/`INTERNAL`） |
| `encryptor.encrypt.failures` | Counter | `failure=<分类>` | 响应加密失败的分类计数 |
| `encryptor.gateway.crypto.pending` | Gauge | - | 已提交未完成的密码学任务数（在跑 + 排队），**过载第一信号** |
| `encryptor.gateway.crypto.rejected` | FunctionCounter | - | 因队列满被拒的累计数（每一次对应一次 503） |
| `encryptor.gateway.crypto.threads`、`encryptor.gateway.crypto.queue.capacity` | Gauge | - | 执行器容量常量，便于算利用率 |

- 所有分类在注册时一次性预建（未出现过的分类也有 0 值），便于直接做面板；分类为 null 或未知时归入 `INTERNAL`（宁可少一个分类，也不丢一次失败）。
- **不记耗时**：`EncryptorListener` 回调只在请求结束时触发，没有"开始"钩子——要加计时段得改 core 热路径，收益配不上风险。
- 网关的 `pending` 是**自己记账**（提交数 − 完成数）：Reactor 的 `Scannable.Attr.BUFFERED`（`estimateSize()`）只反映它自己的待派发队列，任务一旦被派进执行器内部队列就看不见了（实测恒为 0）。

## 性能基准（JMH）

基准代码在 `encryptor-bench/`。下表是**同一台机器上三次独立运行的中位数**（轮间偏差 <1%）：

- 机器：Apple M1 Pro（10 核）/ 32 GB / macOS，Oracle JDK 11.0.28
- 参数：`-wi 2 -i 3 -f 1 -prof gc`（每基准 2×1s 预热 + 3×1s 测量，1 个 fork）
- 单位：一次 `roundTrip` = **服务端处理一次请求**（`decryptRequest` + `encryptResponse`）；客户端封包不在其中，compact 在 `setup` 阶段预先生成；`decrypt*` = 仅服务端解封 + 解密

| 基准 | 吞吐 (ops/s) | 单次耗时 | 4 线程并行度 | 分配 (B/op) |
| --- | --- | --- | --- | --- |
| `E2eBenchmark.roundTrip`（RSA-OAEP-256） | **1020** | 0.98 ms | — | 73018 |
| `EcdhEsBenchmark.ecdhRoundTrip`（ECDH-ES P-256） | **1438** | 0.70 ms | — | 73550 |
| `RsaParallelBenchmark.decryptSingleThread` | 1028 | 0.97 ms | — | 60881 |
| `RsaParallelBenchmark.decryptFourThreads` | 4051 | 0.25 ms/op | **3.94×** | 60584 |
| `EcdhEsBenchmark.ecdhDecryptSingleThread` | 1457 | 0.69 ms | — | 61456 |
| `EcdhEsBenchmark.ecdhDecryptFourThreads` | 5808 | 0.17 ms/op | **3.99×** | 60833 |

怎么读：

- **两个算法族都在千级 ops/s，ECDH-ES 约为 RSA-OAEP-256 的 1.4 倍**——是同一数量级的差距，不是数量级优势。单次请求的成本 = 「一次 JWE 编解码（parse/AAD/GCM）」+「一次密钥协商」，P-256 协商相对 RSA-2048 私钥运算只省下其中一段（实测 ≈0.29 ms/op，其余为两条路径共享的管线成本）。
- **并发近线性**（4 线程 3.94× / 3.99×）：`Cipher` 每次新建、无共享可变状态，密钥运算不互相阻塞。
- **分配量约 61–74 KB/op**，主要来自 nimbus 的 JWE/JSON 对象。`gc.alloc.rate.norm` 是本仓库的回归基线（`encryptor-bench/baseline.json`，阈值 +10%）。
- 以上是**本机、JDK 11、未调优**的原始值；换机器或换 JDK 请以本机重跑为准。

复现：

```bash
/usr/local/maven/3.8.9/bin/mvn -B -Pall-modules -pl encryptor-bench -am -DskipTests package
java -jar encryptor-bench/target/bench.jar -wi 2 -i 3 -f 1 -prof gc -rf json -rff encryptor-bench/target/bench.json
encryptor-bench/check-thresholds.sh encryptor-bench/target/bench.json
```

`check-thresholds.sh` 卡两条闸门：4 线程解封并行度 ≥2.5×、往返分配量不超过基线 +10%；ECDH-ES/RSA 的比值只打印不断言（3×1s 迭代下该比值噪声可达 ±35%，当闸门只会带来假失败；看趋势请加长迭代，如 `-wi 3 -i 5`）。

⚠️ **别拿 `spring-boot:run` 的性能数字做决策**：它会给示例应用注入 `-XX:TieredStopAtLevel=1`（只跑 C1）。同一套代码实测从约 0.95 ms/op 变成约 7.5 ms/op（≈7.8×），HTTP 往返 rtt 从约 1.6 ms 变成约 8.6 ms。要量生产形态就用 `java -cp … <MainClass>` 直接起（示例见 `AGENTS.md`），或打包后 `java -jar`。

## v1 → v2 迁移

**v1（RSA-PKCS1v15 + AES-CBC + MD5-AES 自造签名）已被移除，无兼容**。v1 的"签名"密钥由客户端自选上传，不提供防伪造；v2 直接对齐 JOSE/JWE。升级方式：前后端同批发布（协议不兼容，服务端对旧报文返回 `failure-status`）。

> **BC 可选化的 API 变化**：`ServerKeyStore.sm2PrivateKey(String)` 与 `SM2_DOMAIN` 已随 BouncyCastle 可选化移除。自定义 `CipherSuite` 如需要 SM2 私钥，请改用 `ServerKeyStore.nativePrivateKey(String)`，并显式添加 `encryptor-sm` 依赖。
