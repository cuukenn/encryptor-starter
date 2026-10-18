# 数据传输加解密通用实现组件

## 简介

encryptor-starter 是一个基于 Spring Boot 的报文层安全启动器：为 HTTP 报文提供 **机密性 + 防篡改**（对齐 JOSE/JWE，RFC 7516），支持 servlet 与 Spring Cloud Gateway 两侧，支持国密（SM2/SM4-GCM）与 ECDH-ES（P-256 直接密钥协商）。

## 安全边界（先读这一段）

- **承诺**：机密性（内容对中间人不可读）+ 完整性（密文/上下文被篡改可检出，AEAD 内建）+ 现代算法（RSA-OAEP-256 / AES-GCM 或 SM2(C1C3C2) / SM4-GCM）+ 密钥可轮换（kid + JWKS）。
- **不承诺**：客户端身份认证 / 防伪造。报文由"谁"发出的不由本组件回答——把认证交给 TLS + Spring Security（JWT / mTLS）。任何人拿到服务端公钥都能构造合法报文，这是设计内的 non-goal。
- **不是 TLS 的替代**：它是 TLS 之上的纵深防御 / 合规外壳，不是安全边界。
- **客户端要求**：WebCrypto（RSA-OAEP + AES-GCM）。浏览器须在 `https://` 或 `localhost`（安全上下文）；Node ≥ 16（`require('crypto').webcrypto`）。

## 特性

- **协议**：JWE Compact 单字段载体（query 参数 / JSON `{"jwe":…}` / form 字段 `jwe`），响应复用请求 CEK（`alg=dir`，客户端不需密钥对）。
- **算法**：请求 `alg=RSA-OAEP-256`（RSA 公钥）或 `alg=ECDH-ES`（P-256 公钥，直接密钥协商，`epk` 随 header 走、`encrypted_key` 段为空），`enc=A256GCM`（默认）；国密 `alg=SM2` + `enc=SM4-GCM`（BC 轻量级 API，不注册 Provider）。算法白名单服务端强制，客户端不可自选。
- **防重放**：服务端强制时间窗（`ttl`，默认 5 分钟）+ nonce 一次性消费。默认内存实现**只在本进程内有效**，多实例部署必须注册自己的 `NonceChecker` bean（Redis 等共享存储），见「运行须知」。
- **上下文绑定**：AAD 绑定 `uri/method/方向/ts/nonce`，密文不能跨接口/跨方向搬运。
- **密钥轮换**：多 kid 并存，JWKS 只读发现端点（`/.well-known/encryptor-keys`，免加密、只含公钥、ETag/缓存）。
- **失败面**：解密/上下文/防重放失败统一回 `failure-status`（默认 400）；请求超限 413、响应超限 500（不发明文）、网关密码学执行器饱和 503。失败响应带 `X-Encryptor-Trace` 头，其值与服务端日志里的 trace 同值，可直接对号排障。
- **上限**：请求 `max-request-size`（默认 1MiB，超限 413）；响应 `max-response-size`（默认 4MiB）—— servlet 侧是**有界缓冲**（超限即停止缓冲并回 500，绝不半截明文透传），网关侧在组装响应时判定（超限回 500，不发明文）。
- **可运维**：运行期旁路开关（`EncryptorRuntime.setBypass`，无需重启）；启动期生效配置摘要 + 公钥指纹；非法配置启动即失败（fail-fast）。
- **uri 级 kid 白名单**：`crypto-config` 可按 uri 正则限定"这条路由只接受哪几把 kid"（密钥轮换/灰度）。

## 使用方法

- 1、导入 pom
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

## 配置样例

```yaml
encryptor:
  config:                       # servlet 侧; reactive 侧前缀 encryptor.config.reactive
    enable: true
    keys:                       # 至少一把; 多钥并存支持轮换
      - kid: "2026-10"
        type: RSA               # RSA(默认) 或 SM2
        private-key: <Base64 PKCS#8>
        public-key: <Base64 X.509/SPKI>   # SM2 可用 SPKI 或裸 64 字节 x||y
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
      black-uris: []            # 跳过名单(正则整串匹配)
      black-methods: []
      black-req-content-type: []
      black-res-content-type: []
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
- **大响应 / 流式接口**（下载、SSE、导出）：响应过滤器必须缓冲才能加密，缓冲上限就是 `max-response-size`。这类接口应把其 content-type 加入 `black-res-content-type`（不包装、原样透传），并把 `max-response-size` 设为 `<= 0` 关闭上限（启动会有告警）。若确实要加密大响应，超限会回 500 且**不会**漏出半截明文。
- **请求上限的实际边界**：`max-request-size` 在 servlet 侧只对 **JSON 载体**是真正的字节上限（starter 自己读 body 再判定，超限 413）；`FORM` 载体经容器 `getParameter()` 解析，字节上限由容器决定（Tomcat `maxPostSize`）；`QUERY` 载体走请求头，受容器 `maxHttpHeaderSize` 约束。网关侧 JSON/FORM 由 `readBody` 有界读取（超限 413），`QUERY` 同样受 Netty 请求头上限约束。要真正卡住整请求体积，必须同时配置容器/Netty 的上限，只调 `max-request-size` 不够。
- **危险开关**：`require-encrypted=false`、`bypass.request/response` 开启、`max-response-size<=0`、网关 `skip-able=true` 都会在启动期打 warn——它们都直接削弱报文安全，看到 warn 要确认是有意为之。
- **客户端**：JS 参考实现（`encryptor-examples/*/front/encryptor/jwe.js`）覆盖 RSA-OAEP-256 与 ECDH-ES（P-256，WebCrypto 原生 `ECDH` + 手写 Concat KDF），`enc` 支持 A128/A192/A256GCM，具体用哪个以服务端 `allowed-encs` 为准。浏览器 WebCrypto **没有** SM 算法，所以 JS 侧不含国密路径。
- **国密的客户端**：服务端国密路径（`alg=SM2` + `enc=SM4-GCM`）由 core/web/gateway 三层测试覆盖。国密客户端需要自带 SM4-GCM 能力的 JS 库（常见 `sm-crypto` 只有 SM4-ECB/CBC，**不能**直接用于本协议的 `SM4-GCM`）。Java 客户端可直接用 `encryptor-core` 的 `JweCodec`。
- **网关下游**：网关转发出去的是**已解密的明文**，下游服务**不要**再引入 encryptor starter（否则会被二次解密 → 400）。参考 `encryptor-examples/gateway-example/web`（普通应用）。

## 代码示例

- JS 客户端（WebCrypto）：`encryptor-examples/web-example/front/encryptor/jwe.js`（`encrypt`/`decrypt`/`fetchKeys`）。
- 端到端示例：`encryptor-examples/`（web-example: 8081；gateway-example: 8080，下游用普通应用 `gateway-example/web`，端口 8082）。
- 设计文档：`docs/superpowers/specs/2026-10-16-payload-security-protocol-design.md`。

### 跑起来（本地验证）

```bash
# 服务端（Maven 不在 PATH 时用全路径；示例未配 repackage，只能用插件全坐标）
mvn -B -pl encryptor-examples/web-example org.springframework.boot:spring-boot-maven-plugin:2.4.2:run
# 网关两个进程：先下游（8082），再网关（8080）
mvn -B -pl encryptor-examples/gateway-example/web     org.springframework.boot:spring-boot-maven-plugin:2.4.2:run
mvn -B -pl encryptor-examples/gateway-example/gateway org.springframework.boot:spring-boot-maven-plugin:2.4.2:run

# 客户端（Node ≥16；本仓库实测 Node 16，用 npm 而不是 pnpm）
cd encryptor-examples/web-example/front && npm install && node test.js     # 6 条断言
cd encryptor-examples/gateway-example/gateway/front && npm install && node test.js
```

`test.js` 覆盖：JWKS 可取公钥且不含 `d`、GET/POST(JSON)/POST(form) 三载体往返、篡改 IV 必须 400；全过 `exit 0`。

## v1 → v2 迁移

**v1（RSA-PKCS1v15 + AES-CBC + MD5-AES 自造签名）已被移除，无兼容**。v1 的"签名"密钥由客户端自选上传，不提供防伪造；v2 直接对齐 JOSE/JWE。升级方式：前后端同批发布（协议不兼容，服务端对旧报文返回 `failure-status`）。
