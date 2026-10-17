# 数据传输加解密通用实现组件

## 简介

encryptor-starter 是一个基于 Spring Boot 的报文层安全启动器：为 HTTP 报文提供 **机密性 + 防篡改**（对齐 JOSE/JWE，RFC 7516），支持 servlet 与 Spring Cloud Gateway 两侧，支持国密（SM2/SM4-GCM）。

## 安全边界（先读这一段）

- **承诺**：机密性（内容对中间人不可读）+ 完整性（密文/上下文被篡改可检出，AEAD 内建）+ 现代算法（RSA-OAEP-256 / AES-GCM 或 SM2(C1C3C2) / SM4-GCM）+ 密钥可轮换（kid + JWKS）。
- **不承诺**：客户端身份认证 / 防伪造。报文由"谁"发出的不由本组件回答——把认证交给 TLS + Spring Security（JWT / mTLS）。任何人拿到服务端公钥都能构造合法报文，这是设计内的 non-goal。
- **不是 TLS 的替代**：它是 TLS 之上的纵深防御 / 合规外壳，不是安全边界。
- **客户端要求**：WebCrypto（RSA-OAEP + AES-GCM）。浏览器须在 `https://` 或 `localhost`（安全上下文）；Node ≥ 16（`require('crypto').webcrypto`）。

## 特性

- **协议**：JWE Compact 单字段载体（query 参数 / JSON `{"jwe":…}` / form 字段 `jwe`），响应复用请求 CEK（`alg=dir`，客户端不需密钥对）。
- **算法**：请求 `alg=RSA-OAEP-256` + `enc=A256GCM`（默认）；国密 `alg=SM2` + `enc=SM4-GCM`（BC 轻量级 API，不注册 Provider）。算法白名单服务端强制，客户端不可自选。
- **防重放**：服务端强制时间窗（`ttl`，默认 5 分钟）+ nonce 一次性消费（内存实现，可换 Redis）。
- **上下文绑定**：AAD 绑定 `uri/method/方向/ts/nonce`，密文不能跨接口/跨方向搬运。
- **密钥轮换**：多 kid 并存，JWKS 只读发现端点（`/.well-known/encryptor-keys`，免加密、只含公钥、ETag/缓存）。
- **失败面**：所有失败统一为 `failure-status`（默认 400）+ `traceId`，对内有分类日志。
- **上限**：请求 `max-request-size`（默认 1MiB，超限 413）；响应 `max-response-size`（默认 4MiB，超限 500 且不发明文）。
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
    allowed-algs: []            # 空 = 按密钥类型联动(RSA→RSA-OAEP-256, SM2→SM2)
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

1. 生成新密钥对，追加为新的一条 `keys[]`（新 kid），**不要**立刻改 `active-kid`。
2. 发布服务端：旧 kid 与新 kid 并存，旧客户端不受影响（客户端自选 kid）。
3. 客户端改造：从 JWKS 端点取公钥（`fetchKeys`），改用新 kid 加密。
4. 客户端全部切换后，改 `active-kid` 为新 kid（供新接入方默认使用）；旧 kid 保留"只解不封"直到流量归零。
5. 移除旧 kid。

## 代码示例

- JS 客户端（WebCrypto）：`encryptor-examples/web-example/front/encryptor/jwe.js`（`encrypt`/`decrypt`/`fetchKeys`）。
- 端到端示例：`encryptor-examples/`（web-example: 8081；gateway-example: 8080，下游用普通应用 `gateway-example/web`）。
- 设计文档：`docs/superpowers/specs/2026-10-16-payload-security-protocol-design.md`。

## v1 → v2 迁移

**v1（RSA-PKCS1v15 + AES-CBC + MD5-AES 自造签名）已被移除，无兼容**。v1 的"签名"密钥由客户端自选上传，不提供防伪造；v2 直接对齐 JOSE/JWE。升级方式：前后端同批发布（协议不兼容，服务端对旧报文返回 `failure-status`）。
