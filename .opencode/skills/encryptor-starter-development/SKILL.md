---
name: encryptor-starter-development
description: Use when touching ANY code, config, pom, docs, or tests in this repository (encryptor-starter, a JWE payload-security Spring Boot Starter family). This is a ROUTER - it maps your task to one per-module deep-dive file; read only the files you need, not everything.
---

# encryptor-starter 开发导航（路由层）

报文层安全（机密性 + 防篡改）的 Spring Boot Starter 家族，协议对齐 JOSE/JWE（RFC 7516）。本 skill 只做**按模块路由**——按任务读下表对应的文件，不要全读。

## 安全边界（仓库级，先于一切模块）

- **承诺**：机密性 + 完整性（AEAD）+ 现代算法 + 密钥轮换。**不承诺**客户端身份认证（TLS + Spring Security 承担；公钥公开、任何人可构造合法报文是设计内 non-goal）。不是 TLS 的替代。
- **v1 协议残留必须 0 命中**：`EncryptorDataWrapper|AES_K|md5withaes|DigestWithEncryptSigner|GroupEncryptor|HexEncoder`。

> `docs/architecture/*.md` 是 v1 时代记录（失效横幅，仅追溯）；协议定义见 `docs/superpowers/specs/2026-10-16-payload-security-protocol-design.md`（§3.11 演进通道契约）。任何文件都不写会变化的数字（测试计数/基准/版本清单）——以 pom / 脚本 / CI 为准。

## 模块路由（改哪读哪）

| 你要动的东西 | 读 |
| --- | --- |
| `encryptor-core/`（jose/protocol/runtime/kit/config-base：编解码、AAD、防重放、密钥库、CipherSuite SPI、CarrierKit/SkipListsConfigBase/RouteRule 单点） | `modules/core.md` |
| `encryptor-sm/`（SM2/SM4-GCM、BC、密钥解析） | `modules/sm.md` |
| `encryptor-starters/encryptor-web-starter/`（servlet 过滤器链/响应面/JWKS/WebEncryptorConfig） | `modules/web.md` |
| `encryptor-starters/encryptor-gateway-starter/`（GlobalFilter/CryptoExecutor/响应改写/GatewayEncryptorConfig/micrometer 衔接） | `modules/gateway.md` |
| `encryptor-starter` / `encryptor-starter-reactive`（通用配置模型/自动装配） | `modules/core.md` 的「配置模型装配」节 + `topics/sync-map.md` |
| `*-boot3-starter/`（jakarta 复制对） | `topics/sync-map.md`（复制对守卫与同步规则） |
| `encryptor-examples/`（示例、front jwe.js、HttpTest、test.js） | `topics/sync-map.md`（同步面）+ 各示例 `application.yml` |
| `encryptor-bench/`、CI workflow、发布/版本、Maven 环境 | `topics/build-and-release.md` |

## 跨模块任务（必读附加文件）

| 任务 | 附加必读 |
| --- | --- |
| 协议/行为变更（claims、载体字段、`kid` 语义、alg/enc） | `topics/sync-map.md` **全文**（成对文件对照表是硬约束） |
| 只改一侧（servlet 或 reactive） | `topics/sync-map.md` 的「成对文件对照表」 |
| 改 POM / 发版 / bump 版本 | `topics/build-and-release.md` 的「双线发布」「Maven 兼容」节 |
| 性能回归 | `topics/build-and-release.md` 的「JMH」节 |
