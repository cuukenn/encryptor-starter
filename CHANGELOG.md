# Changelog

## Unreleased

### Added

- 新增可选模块 `encryptor-sm`：SM2（C1C3C2）+ SM4-GCM 套件与 SM2 密钥解析器，按需显式引入。
- 新增 `JwksDocument`，servlet 与 gateway 共用同一份 JWKS JSON/ETag 生成逻辑。
- 新增 `ProtocolAssembler`，两侧自动装配共用 `DefaultProtocol` 组装规则。
- 新增 core `config/base` 配置模型，servlet/reactive 只保留各自的 `PREFIX`。
- servlet 支持异步响应加密：包装 `AsyncContext`，在 `complete()` 前加密写回，`onComplete` 仅作兜底。
- 新增 `InMemoryNonceStore` 分片：容量 ≥ 1024 时最多 16 片，总容量精确、分片内 FIFO。

### Changed

- `encryptor-core` 不再依赖 BouncyCastle；SM2 能力迁移到 `encryptor-sm`，通过 `ServiceLoader` 发现 `KeyEntryParser` / `CipherSuite`。
- 未引入 `encryptor-sm` 时配置 SM2 密钥会在启动期失败，并提示添加 `io.github.cuukenn:encryptor-sm`。
- gateway starter 排除 `spring-security-rsa` 传递的 `bcprov/bcpkix/bcutil-jdk15on:1.69`，避免与 `encryptor-sm` 的 `*-jdk18on` 形成双 BC 血统。
- 使用内置 `InMemoryNonceStore` 时，`nonce-retention` 要求 **≥ 2 × ttl**（未配置时默认 `2 × ttl`），关闭未来时间戳偏移造成的重放窗口。
- `require-encrypted=false` 时，已读取的明文 JSON body 会重新提供给下游（servlet 使用缓存请求包装，gateway 使用请求装饰器）。
- servlet 异步交接时延迟清零请求明文，避免异步处理器读取时已被清零。
- `SmCipherSuite` / `SmKeyEntryParser` 移到 `io.github.cuukenn.encryptor.sm`，避免与 core 的 `io.github.cuukenn.encryptor.jose` 形成 split package。
- `MAX_NONCE_LENGTH` 改为按 UTF-8 字节数计算。

### Removed

- 移除 `ServerKeyStore.sm2PrivateKey(String)` 与 `SM2_DOMAIN`；自定义 `CipherSuite` 请改用 `ServerKeyStore.nativePrivateKey(String)`，国密实现需显式依赖 `encryptor-sm`。
- 移除未使用的 `StrKit.precompile(Collection<String>)`。
- core 内的 `SmCipherSuite` 已删除，国密实现只存在于 `encryptor-sm`。

### Fixed

- servlet `fail()` 增加已提交响应保护，避免失败路径再次 `resetBuffer()` 抛异常。
- gateway 响应过滤器在装饰阶段捕获 `JweContext`，避免清理后的懒读取竞态。
- `InMemoryNonceStore` 淘汰改为条件删除，避免并发新插入的 nonce 被误删。
- `DefaultProtocol.Builder.keys(null)` 现在给出明确的 `EncryptorException`。
- 文档补充跳过 content-type 的响应仍会先缓冲、需配合 `max-response-size <= 0`；以及 QUERY 载体携带超大 `Content-Length` 仍会 413。
