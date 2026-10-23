# Changelog

## Unreleased

### Changed（不兼容）

- servlet 的 `skip-uris` / `crypto-config` 改为按**去 context-path 的应用内路径**匹配；部署在 `/app` 下的旧写法（`[/app/...]`）需去掉前缀，否则 uri 级 kid 白名单会静默失效。
- 重放/过期纳入 `EncryptorListener` 失败回调与指标（不再计为解密成功）；失败路径在抛出前清零已解出的 CEK/明文。
- 空 `200`（以及允许 body 的其他状态）统一返回 `{"jwe":...}` 信封；HEAD/1xx/204/205/304 与空 3xx 例外。
- 启动期校验收紧：`ttl <= 0`、`allowed-algs` 与已配置密钥无交集、`failure-status` 非法（网关侧还要求是 Spring 已知状态码）直接启动失败。
- QUERY 载体的明文契约明确为“已百分号编码”（与 servlet `parseQuery`、示例客户端一致），网关不再二次编码。
- `crypto-config` 引用不存在的 kid、servlet 过滤器 order 不满足 `jwks < facade < params < body < res` 时启动失败。
- servlet 参数视图的 `getQueryString()` 剔除 `jwe` 段，日志/自链接不再带密文。

### Added

- 新增 boot3 线（Jakarta / Boot 3.5）复制模块：`encryptor-spring-boot3-starter`、`encryptor-web-boot3-starter`、`encryptor-gateway-boot3-starter`（3.0.0），core/reactive/micrometer 直接复用 javax 线制品；复制对由 `scripts/javax-to-jakarta.sh --diff` 守卫。
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
- 响应封装减少整份拷贝：servlet/gateway 分三段写 `{"jwe":...}` 信封、复用 protected header 的 Base64URL。
- 请求体有界读在小包场景按 `Content-Length` 预分配（上限 64KB，避免大声明值放大内存）；`StrKit` 名单匹配改为循环，避免每请求 stream/matcher 分配。
- 启动日志打印四条 `skip-*` 名单；`text/event-stream` 命中 skip 或名单为空且响应上限开启时给出 WARN。
- 固定 `maven-jar-plugin`/`maven-source-plugin` 版本，`project.build.outputTimestamp` 生效（同一 commit 两次打包字节一致）。
- `skip-res-content-type` 默认包含 `text/event-stream`，SSE 开箱不再被缓冲到超限。
- 依赖瘦身：`hutool-all` 改为 `hutool-json`（servlet 侧的 `IoUtil`/`ThreadUtil` 换成 JDK/Spring 等价物）、core 移除未使用的 `mockito-core`、BOM 移除无人使用的 `spring-cloud-starter-bootstrap`。

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
- `chunked` 表单载体在配置 `max-request-size` 时与 JSON 一样返回 413，不再交给容器无界解析。
- 网关请求体改写改用 `Flux.defer`，请求被二次订阅（重试过滤器）时 body 不会为空。
- `CryptoExecutor` 随 Spring 上下文关闭（`@Bean(destroyMethod="dispose")` + `DisposableBean`），不再残留非守护线程。
