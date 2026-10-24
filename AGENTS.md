# AGENTS.md

## 安全边界

- 承诺：机密性 + 完整性（AEAD）+ 现代算法 + 密钥轮换（kid/JWKS）。**不承诺**客户端身份认证（TLS + Spring Security 承担；公钥公开、任何人可构造合法报文是设计内 non-goal）。不是 TLS 的替代。

## 必须限制

1. `encryptor-core` 零 Spring、零 `org.bouncycastle`；BC 只允许在可选模块 `encryptor-sm`（不注册全局 Provider、不被任何 starter 传递）。
2. v1 协议已删除，残留 grep 必须 0 命中：`EncryptorDataWrapper|AES_K|md5withaes|DigestWithEncryptSigner|GroupEncryptor|HexEncoder`。
3. 防重放校验必须在 AEAD tag 校验**之后**（未认证输入不得污染 nonce 存储）；nonce 保留期 ≥ 2·ttl 构造期强制。
4. `Cipher` 非线程安全：每次新建，禁止缓存单例。
5. ECDH-ES：`epk` 属 protected header、参与 AAD（改其解析口径 = 改 AAD）；只支持 P-256；`apu`/`apv` 必须进 Concat-KDF；共享秘密左补零 32 字节。
6. 协议演进通道唯一：additive claim + 服务端软接受；`crit` 非空一律 fail-closed 拒绝。
7. 载体编解码只走 core `kit/CarrierKit`（QUERY 明文 = form 语义 urlencoded 且即完整 query；jwe 在 query string 上一律按 QUERY 载体），两侧过滤器不得写本地实现。
8. skip 名单机制只改 core `config/base/SkipListsConfigBase`（两侧配置类只继承）；content-type 名单按 media-type 段（剥 `;` 参数、小写）整串正则匹配。
9. `crypto-config`/`routes` 的键结构 `Map<正则, RouteRule>` 已固定，扩展只往 RouteRule 加字段，禁止改 Map 值类型。
10. 过滤器 order 全可配，但相对链序启动期校验（顺序错 = 启动失败而非静默明文）；网关下游必须是不带 encryptor 的普通应用。
11. 审计不双计：codec 内失败由 `JweCodec` 回调、codec 外失败由过滤器补发；`EncryptorListener` 保持全 default 方法。
12. `JweContext.destroy()` 后 `cek()`/`plaintext()` 抛 `IllegalStateException`，不得改回静默返回全零。
13. 双线版本只 bump root 的 `project.version` + `encryptor.javax.line.version`（boot3 pom 引用该 property，禁止字面量）；`-Pmain-module,boot3` 不可组合；`-Pboot3` reactor 不含 core/reactive（从本地仓库解析 javax 线制品）。
14. POM 必须兼容 Maven 3.9+（`pluginManagement` 同插件重复声明是硬错误）。
