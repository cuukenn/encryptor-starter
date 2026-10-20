# 机制级安全审查（传输加解密机制）

> 📌 **v2 状态表（2026-10-17，JWE 协议重做后复核）**：以下是 v1 机制（自研 RSA-PKCS1v15 + AES-CBC + MD5-AES 签名）的审查记录。v2 对齐 JOSE/JWE 后逐条处置：
>
> | 条目 | v2 处置 |
> | --- | --- |
> | S1 无客户端身份认证 | ❌ **仍成立（设计内 non-goal）**：认证交给 TLS + Spring Security（JWT/mTLS），已写入 README/AGENTS 的安全边界 |
> | S2 MD5-AES 签名 | 🟩 消除：无独立签名概念，完整性由 GCM/SM4-GCM AEAD tag 内建 |
> | S3 算法降级 | 🟩 消除：alg/enc 白名单在 JweCodec 内强制，客户端不可自选 |
> | S4 域分离/IV 固定 | 🟩 消除：AAD 绑定 uri/m/dir/ts/nonce；每请求新 IV |
> | S5 校验顺序 | 🟩 消除：ReplayGuard 在 tag 校验后才消费 nonce |
> | S6 防重放弱点 | 🟩 消除：对称时间窗（ttl）+ 原子 consume + 容量上限 |
> | S7 签名覆盖面/拼接歧义 | 🟩 消除：无字符串拼接签名面，AAD 为结构化 protected header |
> | S8 PKCS1v15/1024 位 | 🟩 消除：RSA-OAEP-256（示例 RSA-2048）；国密 SM2 |
> | S9 客户端可跳过加密 | 🟩 消除：require-encrypted 默认 true（fail-closed），bypass 是服务端运行期开关 |
> | S10 熵源 | 🟩 消除：WebCrypto/SecureRandom |
> | S11 错误可区分 | 🟩 消除：EncryptorFailure 枚举分类 + 对外统一 failure-status + 对内 listener/日志 |
> | S12 密钥管理/演进 | 🟩 消除：kid 多钥并存 + JWKS 发现端点 + 轮换 SOP（README） |
> | S13 响应新鲜度 | 🟩 消除：响应 JWE 带新 ts/nonce |
> | S14 IV 复用 | 🟩 消除：每请求新 CEK/IV/nonce（服务端与 JS 客户端都强制） |
> | S15 审计信号 | 🟩 消除：EncryptorListener（core，0 行 starter 改动可接指标） |
> | S16 网关明文写回下游 | ⚠️ **仍成立（架构约束）**：网关下游必须是不引入 encryptor 的普通应用；已写入 README/AGENTS 并有示例演示 |
> | S17 缓冲/事件循环 | 🟩 消除：max-request-size/413、max-response-size/500、有界执行器（bench 验证 RSA 并行度 3.83×） |
>
> **结论**：v2 后仅 S1（不提供认证，设计内 non-goal）与 S16（网关下游约束，文档化）为“明确接受的边界”，其余全部消除。

> 📦 v1 原始记录已归档到 [docs/archive/security-review-v1.md](../archive/security-review-v1.md)；本文只保留 v2 状态表与结论。
