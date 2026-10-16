# 机制级安全审查（传输加解密机制）

> 生成于 2026-10-16。**基于静态阅读**（codegraph + 逐文件阅读），**未做动态验证/渗透测试**。可通过自写客户端脚本快速实证的条目已在各条注明。
>
> 代码级问题清单见 `open-issues.md`（编号 P0-x …），本文编号 `S1…`，两者交叉引用。

## 0. 结论先说

这套机制提供的是 **「传输加密 + 报文自洽完整性」**，**不提供「客户端身份认证」**。

- 防"被明文抓包" ✅
- 防"报文被篡改"⚠️ 部分（完整性建立在 MD5 上，且无域分离）
- 防"伪造请求" ❌ **完全没有**（唯一的服务端秘密是 RSA 私钥，而公钥是公开的）
- 防重放 ⚠️ 默认未启用 + 有三处洞（P0-4/P0-5/S5/S6）

README 用的词是"数据传输加解密通用实现组件"，没有承诺认证；但**使用方极易把"有签名"误解成"能防伪造"**，建议在 README 与 `AGENTS.md` 里把它写成显式非目标（non-goal）。

## 1. 机制数据流（一次请求）

```text
客户端（示例前端 front/index.js）
  1. key      = base64(16 个随机字符)                     ← AES-128 密钥 K（明文放在闭包里）
  2. iv       = 16 个随机字符                              ← IV（一个请求内固定复用）
  3. options  = { mode:"CBC", padding:"PKCS5Padding", key, iv }
  4. key 字段 = RSA_PKCS1v15_encrypt(服务器公钥, options)   ← 公钥公开在前端 JS 里
  5. data 字段      = Base64( AES_CBC_PKCS5(K, iv, 业务明文) )
  6. signature 字段 = Base64( AES_CBC_PKCS5(K, iv, MD5Hex(nonce+timestamp+data) 的 UTF-8 字节) )
  7. nonce = 24 个随机字符；timestamp = Date.now()

服务端（EncryptorFacade.decrypt → EncryptorKit.decrypt:29-45）
  8. negotiateEncoder.decrypt(key 字段)  → RSA 私钥解密 → options JSON     ← 客户端可选 mode/padding/key
  9. for CheckerStrategy : check(data)   → nonce 未用过 + 时间窗          ← 先于验签！
 10. signerEncoder.verify(signature, MD5Hex(nonce+timestamp+data))
 11. encryptorEncoder.decrypt(data 字段) → 业务明文
 12. 响应：用同一个 K/iv 再 AES 加密回去
```

关键事实：**`data`、`signature`、响应体三者共用同一 `(K, iv)`**（两个 auto-config 里 `strategyFunction` 被 data 与 signer 复用，见 `EncryptorAutoConfiguration.java:48-57`）。

## 2. 威胁模型

| 攻击者 | 能力 | 现状 |
| --- | --- | --- |
| 被动监听者 | 抓包看密文 | ✅ 无法读明文（除非 K 可预测，见 S10） |
| 主动中间人 | 改字段、重放、注入 | ⚠️ 可改 `key`（只会导致解密失败，不被识别为篡改，见 S7） |
| 任意匿名请求者 | 持有公钥（**前端 JS 里就有**） | ❌ **可构造完全合法的请求**（见 S1） |
| 内部/测试开关 | 发 `x-skip-encryptor` 头 | ⚠️ 开启 `skip-able` 后任何人可绕过全部加解密（见 S9） |

## 3. 安全目标达成度

| 目标 | 达成 | 依据 |
| --- | --- | --- |
| 机密性（防被动监听） | ✅ | RSA 分发 + AES-CBC |
| 完整性（防篡改） | ⚠️ | 建立在 MD5 上（S2）+ 无域分离（S4）+ 覆盖面不足（S7） |
| 认证（防伪造） | ❌ | S1 |
| 防重放 | ⚠️ | 默认关闭 + 单向时窗 + 容量驱逐 + 校验顺序（P0-4/P0-5/S5/S6） |
| 前向保密 | ❌ | 无会话密钥协商，每次请求自带 K（无 PFS 可言，属设计） |
| 算法/密钥可演进 | ❌ | 无 `v`/`alg`/`kid`（S12） |

## 4. 发现明细

### S1 无客户端身份认证 → 任何人都能伪造合法请求 ❌（最高优先级认知问题）

- **论证**：服务端唯一的秘密是 RSA 私钥；公钥是公开的，**并且就写在前端代码里**（`encryptor-examples/web-example/front/index.js:8`、`encryptor-examples/gateway-example/gateway/front/index.js:8`）。因此任何攻击者都能：
  1. 自选 `nonce` / `timestamp`；
  2. 自选 AES `key` / `iv`，用**公开的公钥**加密出合法的 `key` 字段（`RSA_PKCS1v15_encrypt` 是公开运算）；
  3. 用该 key 加密自己的 `data`；
  4. 计算 `signature = AES_K(MD5(nonce+timestamp+data))`。
  服务端第 8–11 步全部校验都会通过。
- **结论**：这里的"签名"只保证**报文字段之间的自洽**，等价于"传输层完整性"，**不证明来源**。它不能替代认证。
- **建议**：
  - 在 README / `AGENTS.md` 显式写为**非目标**（"本组件不提供客户端认证"）；
  - 若需要防伪造：客户端私钥签名（服务端持公钥验签），或预共享密钥 + HMAC（`v2` 协议）；
  - 现阶段的现实缓解手段只有防重放（P0-4/P0-5/S5/S6）——所以那几条不是"锦上添花"。
- **可实证**：写 20 行 node 脚本用示例公钥构造请求即可。

### S2 签名 = `AES_K(MD5(msg))`：摘要已被攻破 + 非常规构造 ❌

- **位置**：`EncryptorAutoConfiguration.java:55`、`EncryptorReactiveAutoConfiguration.java:55`（`new DigestWithEncryptSigner(new HtlDigester(new MD5()), strategyFunction.apply(params))`）；签名输入 `EncryptorKit.java:21`。
- **问题**：
  1. **MD5 是已知可构造碰撞的摘要**（2004 起，实际碰撞极廉价）→ 攻击者可构造 `data′ ≠ data` 但 `MD5(nonce+timestamp+data′) = MD5(nonce+timestamp+data)`，从而**复用他人签名**，完整性被破。
  2. **不是标准 MAC**：没有密钥参与摘要计算（不是 HMAC），而是"摘要再加密"。安全性完全押在 AES 是双射上：验证 = 解密后比较。
  3. **无域分离**：同一个 K 既加密 `data` 又"签名"，见 S4。
- **建议**：换 `HMAC-SHA256`（用独立子密钥 `K_mac`），或直接上 AEAD（AES-GCM，把 `nonce`/`timestamp`/`uri` 作为 AAD）。属协议变更，需 `v2`。

### S3 客户端可自选算法/参数，服务端无白名单 → 算法降级 ⚠️

- **位置**：`EncryptorAutoConfiguration.java:48-51`、`EncryptorReactiveAutoConfiguration.java:48-51`：`new AES(obj.getStr("mode"), obj.getStr("padding"), key, iv)`。
- **问题**：`mode` / `padding` / `key` 长度**全部来自客户端可控的协商报文**（且该报文可被任意伪造，见 S1）。客户端可以要求 `ECB`、`NoPadding`、`OFB`，也可用 16/24/32 字节任意长度 key；服务端照做，无校验、无审计。所谓"可切换算法"实际是**客户端单方面决定**，CBC/IV 相关的防护假设随之失效。
- **建议**：服务端白名单（`allowedModes` / `allowedPaddings` / 允许的 key 长度），不匹配即拒绝并告警；算法标识不要只靠 mode/padding，见 S12。
- **可实证**：把前端 `options.mode` 改成 `'ECB'` 发一次即可。

### S4 无域分离 + IV 固定：CBC 确定性、字段可互换 ⚠️

- **位置**：`EncryptorAutoConfiguration.java:48-57` 的 `strategyFunction` 同时喂给 data 加密器与 signer（`SignerEncoder` 内部也是同一 `EncryptorStrategy`）。
- **问题**：
  1. 一个请求内 `data`、`signature`、响应体**共用同一 `(K, iv)`**；CBC + 固定 IV → 明文前缀相同则密文前缀相同（确定性加密），可做前缀/字典分析。
  2. `data` 与 `signature` 处于**同一密钥空间、同一构造**（都是 `AES_CBC(K, iv, x)`），**没有角色标签** → 字段可互换/可混用（域分离缺失）。
  3. **无方向绑定**：请求密文与响应密文不可区分（无 direction 标记）。
- **建议**：用 HKDF 从主密钥派生独立子密钥（`K_data` / `K_mac` / `K_res`），或改 AEAD：AAD 绑定 `{nonce, timestamp, uri, direction}`。

### S5 校验顺序：nonce/时间窗先于验签 → 缓存投毒 + 驱逐 ⚠️

- **位置**：`encryptor-core/.../kit/EncryptorKit.java:37-44`：先 `for (CheckerStrategy ...) check(data)`，**之后**才 `signerEncoder.verify(...)`。
- **问题**：nonce 记录被**未经认证的输入**填充。攻击者可用垃圾请求洪泛（每个新 nonce 占一个 LRU 槽）→ **驱逐合法 nonce 记录** → 在时间窗内重放捕获到的合法请求；也可"抢先占用"某个 nonce 造成合法客户端被误判重放（DoS）。
- **建议**：先验签（建立完整性）再消费 nonce；或两阶段——先验签成功再写入 nonce 记录。

### S6 防重放三重弱点 ⚠️

- (a) starter 默认不启用（`open-issues.md` P0-4）；
- (b) 只挡过去不挡未来（P0-5）；
- (c) `InMemoryNonceChecker(1000, 30s)`（示例 `WebApplication.java:18`）容量仅 1000 → 高并发下 LRU 驱逐使"30s 内不可重放"的保证不成立。
- **建议**：默认启用 + 双向时窗 + 容量按"TTL 内最大请求量"估算或用 Redis（`setIfAbsent`），并暴露命中/驱逐计数指标。

### S7 签名覆盖面不足 + 拼接歧义 ⚠️

- **位置**：`EncryptorKit.java:21`：签名输入 = `nonce + timestamp + data` **字符串直接拼接**。
- **问题**：
  1. **不含 `uri` / `method` / 方向** → 在防重放关闭时可**跨接口重放**（同一报文打到另一个接口）；也无法做"请求绑定到接口"。
  2. **不含 `key` 字段**（承载 mode/padding/AES key/iv）→ 篡改 `key` 只会导致解密失败，**不会被识别为篡改**（审计上无法区分攻击与客户端 bug）。
  3. **无分隔符/长度前缀** 的字符串拼接存在歧义空间（`nonce` 尾与 `timestamp` 头可重排）。
- **建议**：签名输入改为规范化结构（含 `uri`/`method`/`v`），加分隔符或长度前缀。

### S8 RSA 密钥传输用 PKCS1 v1.5 + 示例 1024 位 ⚠️

- **位置**：`EncryptorAutoConfiguration.java:53`（`new RSA(config.getAlgorithm(), ...)`，默认算法见 `CryptoConfig`）、`front/encryptor/rsa.js:11`（`RSAES-PKCS1-V1_5`）；示例公私钥为 1024 位（`gateway-example/gateway/front/index.js:8`）。
- **问题**：
  1. **PKCS1 v1.5 解密失败与其它错误的可区分性** → 理论上存在 **Bleichenbacher padding oracle**（低危，但应消除）；
  2. 1024 位**低于现行最低建议**（≥2048）；
  3. 1024 位下单次仅能加密 **117 字节**，而协商报文已接近该上限 → `key`/`iv` 一变长，前端直接抛错（P1-4）。
- **建议**：改 `RSA/ECB/OAEPWithSHA-256AndMGF1Padding`（hutool 可通过 `algorithm` 配置；node-forge 改 `RSA-OAEP`）+ 2048 位以上；解密失败统一为不可区分的 `EncryptorException`。

### S9 客户端可自行跳过加密（opt-in，但一旦打开等于裸奔）⚠️

- **位置**：`EncryptorSkipFilter.java:15,24`（读**请求头** `x-skip-encryptor`）+ `GatewayEncryptorConfiguration.java:81-84`（`@ConditionalOnProperty(prefix = "encryptor.config.reactive.gateway", name = "skip-able", havingValue = "true")`，注册时 `logger.warn("...JUST GIVE A WAY TO SKIP IN TEST, DO NOT USE IN PRD!!!")`）。
- **问题**：一旦在非测试环境打开 `skip-able`，**任何客户端**都能发 `x-skip-encryptor` 绕过全部加解密。web 侧无此能力。
- **建议**：保持默认关闭；生产用配置中心强制校验；或限制为仅内网/白名单来源。

### S10 熵源不是密码学安全 ⚠️

- **位置**：`front/encryptor/random.js:13`（`Math.random()`）用于 AES key / IV / nonce；服务端 `EncryptorKit.java:19`（`IdUtil.fastSimpleUUID()`，非 CSPRNG）。
- **问题**：AES-128 key 与 IV 可预测；nonce 可预测（配合 S5 更容易命中驱逐）。
- **建议**：前端 `crypto.getRandomValues` / `randomBytes`，服务端 `SecureRandom`。

### S11 错误处理与可区分反馈 ⚠️

- **位置**：`core/.../exception/EncryptorException.java` 的文案：`"request replay"`、`"sig check error"`、`"request out of time or client time error"`。
- **问题**：若直接透出到响应/日志，攻击者可区分"填充错 / 验签错 / 重放"（对 S8 的 oracle 尤其有用）；且**无速率限制、无失败计数告警**。
- **建议**：对外统一（`400` + 通用文案 + traceId），对内结构化日志 + 指标 + 限流。

### S12 密钥管理与协议演进 ❌

- **位置**：私钥/公钥放在应用配置（`CryptoConfig.privateKey` / `publicKey`）。
- **问题**：无 `kid`、无轮换、无多密钥并存；报文 `EncryptorDataWrapper{nonce,timestamp,signature,key,data}` **无 `version` / `alg` 字段** → 换算法/换密钥需前后端同时改并停机。（P0-2 的兼容困境正是这个结构的产物。）
- **建议**：报文加 `v`(version) + `alg`，服务端按版本矩阵解析；密钥支持多套并存 + `kid` 选择。

### S13 响应方向无新鲜度证明（轻微）ℹ️

- 响应体只用同一 K 加密，**无反向 nonce / 序号 / MAC**。客户端无法判断响应是否新鲜，响应重放对客户端有效（示例 JS 侧也没有校验）。
- **建议**：如需闭环，响应带 `MAC(K_res, respNonce + data)`。

## 5. 建议优先级

1. **S3 + S5 + S6**：不改协议即可显著缩小攻击面（白名单校验、验签顺序、默认启用双向时窗）。
2. **S1 写进文档作为非目标**：否则使用方会误以为"有签名 = 能防伪造"。
3. **S2 / S4 / S7 / S8 / S12**：协议级改造，建议合并为一个 **"协议 v2"** 一次做完（引入 `v`/`alg`/`kid`、AEAD 或 HMAC、AAD 绑定），不要零敲碎打。

## 6. 未验证说明

本文全部结论来自**静态阅读**（含前端 JS 与两侧 Java 的行为对照）。未做：动态验证、渗透测试、性能压测。其中最值得先实证的三条：**S1（伪造请求）、S3（算法降级）、P0-2（网关 JS 客户端解不开）** —— 三者都可以用几十行脚本确认。
