# 机制级安全审查 v1 原始记录（归档）

> 生成于 2026-10-16，v1 协议时代；仅用于追溯。当前 v2 状态表见 [security-review.md](../architecture/security-review.md)。

>
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

### S14 示例前端把同一 `(K, IV)` 复用到同页面的**所有**请求，协议也不强制 IV 新鲜度 ⚠️（2026-10-16 第三批扫描发现；**已由可执行测试固定，未修**）

- **位置**：`encryptor-examples/web-example/front/index.js:9-12`（以及 gateway 侧同构文件）：`const key = aes.generateBase64Key(128)` 与 `const options = {iv: random.getRandomStr(16), …}` 是**模块级常量**，往后的 `test get` / `test post` / `test post(form)` 三个请求**共用**同一 `(K, iv)`。
- **问题**：CBC + 固定 IV ⇒ **确定性加密**：同一密钥下不同明文若前缀相同，密文前缀也相同。攻击者可做前缀/相等性分析（例如判断"两次请求的业务数据是否一样"）。叠加 S4（`data`、`signature`、响应体共用同一 `(K, iv)`）与 S1（任何人可伪造），这套"每次请求协商一个 AES key"看起来像会话密钥，实际**每次请求都该换 IV，示例却没换**。
- **协议缺陷**：IV 藏在 RSA 加密的 `key` 字段（`options` JSON）里，报文没有独立的 IV/nonce 字段 → 服务端**无法检测、也无法纠正**客户端跨请求复用 IV；响应还复用客户端给的 `(K, iv)`。
- ✅ **已证据化（2026-10-16，`mvn` 验证）**：`CryptoMechanismAuditTest#test_reused_key_and_iv_make_ciphertext_deterministic` 断言了"固定 (K,IV) 下同一明文两次加密密文相同""首分组相同的明文 → 密文首分组相同"。这是把上面这段静态推理变成**可复现证据**，不是修复。
- **建议**：① 示例前端每请求新 `iv`（协议已经能承载，只是没这么做）；② 文档写明"IV 不得跨请求复用"；③ 协议 v2 里让服务端参与（下发 IV / AEAD nonce，S12）。

### S15 完整性校验失败表现为"解密异常"而不是"验签失败"，审计信号丢失 🟡（2026-10-16 第三批扫描发现；**对外表现已由 P1-12 收敛，审计信号问题仍在**）

- **实证**（hutool 5.8.26）：`DigestWithEncryptSigner.verify` 的实现是"`AES.decrypt(signature)` 后与 `MD5(data)` 比较"，篡改 `signature` 一个字节时先抛的是 `CryptoException: IllegalBlockSizeException: Input length must be multiple of 16 …`（长度恰为 16 倍数时是 `BadPaddingException`），**根本走不到 `"sig check error"`**。
- ✅ **已证据化（2026-10-16，`mvn` 验证）**：`CryptoMechanismAuditTest#test_malformed_signature_escapes_as_crypto_exception` 断言了 signature=`"AAAA"` 时抛的是 `CryptoException` 而非 `"sig check error"`；同时 `#test_tampered_payload_is_caught_by_signature_check` 钉住了**正面**行为（改密文不动签名 → `EncryptorException("sig check error")`），两者互为对照。
- **问题**：① "有人在改报文"这个本该最响的信号，被降级成一个通用解密异常（日志/告警里看不到）；② 两种失败模式（长度错 vs padding 错）可区分，给 S8 的 padding oracle 提供额外信息；③ 没有失败计数/指标（S11 的补充）。
- **部分缓解（2026-10-16）**：P0-7 修完后，"字段缺失/为 null"这类畸形报文已经统一成 `EncryptorException` 而不再是 `NPE`/`CryptoException(NPE)`（见 `EncryptorKitTest`/`EncryptorFacadeTest`）。
- **进一步收敛（2026-10-16，P1-12）**：篡改导致的 `CryptoException` **不再逃逸**——`EncryptorFacade` 统一包装成 `EncryptorException`，web / gateway 两侧回**可配置的 `failure-status`（默认 400）**而不是 500，且异常带 cause 进日志（`EncryptorFacadeTest` 4 条先红后绿用例钉住）。
- **但本条的实质问题仍在**：对外仍然只是"解密/验签失败"一个笼统错误（没有把"有人在改报文"作为独立信号）；**没有失败计数/指标**（S11）；失败响应也没有 traceId。`DigestWithEncryptSigner.verify` 依然是"先解密再比较"，"验签失败"这个语义只在解密**成功但内容不符**时才出现。
- **建议**：`verify` 内 catch `CryptoException` 一律 `return false`（统一成"验签失败"）；对验签/解密失败做指标与告警；对外只回 traceId（S11）。

### S16 网关把解密后的参数**明文**写回下游 URI ⚠️（2026-10-16 第三批扫描发现；**端到端已实证其后果，未修**）

- **位置**：`encryptor-gateway-starter/.../reactive/gateway/filter/rewrite/EncryptorRequestParameterFilter.java:61-70`：`UriComponentsBuilder.fromUri(...).replaceQueryParams(解出来的参数).build().toUri()`。
- **问题**：
  1. 解密后的业务参数出现在**下游请求行**里 → 下游服务、中间代理、链路追踪的访问日志里是**明文**。客户端→网关那一段仍是密文（目标达成），但"链路内不落明文"的隐含预期被打破，需要写进文档。
  2. `build()` 未 `encode()`：明文里若含 `&`、`#`、`%`、`+` 等字符会被重新解释或双重编码，参数可能被改坏（`.encode()` / `build(true)` 的语义要明确并加用例）。
  3. 重建后的 query **只含解密出来的参数** → 原请求里其它非加密参数（如上游/客户端附加的 `traceId`）会被静默丢弃。
- ✅ **端到端已实证（2026-10-16）**：把 `web-example`（也带 starter）当成网关的**下游**时，GET/POST 一律 **400** —— 网关转发的是**明文**参数，下游 starter 又去解密（`key=null`）→ P1-12 之后是 400（修前是 500）。换成没有引入 encryptor 的下游（`encryptor-examples/gateway-example/web`）才 2/2 绿。**这既是 S16 的行为证据，也说明"下游若也带 starter 会 400"是必须写进文档的架构约束。**
- **建议**：文档写明"网关会在下游侧还原明文参数（下游只应看到明文）"；明确编码策略（`build()` 未 `encode()`，含 `&`/`+`/`#` 的参数可能被改坏）；只替换加密字段而不是整体替换 query。

### S17 无大小上限的缓冲 + 每请求强制 RSA 私钥运算（网关还跑在事件循环上） 🟡（2026-10-16 第三批扫描发现；**请求上限/事件循环/重复 RSA 已修，响应全量缓冲仍在**）

- **web**：`web/filter/EncryptorRequestBodyFilter.java:44` 无上限读全量 body；`web/filter/EncryptorResponseFilter.java:35` 用 `ContentCachingResponseWrapper` 把**整个响应体**缓存进堆。
- **gateway**：`ModifyRequestBodyGatewayFilterFactory`（inClass=String 时先整体转 String）同样全量缓冲；`RewriteFunction` 在 **Netty event loop** 上同步执行 RSA 私钥运算 + AES。
- **结合 S1**（这些路径全部在认证之前）：单个未认证请求即可放大成堆内存/CPU 压力；每个加密往返还至少 **2 次 RSA 私钥运算**（请求解密 1 次 + 响应加密时重新解析 `key` 1 次，见 P2-7）。
- **建议**：报文大小上限（超限 4xx）+ 大响应流式处理；网关侧把加解密放到有界弹性调度器；记录耗时/失败率指标（配合 S11/S15）。
- **已修（2026-10-16，代码级见 P1-13 / P2-7）**：
  - **请求大小上限**：`encryptor.config.web.max-request-size`（默认 1048576 字节，`<=0` 不限）→ 超限直接 `413` 且不进业务链（有 Content-Length 与 chunked 两条路径都有界）；gateway 侧同名字段已加（`GatewayEncryptorConfig#maxRequestSize`，暂未在网关上强制——网关是流式的，留待后续）。
  - **事件循环**：网关三个 `MessageReader/Writer` 的 RSA/AES 运算已 `subscribeOn(Schedulers.boundedElastic())`，不再阻塞 Netty event loop。
  - **重复 RSA**：`EncryptorFacade` 的记忆化使**同一请求**的响应方向不再重做 RSA 私钥运算（一往返 2 次 → 1 次）；facade 本身也按命中的配置 key 缓存（不再每请求 `new RSA`）。
- **仍未修**：**响应**方向依旧全量堆内缓冲（web `ContentCachingResponseWrapper`、gateway `ModifyResponseBody`）→ 大响应仍应避免；无耗时/失败率指标（配合 S11/S15）；网关侧未强制 `maxRequestSize`。

## 5. 建议优先级

1. **S3 + S5 + S6**：不改协议即可显著缩小攻击面（白名单校验、验签顺序、默认启用双向时窗）。
2. **S1 写进文档作为非目标**：否则使用方会误以为"有签名 = 能防伪造"。
3. **S2 / S4 / S7 / S8 / S12**：协议级改造，建议合并为一个 **"协议 v2"** 一次做完（引入 `v`/`alg`/`kid`、AEAD 或 HMAC、AAD 绑定），不要零敲碎打。
4. **S14 + S15 + S16 + S17**（第三批新增）：使用面/工程面加固——IV 不复用（改示例即见效）、失败统一为"验签失败"+ 指标、网关明文参数边界写进文档并修编码、报文大小上限 + 事件循环外移。都不需要改协议。
   - **进度（2026-10-16 第三批当批）**：S17 的"请求上限 / 事件循环 / 重复 RSA"三项与 S15 的"对外表现"已修；**S14（示例前端复用 IV）与 S16（下游明文边界 + `build()` 未 encode）、S15 的指标部分仍未做**。

## 6. 验证状态

本文的**分析**来自静态阅读（含前端 JS 与两侧 Java 的行为对照）；未做渗透测试与性能压测。

**能跑构建之后（2026-10-16）新增的验证**：本机 `java`/`javac` 11.0.28 + Maven 3.8.9（`/usr/local/maven/3.8.9/bin/mvn`），全量 `mvn clean install`（含 examples）**BUILD SUCCESS / 73 tests**（core 43 / reactive 1 / web 17 / gateway 10 / web-example 2）。另外示例已**真实起服务跑通端到端**（web-example:8081 的 uri 级密钥正向/反向两条，与 gateway:8080 → gateway-example/web 下游）。据此：

- **已用可执行测试固化为证据**（`encryptor-core/src/test/java/io/github/cuukenn/encryptor/audit/`）：**S7**（签名输入歧义：nonce/timestamp 边界可平移且验签仍过）、**S14**（固定 (K,IV) 的确定性）、**S15**（畸形签名抛 `CryptoException` 而非 `"sig check error"`）、**S1**（`ClientAuthAuditTest#test_anyone_with_the_public_key_can_forge_a_valid_request`：只持公钥即可伪造被服务端接受的请求）、**S3**（`ClientAuthAuditTest#test_server_accepts_any_client_chosen_algorithm_without_whitelist`：ECB + 24 字节 key 照样被接受）、**P2-8**（`CryptoMechanismAuditTest#test_group_encryptor_does_not_leak_repeated_plaintext_blocks`：分组不再泄漏）。同时钉住了**正面**承诺：只改密文 → `EncryptorException("sig check error")`。
- **已修复并验证**（第一批/第二批）：**P0-2**（网关 key 编码，改前 `BadPaddingException`）、**P0-6**（`black-req-content-type` 在网关生效）、**P0-7**（畸形报文统一成 `EncryptorException`，不再是 NPE）、**P1-10**（带 `;charset=UTF-8` 的表单可识别）。
- **已修复并验证**（第三批当批，详见 `open-issues.md`）：**P1-9**（`black-res-content-type` 求值时机，两个方向）、**P1-11**（参数 wrapper 三个视图一致）、**P1-12**（错误面统一 + `failure-status`，S15 的对外表现）、**P1-13**（请求大小上限 + 网关切 `boundedElastic`，S17 的两项）、**P2-1**（两个 `HttpTest` 加断言并真跑通，顺带修掉 3 个示例真 bug）、**P2-7**（facade/params 缓存，S17 的重复 RSA）、**P2-8**（见上）、**P3-7**（uri 级 `crypto-config` 括号写法，含 `CryptoConfigBindingTest` 绑定证据 + 端到端正反向）、**P2-9 / P2-10 / P3-6 / P3-8**（死代码依赖、自动装配、StrKit 契约、pom/环境）。
- **仍为静态结论 / 未实证**：**S5/S6**（验签顺序与重放窗口）、**S8**（padding oracle）、**S9**、**S11**（指标/告警）、**S12**（协议 v2）、**S13**、**S16**（下游明文边界，端到端已观察到 400 现象但未加固）、**S14**（示例前端 IV 复用，未改）。S1/S3 已从本行移出（已补端到端证明）。
