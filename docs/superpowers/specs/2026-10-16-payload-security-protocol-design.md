# encryptor-starter 报文层安全协议重设计（2026-10-16）

> 状态：**待批准**。批准前不写任何产品代码（`brainstorming` HARD-GATE）。
> 本文是一份"有能力的 builder 不必回头问我就能据此做计划"的设计文档。

## 0. 一句话意图

把今天这套**自研的应用层混合加密**（RSA-PKCS1v15 封装客户端自选 AES key + AES-CBC + `AES_K(MD5hex)` 签名 + 先解密再比较）换成**对齐 JOSE/JWE 标准的报文层安全**：机密性 + 完整性 + 现代算法 + 可轮换密钥；**身份认证不在本层解决**。

## 1. 为什么（背景）

第 4 轮设计级评审（只读）的结论，作为本文的事实基础：

- **形态是主流的**：`filter/gateway-filter + 策略 SPI + 报文对象` 的分层与国内同类 starter 同构，比多数同类多做了 reactive/网关一侧。**保留**。
- **密码学配方不是**：`RSA/PKCS1v15` 直接封装**客户端自选**的 AES key；`AES/CBC/PKCS5`（无完整性）；"签名" = `AES_K(MD5hex(nonce+timestamp+data))`，验签 = **先解密再 `Arrays.equals`**。
- **致命点**：MAC 密钥是客户端自选并随报文上传的（服务端无任何秘密参与）⇒ **"签名"等价于一个没有秘密的 MAC，不提供防伪造**（`ClientAuthAuditTest` 已把 S1/S3 钉成可执行断言）。同时 MD5 可碰撞、CBC 无完整性、PKCS1v15 有 padding oracle 面、字段间无域分离、无算法白名单、无 `v`/`alg`/`kid`（换算法/换密钥只能停机两端同切）。
- **性能与可运维的硬伤**（见第 4 轮性能/运维评审）：`facadeCache` 让同一配置下所有请求共用**一个** `RSA` 实例，而 hutool 的 `AsymmetricCrypto` 被实例级 `ReentrantLock` 包住 ⇒ RSA 私钥运算**全局串行**；响应方向**全量堆缓冲且无上限**（明文请求也被包装，SSE/下载会坏）；每往返 4 个 AES + 4 次 params JSON 解析；正则每请求重编译；网关 `max-request-size` 是死配置；**失败静默 400、无日志/无指标/无 traceId**；所有旁路开关都是启动期，**没有运行期总闸**。

## 2. 目标与非目标

### 2.1 目标（本次要做）

1. **机密性**：报文内容对中间人不可读。
2. **完整性**：密文或上下文被篡改必须**可检出**，且这是 AEAD 的内建性质，不依赖"先解密再比较"。
3. **现代算法**：AEAD（AES-GCM）+ 标准密钥封装（RSA-OAEP-256），不使用 MD5、不使用 PKCS1v15 封包、不使用 CBC。
4. **上下文绑定**：密文与"这条请求是谁发到哪个 uri、什么方法、哪个方向"绑定（AAD），防止密文跨接口/跨方向搬运。
5. **密钥可轮换**：服务端可持多把密钥并公布 `kid`；轮换与回滚不停机、两端不同批。
6. **可运维**：失败可区分、可观测（日志 + 指标）、有运行期旁路开关、有报文大小上限、RSA 运算可并行。
7. **易用性不退步**：客户端（浏览器）**仍然只需要服务端公钥**，不需要自己的密钥对。

### 2.2 非目标（明确不做，且要写进 README/AGENTS.md）

1. **不提供客户端身份认证 / 防伪造**（用户已定：认证交给 TLS + Spring Security 的 JWT/mTLS）。报文被"谁"发出的，本层不回答。

   > **术语边界（必须写进 README，避免误读）**：
   > - **加解密 = 机密性**：内容不外泄。
   > - **防篡改 = 完整性**：密文或上下文被改过一定验不过。**是本 starter 承诺的特性**，由 AEAD tag + AAD 绑定实现。
   > - **防伪造 = 身份认证**：证明"这条报文是某个特定主体发的"。**不是本层承诺**（公开公钥 ⇒ 任何人都能造一条全新的合法报文）。
   >
   > 三者常被混为一谈："防篡改"只回答"这条报文在传输中没被动过"，**不**回答"谁发的"。
2. **不替代 TLS**。它是 TLS 之上的纵深防御 / 合规外壳（防明文落库、防中间代理窥探）。
3. **不做前向保密**（PFS）。要 PFS 就得引入 ECDH-ES，留作将来选项，不在本次范围。
4. **不做 v1 兼容**（用户已定：「这个应该没什么人用、还是按全新的来吧」）。旧报文格式直接不支持。
5. **不做客户端侧（发起端）SDK**：仍只提供服务端（servlet / Spring Cloud Gateway）能力，客户端示例用 JS 演示。若将来要 Feign/WebClient 发起端，属新模块。

### 2.3 反目标（做到这些就算失败）

- 再出现一个"看起来像签名、实际无秘密"的机制，或任何"先解密再比较"的校验。
- 客户端仍能**单方面**决定算法（`mode/padding/key 长度`）。
- 为了"通用"把协议细节（字段名、签名输入）继续焊死在 core 里，导致换算法要改 core + 双写两侧 + 两套前端。
- 把旁路开关继续做成"必须重启"。

## 3. 协议规格（新，唯一版本）

### 3.1 报文载体

报文**不再摊平成 5 个字段**。内部载荷一律是 **JWE Compact Serialization**（`BASE64URL(header).BASE64URL(encrypted_key).BASE64URL(iv).BASE64URL(ciphertext).BASE64URL(tag)`）。

- **请求**：
  - GET/参数类：`?jwe=<compact>`（查询串里只有一个参数名 `jwe`）。
  - POST body 类：`Content-Type: application/json`，body = `{"jwe":"<compact>"}`；或 `application/x-www-form-urlencoded` 表单字段 `jwe=<compact>`。
- **响应**：`Content-Type: application/json`，body = `{"jwe":"<compact>"}`（与请求同形，便于客户端统一处理）。
- 内部明文的**语义不变**：请求解密后仍是"业务参数 / 业务 body"，交给业务链；响应加密前仍是业务写出的字节。

> 一个参数名、一个字段名，少了 4 个自研字段与全部"字段拼接 → 签名"逻辑。

### 3.2 JWE 头与算法策略

请求 JWE：

```json
{ "alg": "RSA-OAEP-256", "enc": "A256GCM", "kid": "<服务端密钥标识>", "typ": "encryptor+jwe" }
```

- `alg`：`RSA-OAEP-256`（默认）或 `ECDH-ES`（P-256 直接密钥协商，见 §3.10）。**服务端白名单决定接受哪些**。
- `enc`：`A256GCM`（默认；可配 `A128GCM`/`A192GCM`）。
- `kid`：**服务端**持有的密钥对标识；服务端按 `kid` 选择私钥解封（多把并存 ⇒ 轮换不停机）。
- **客户端不得自选 `alg`/`enc`/密钥长度**：服务端按白名单校验，不在白名单一律拒绝（消除今天的算法降级面）。

响应 JWE：

```json
{ "alg": "dir", "enc": "A256GCM", "typ": "encryptor+jwe" }
```

- **`dir`**：直接使用"请求里那把 CEK"（客户端已用它加密过请求，只有服务端能解封出来）。
- ⇒ 客户端**不需要密钥对**（保持易用性）；代价是不提供 PFS 与双向独立密钥（见 2.2 非目标 3）。
- 若将来要双向独立密钥，响应改用 `ECDH-ES`（客户端在请求里附一把临时公钥），属 v3 级演进。

### 3.3 上下文绑定（AAD）与防重放

- **AAD**（Additional Authenticated Data）= 规范化后的上下文串，至少含：`uri`（不含 query）、`method`、`direction`（`req`/`res`）、`ts`、`nonce`。AAD 在 JWE 中参与 tag 计算 ⇒ 密文不能跨接口/跨方向/跨时间搬运。
- **防重放**：`ts` + `nonce` 放**保护头（JWE protected header）**里（与密文一起被 tag 覆盖，不可篡改）；服务端**强制**校验：
  - `ts` 在允许窗口内（默认 ±5 分钟，可配）；
  - `nonce` 未使用过（默认 `InMemoryNonceChecker`，支持换 Redis 实现）；
  - 校验顺序：**先验 GCM tag / 解密成功，再消费 nonce**（避免未认证输入污染 nonce 存储）。
- `nonce` 由客户端生成（CSPRNG，≥96 bit），服务端不做下发（无状态、无往返）。

### 3.4 请求/响应全流程

```
客户端：
  CEK = random(32B)                       # CSPRNG
  JWE(protected header={alg:RSA-OAEP-256,enc:A256GCM,kid,ts,nonce},
      enc_key=RSA-OAEP(serverPub, CEK),
      iv=random(12B),
      payload=业务参数/body,
      aad={uri,method,req,ts,nonce})
服务端（filter）：
  解 JWE → 校验 kid 在白名单 → 解封 CEK → 校验 ts/nonce → GCM 解密（tag 校验 + AAD 校验）
        → 消费 nonce → 明文进业务链（GET 参数 / body）
  业务写出响应 → 用同一 CEK + 新 iv 生成响应 JWE（alg=dir）
  响应 AAD 用 {uri,method,res,ts,nonce}（服务端新生成，回给客户端可校验新鲜度）
客户端：解响应 JWE（同一 CEK）
```

### 3.5 失败面（对外不可区分，对内有信息）

- **命中加密范围但没有合法 `jwe`（缺失 / 空 / 非法）⇒ fail-closed**：`failure-status`（默认 400），**绝不静默放行**。理由：既然"防篡改"是本 starter 承诺的特性，一条未加密的请求不存在任何防篡改，放行等于作废该承诺。开关 `require-encrypted`，默认 `true`；设为 `false` 才允许明文透传，且启动时 `logger.warn` 告警。
- 所有失败（头非法 / `kid` 未知 / 解密失败 / GCM tag 不符 / `ts` 过期 / `nonce` 重放 / 超限）对外**统一**为：`failure-status`（默认 400）+ 通用文案（不含原因），响应带 `traceId`。
- **对内**：一律 `logger.warn`，带 `uri`、`method`、失败分类、`traceId`、耗时的 cause（不打印密文/明文/密钥）。
- 指标：`encryptor.decrypt{result,reason}`、`encryptor.encrypt{result}`、`encryptor.rsa.wait`（RSA 段耗时）、失败计数可用于告警。

### 3.6 大小与资源上限

- 请求：`max-request-size`（默认 1MiB）**两侧都真正强制**，超限 → `413`，不进业务链、不落日志噪音（只计数）。
- 响应：加密前检查 `max-response-size`（默认 4MiB），超限 → `500` + 明确日志（不静默、不把明文发出去）；SSE / 文件下载类 content-type 走 `skip-response` 名单**不包装**（今天明文请求被无脑包装的问题一并修掉）。
- 网关：密码学运算跑在**专用有界执行器**（不是裸 `boundedElastic`）：固定线程数 = CPU 数、有界队列、拒绝时回 `failure-status`，队列深度与拒绝数上报指标。
- **RSA 并行**：缓存**已解析的 `PrivateKey`/`PublicKey`（或 `kid → 密钥对）**，每次运算构造**短命**的 Cipher 对象（`Cipher` 非线程安全 → 用 `ThreadLocal<Cipher>`），**绝不**共享单 `Cipher`/单 `RSA` 实例。基准必须证明多线程吞吐随核数增长。

### 3.7 运行期开关（可运维）

| 开关 | 范围 | 运行期可改 | 语义 |
| --- | --- | --- | --- |
| `enable` | 全局 | 重启（过滤链注册） | 关掉 = 完全不处理 |
| `bypass.request` / `bypass.response` | 全局，按方向 | **可（每请求读）** | 该方向"原样透传"（请求不再要求密文、响应不加密）——用于止血 |
| **`skip-uris` / `skip-methods`**（旧名 `black-*` 为弃用 alias，P3-4 已实现） | 单 uri/method | 重启 | 完全跳过 |
| **`skip-req/res-content-type`**（旧名 `black-*` 为弃用 alias，P3-4 已实现） | content-type | 重启 | 该方向的处理跳过（**请求/响应语义必须在两侧一致**，改掉今天 web/gateway 不对称） |
| `failure-status` / `max-request-size` / `max-response-size` | 全局 | 重启 | 同今天，但网关也真正生效 |
| `x-skip-encryptor`（网关，`skip-able=true`） | 单请求 | 启动期预置 | 保持，但要求内网/共享密钥且启动时大声告警 |

- `bypass.*` 与 `facadeCache`/密钥缓存必须**联动失效**（有 `invalidate()`），否则热更后仍用旧钥。
- 启动时打印**生效配置摘要**：`kid` 清单 + 公钥指纹、black/skip 名单、`enable`/`bypass`/`failure-status`/上限值；**预构造一次密钥（解析失败即 fail-fast）**。

### 3.8 密钥发现端点（JWKS，**已定：方案 A**）

**为什么需要**：浏览器端无法按需重发（用户不刷新就没有新 JS）。把公钥/`kid` 钉死在客户端 ⇒ 每次换钥都要发前端版本；有发现端点后，服务端加 `kid`、切 `active-kid` 时**前端零改动**。

- **形态**：标准 **JWKS（RFC 7517）+ `kid`**。`GET <path>`（默认 `/.well-known/encryptor-keys`），响应：
  ```json
  { "keys": [ { "kty":"RSA", "use":"enc", "alg":"RSA-OAEP-256",
                "kid":"k2026-10", "n":"...", "e":"AQAB" } ],
    "activeKid": "k2026-10" }
  ```
  用 JWK（`n`/`e`）而非 SPKI：既是 JWKS 标准形态，**WebCrypto 又能原生 `importKey('jwk', …)`**，`jose` 亦可。
- **只含公钥**：绝不能出现私钥字段（必须有测试钉住）。
- **自身必须免加密（鸡生蛋）**：请求侧不要求 `jwe`、响应侧不加密——客户端在拿到公钥前不可能加密任何东西。因此该路径**隐式加入 skip 名单**，不参与 `require-encrypted`。
- **缓存**：`Cache-Control: public, max-age=<cache-max-age>`（默认 5m）+ `ETag`；客户端整页加载拉一次并缓存。
- **轮换配合**：客户端按 `kid` 封包；服务端不认识该 `kid`（客户端缓存过期）时仍统一 400；客户端 helper 规则 = **首次 400 刷新一次 JWKS 并重试一次**（有界，不循环）⇒ 不新增错误信号、失败面保持统一。
- **归属**：web 侧由本 starter 的 `WebFilter` 处理；网关侧由网关自身处理（**不转发下游**，下游无需知道）。`encryptor.config.discovery.enable=false` 可关闭。
- **限流**：内容静态可缓存，无需鉴权。

**轮换 SOP（写进 README）**：① 加新 `kid`（含公钥）→ ② 观察客户端开始用新 `kid`（≤ 缓存 TTL）→ ③ 切 `active-kid` → ④ 旧 `kid` 只解不封，直到确认无旧客户端流量 → ⑤ 移除旧 `kid`。

> **实现校正（2026-10-18 评审）**：`ServerKeyStore` 启动期构建、运行期不可变，JWKS 的 ETag 同样在启动期算定 ⇒ ①⑤ 两步**必须重启**（滚动重启），原写法的"全程不停机"不成立；且客户端必须等所有实例都升级完才开始用新 kid。README 的 SOP 已按此改写。

### 3.9 国密（SM2 / SM4-GCM）—— 必须支持

**范围**：只加算法层，**不改线格式**（仍是单 `jwe` 字段的 JWE Compact）。与 RSA/AES 并存。

- **算法名**：`alg=SM2`（CEK 封装，C1C3C2 排列）、`enc=SM4-GCM`（内容 AEAD）。二者不是 IANA/JOSE 注册名，本实现只当作字符串白名单项；nimbus 对未知名会新建实例，结构/头解析照常可用。
- **密钥**：服务端 `keys[]` 增加 `type: RSA | SM2`（缺省 `RSA`）。SM2 私钥 PKCS#8、公钥 SPKI 或裸 64 字节（`x||y`）；启动期 fail-fast。JWKS 输出 `kty=EC, crv=SM2, x, y`（仍只发布公钥）。
- **实现**：只用 BouncyCastle **轻量级 API**（`SM2Engine`(C1C3C2)、`GCMBlockCipher`+`SM4Engine`、`PrivateKeyFactory`/`PublicKeyFactory`），**不注册全局 Provider**（不污染宿主 JCA、不与宿主已有 BC 版本冲突）。`bcpkix-jdk18on` 已在依赖里（T1/P2-9 记录：hutool 的国密也依赖它，勿删）。
- **一致性**：SM4-GCM 仍是 AEAD ⇒ 完整性由 tag 保证，**不引入** `SM4-CBC + HMAC-SM3`；若密评明确要求该组合，作为**追加的 `enc` 值**后补（套件 SPI 可扩展，不改线格式）。
- **JS**：WebCrypto 无 SM ⇒ SM 路径需纯 JS 库（`sm-crypto`）；RSA/AES 路径仍用 `crypto.subtle`。示例两条路径都演示，并注明 SM 路径需第三方库。

  > **实现校正（2026-10-18 评审）**：`sm-crypto` 只提供 SM4-ECB/CBC，**没有** SM4-GCM，不能直接用于本协议的 `enc=SM4-GCM`。当前两份 front 参考实现只演示 RSA 路径；国密路径由 core（`SmCipherSuiteTest`）、web（`SmJweTestSupport`）、gateway（`SmGatewayTestSupport`）三层 Java 测试覆盖。要在浏览器跑国密，需要引入具备 SM4-GCM 能力的 JS 实现（或走 WASM），属后续独立任务。
- **抽象**：SM 与 RSA/AES 在"CEK 封装 + 内容加密"两侧都不同，抽出 `CipherSuite` SPI（`algorithms`/`encryptionMethods`/`unwrapCek`/`aeadEncrypt`/`aeadDecrypt`/`keyLength`）；JCE 实现 `JceCipherSuite`、国密实现 `SmCipherSuite`；`JweCodec` 按 `alg`/`enc` 分派，白名单仍在本类内部强制。

### 3.10 ECDH-ES（P-256 直接密钥协商）—— 已实现（2026-10-18）

- **算法**：`alg=ECDH-ES`（RFC 7518 §4.6 直接密钥协商）+ `enc=A128/A192/A256GCM`。`encrypted_key` 段**为空**（与 `alg=dir` 一样），CEK 由双方协商派生。
- **`epk`**：客户端每次请求生成**临时** P-256 密钥对，把公钥以 JWK（`kty=EC, crv=P-256, x, y`）放进 protected header 的 `epk`；`epk` 属于 protected header，天然参与 AAD 校验。`epk` 携带私钥参数 `d` 一律拒绝。
- **KDF**：`CEK = ConcatKDF-SHA256(Z, enc, keydatalen)`，`K = SHA-256(counter=1 || Z || OtherInfo)`，`OtherInfo = AlgorithmID(=enc) || PartyUInfo(apu) || PartyVInfo(apv) || SuppPubInfo(keydatalen 位)`，每项 4 字节大端长度前缀（NIST SP 800-56A §5.8.1）。`apu`/`apv` 存在时必须进 OtherInfo（RFC 7518 §4.6.1；2026-10-24 起，此前恒空——与发送 apu/apv 的合规客户端会派生出不同 CEK），缺省为空；共享秘密 Z 统一左补零到 32 字节再派生。
- **曲线只允许 P-256**（`secp256r1`）：WebCrypto、Java 8 SunEC、nimbus 都原生支持，**不引入新依赖、不注册全局 Provider**；`epk.crv` 非 P-256 直接拒绝（防曲线降级）。
- **服务端密钥**：`keys[].type: EC`，私钥 PKCS#8、公钥 SPKI（Base64）。启动期 fail-fast：曲线必须是 P-256，且公私钥必须成对（用一次"自协商"验证：`ECDH(临时私钥, 配置公钥) == ECDH(配置私钥, 临时公钥)`）。JWKS 输出 `kty=EC, crv=P-256, x, y, alg=ECDH-ES, use=enc`。
- **白名单联动**：存在 EC 密钥时 `allowed-algs` 默认加 `ECDH-ES`；`enc` 走 AES-GCM 家族（与 RSA 共用 `JceCipherSuite` 的 AEAD 实现）。
- **SPI**：`CipherSuite` 新增带 protected header 的解封重载 `unwrapCek(keys, kid, alg, encryptedKey, header)`（默认实现委托旧四参重载，RSA/SM2 不受影响）；`JweCodec` 统一调用带 header 的入口，`encrypted_key` 为 `null`/空段时统一按 0 长度字节交给套件裁定。
- **客户端**：两份 front 参考实现均已支持（WebCrypto `ECDH` + 手写 Concat KDF），`enc` 以服务端 `allowed-encs` 为准（不再写死 A256GCM）。
- **互通性证据**：core 单测用 nimbus `ECDHEncrypter`（独立实现）当 oracle 双向验证；真实 E2E（2026-10-18 时点）：web-example 11/11、gateway-example 10/10（test.js 后扩至八组，见仓库 front/test.js 头注释）。

## 4. 模块与 API 变更

### 4.1 保留的骨架（不动）

`encryptor-dependencies`（BOM）→ `encryptor-core`（无 Spring）→ `encryptor-spring-boot-starter`(servlet 通用) / `encryptor-spring-boot-starter-reactive` → `encryptor-web-spring-boot-starter` / `encryptor-gateway-spring-boot-starter` → `encryptor-examples`。依赖方向不变、无环、core 不引 Spring（例外仍只有可选 redis）。

### 4.2 core：删掉自研密码学，换成 JWE 编解码 + 现代算法

**新增**
- `core/jose/JweCodec`（或等价命名）：`JweRequest decrypt(...)` / `String encryptToJwe(...)`；内部用 Nimbus JOSE+JWT（`JWEObject` + `DirectEncrypter`/`RSAEncrypter`/`RSADecrypter` + `A256GCM`）。
- `core/jose/ContextAad`：AAD 规范化（`uri|method|direction|ts|nonce`，分隔符 + 长度前缀，避免边界平移）。
- `core/keys/ServerKeyStore`：`kid → 密钥对（已解析 `PrivateKey`/`PublicKey`）`；提供 `kid` 清单、指纹、`Cipher` 的 `ThreadLocal` 工厂，**不共享单实例**。
- `core/CheckerStrategy` 扩展：新增带"协商元数据"的默认重载（`kid`/`alg`/`enc`/`ts`/`nonce`），老签名保持 `default` 委派 ⇒ 算法白名单与重放校验都可作为 checker 实现（今天看不到 params，做不了白名单）。
- `core/audit/EncryptorListener`（no-op 默认）：`onDecryptSuccess/onDecryptFailure/onEncryptSuccess/onEncryptFailure`（2026-10-24 起含加密成功回调），携带上下文与耗时 ⇒ 指标/审计 0 行 starter 改动即可接入。
- 默认注册 `InMemoryNonceChecker`（`@ConditionalOnMissingBean` + 属性开关，默认开；关闭时 `logger.warn`）。

**删除**（连同其测试；这些是自研密码学的载体）
- `pojo/EncryptorDataWrapper`（5 字段信封）→ 由 `{"jwe": ...}` + JWE 保护头取代。
- `kit/EncryptorKit` 的"nonce 生成 + `getBytes(nonce+timestamp+data)` + 先解密再比较"编排 → 由 GCM tag 校验取代。
- `strategy/signer/**`：`DigestWithEncryptSigner`（`AES_K(MD5hex)`）、`HtlSigner`、`HtlDigester`、`ISignerStrategy`/`SignerStrategy`（无签名概念了）。
- `signature`/`digest` 相关 config 字段与前端 `md5withaes.signature.js`。
- `GroupEncryptor`（明文/密文分片，无生产调用，与 JWE 单一密文冲突）、`HexEncoder`（未被使用）。
- `WebContext.resEncryptor` / `isResEncryptor()` / `setResEncryptor()`（无调用者、语义误导）。
- `CoreEncryptorConstant.KEY="x-key"` 这个"伪 HTTP 头名"槽位 → 用 Carrier 自己的请求属性名。

**保留但改位置/签名**
- `StrKit` 改为 `Pattern` 预编译缓存（`ConcurrentHashMap<String,Pattern>` + 配置变更失效）。
- `FormMessageConverter.parseForm` 与 web 的两份重复实现合并到 core 工具类。
- `EncryptorFacade`/`EncryptorKit` 依赖**接口**（`IEncryptorStrategy` 等）而非具体组合类（DIP）。
- 默认算法栈从两个自动装配的 lambda 下沉到 core 的 `DefaultProtocol`（纯 Java，无 Spring），两个自动装配只 `new` 它 ⇒ 消掉两侧逐字重复。
- facade/密钥选择逻辑抽 `FacadeResolver`（core，含 `invalidate()`），两侧 filter 只负责"取 uri → 问 resolver → 存上下文"。

### 4.3 web / gateway：过滤器职责简化

- 请求侧：`EncryptorRequestFilter`（包装请求，把 `jwe` 解成明文参数/body）；响应侧：`EncryptorResponseFilter`（把业务响应体封成 `{"jwe":...}`）。
- **响应包装必须先判断"这次请求真的协商到了 CEK 且该方向未被 bypass/skip"再包装**（今天无条件包装 ⇒ 明文请求、SSE、下载全被整段缓冲）。
- 网关：请求/响应两侧的 `MessageReader/MessageWriter` 泛型反射改为**构造期预计算**（`contentType → inClass/outClass` 映射），避免每请求 `ResolvableType`；`max-request-size` 真正生效并兜 `DataBufferLimitException`（→ 413 而非 500）。
- 两侧"请求/响应方向跳过"语义**必须一致**（今天 web 的 `black-req-content-type` 会连带关掉响应加密，网关不会）。

### 4.4 配置（新前缀形态，示例）

```yaml
encryptor:
  config:
    enable: true
    keys:                              # 多钥并存，支持轮换
      - kid: "k2026-10"
        private-key: <base64 PKCS8>
        public-key: <base64 PKCS8/X509>
      - kid: "k2026-07"                # 旧钥保留只解不封
        private-key: <base64 PKCS8>
    active-kid: "k2026-10"             # 推荐客户端使用的 kid（在 JWKS 里以 activeKid 公布）
    allowed-algs: [ "RSA-OAEP-256" ]
    allowed-encs: [ "A256GCM" ]
    ttl: 5m                            # ts 允许窗口
    failure-status: 400
    max-request-size: 1048576
    max-response-size: 4194304
    require-encrypted: true            # 命中范围但未带合法 jwe ⇒ 400（fail-closed）
    discovery:
      enable: true
      path: /.well-known/encryptor-keys   # 隐式免加密，不参与 require-encrypted
      cache-max-age: 5m
    web:
      enable: true
      bypass: { request: false, response: false }
      skip-uris: [ ... ]               # 命中即跳过（旧名 black-uris 仍可绑定，已弃用）
      skip-methods: [ ... ]
      skip-req-content-type: [ ... ]
      skip-res-content-type: [ ... ]
      crypto-config:                   # uri 级覆盖（key 含 . 必须 [key] 括号写法）
        "[^/pay/.*]": { active-kid: "k-pay-2026" }
```

## 5. 示例与前端改造（JS 可行性已核对现有代码）

### 5.1 结论：JS 原生可支持，且比今天更简单

现有前端（`encryptor-examples/*/front/`）是 **Node（CommonJS）脚本**：`node-forge`(PKCS1v15) + `crypto-js`(AES-CBC) + `Math.random()` 自造随机 + `AES_K(MD5)` 签名。

| 能力 | Node | 浏览器 |
| --- | --- | --- |
| RSA-OAEP(SHA-256) 封装 CEK | `crypto.webcrypto.subtle`（Node ≥16；全局 `crypto` ≥19）或 `publicEncrypt({oaepHash:'sha256'})` | `crypto.subtle`（Chrome 37+ / Firefox 34+ / Safari 11+ / Edge 79+） |
| AES-256-GCM | 同上 / `createCipheriv('aes-256-gcm')` | `crypto.subtle` |
| 随机 CEK / IV / nonce | `crypto.getRandomValues` | 同左 |

**硬约束（必须写进 README）**

1. **安全上下文**：`crypto.subtle` 仅在 `https://` 或 `http://localhost` 可用 ⇒ 内网 IP 上的纯 HTTP 页面必须改 HTTPS（127.0.0.1 本地示例不受影响）。
2. **公钥必须是 X.509 SubjectPublicKeyInfo（SPKI）**base64/PEM——现有前端用的就是这种，可直接 `importKey('spki', …, {name:'RSA-OAEP', hash:'SHA-256'})`；服务端配置与发布接口**不得**给 PKCS#1 裸 `RSAPublicKey`。
3. **今天的协议在浏览器上根本做不了**：WebCrypto 不支持 RSAES-PKCS1-v1_5 **加密**（仅签名）⇒ 又一个"配方过时"的证据。
4. `crypto.subtle` 是**异步**的 ⇒ 前端调用点变 async（axios 拦截器内无碍）。
5. 算法面被 WebCrypto 钉在我们的选择上是对的：`RSA-OAEP-256` + `A256GCM` 零依赖可实现；将来 `ECDH-ES` 亦可（浏览器支持 ECDH P-256）。

**改动**：删 `md5withaes.signature.js`；`random.js`（`Math.random()`）弃用改 CSPRNG（**修 S14**：今天连 CEK 都是弱随机、且每进程只生成一次并全请求复用）；`aes.js`/`rsa.js` 合并为 `jwe.js`（约 40 行：b64url 头、封装 CEK、AES-GCM 加解密并切出 16 字节 `tag`）；`crypto-js`、`node-forge` 两个依赖可全部移除。也可改用 `jose`（Node/浏览器通用）替代手写——留给 builder。**每请求新 CEK/IV/nonce。**

### 5.2 与密钥轮换的关系（即"客户端怎么拿公钥"一题的输入）

浏览器端**无法按需重发**（用户不刷新就没有新 JS）⇒ 若把公钥/`kid` 钉死在 JS 里，轮换必须发前端版本。要让轮换不停机，客户端需能发现当前 `kid`/公钥——这正是 JWKS / `.well-known` 端点的用途（带 `kid`、短缓存、多钥并存）。**这是"要不要 discovery 端点"的最强论据。**

### 5.3 其余
- 两个 `HttpTest`：改为构造/校验 JWE（不再拼 5 字段），断言保持"200 + 解出明文含预期内容"。
- 两个示例的 `application.yml` 换成 §4.4 的新形态（含 `kid`、`allowed-*`、`bypass`）。
- 示例的"普通下游"约束不变（网关下游不得引入 encryptor），文档继续写明。

## 6. 验证计划（TDD：每个行为先红后绿）

1. **协议互操作**：JS 侧生成 → Java 侧解；Java 侧生成 → JS 侧解（示例 e2e）。
2. **篡改必须失败**：改 `ciphertext`/`iv`/`tag`/`protected header` 任一字节 ⇒ 400（今天"改 key 不会被判为篡改"，新设计里 AAD 含 `kid`/`ts`/`nonce` ⇒ 必须失败）。
3. **AAD 绑定**：同一密文换 `uri`/`method`/`direction` ⇒ 失败（跨接口重放、请求密文当响应）。
4. **算法降级被拒**：`alg=PKCS1`/`enc=A128CBC-HS256`/未知 `kid`/头缺失 ⇒ 400，且**不**进入业务链。
5. **重放**：同 `nonce` 第二次 ⇒ 400；`ts` 超窗 ⇒ 400；窗口内 ⇒ 通过。
6. **密钥轮换**：旧 `kid` 仍可解、新 `active-kid` 可解；未知 `kid` 拒绝。
7. **上限**：请求超 `max-request-size` ⇒ 413（两侧都测）；响应超 `max-response-size` ⇒ 500 + 日志；SSE/下载 content-type ⇒ 完全不包装、可流式。
8. **旁路**：`bypass.request=true` 后**不重启**明文请求即可通过；`bypass.response=true` 后响应为明文；`x-skip-encryptor` 仍按老规则工作且有告警。
9. **可观测**：失败必有一条 `logger.warn`（含 `uri`/分类/traceId）；指标计数正确。
10. **并发/性能**（JMH，新模块 `encryptor-bench`，不随发布）：① RSA 段多线程吞吐**随核数增长**（守住"单锁串行"不复发）；② `bytes/op` 不超基线 +10%（硬件无关，可进 CI）；③ e2e 基准记录 P50/P99。
11. **攻击用例（安全回归）**：把今天 `ClientAuthAuditTest` 的 S1/S3 断言**改写**为"新协议下同样只持公钥者**能**发请求（因为仍然不做认证），但**不能**篡改、不能跨接口、不能重放"——即把"非目标"与"目标"分别钉死。
12. **失败面统一**：所有失败路径（含 `DataBufferLimitException`）都收敛为 `failure-status` + traceId，不出现 500 泄漏原因。

## 7. 迁移与废弃

- **无 v1 兼容**（用户决定）：旧报文（5 字段）在新版本里被当作"非法报文" → `failure-status`。README 与 `AGENTS.md` 必须写明这一点与升级方式（前后端同批发布）。
- 旧配置项 `crypto-config.*.{private-key,public-key,algorithm,encryptor-factory,signature,...}` 一并替换为 §4.4；`encryptor-dependencies` 的 BOM 里加上 `nimbus-jose-jwt`，`bcpkix-jdk18on` 保留（国密用例仍需要它）。
- 文档同步：`README.md`（特性 + non-goal + 新配置样例）、`AGENTS.md`（双写清单、已知问题）、`docs/architecture/*`（把 P1-2/P1-6/S1–S17 中"新协议已消除/仍未消除"逐条标注）。

## 8. 我的决定（my call，可被否决）+ 留给 builder 的空白

**我的决定**
1. 引入 `com.nimbusds:nimbus-jose-jwt`（不手拼 JWE 形状）。理由：目标是"标准做法"，且它能直接给出 `kid`/`alg`/`enc`/tag 的正确实现。
2. 响应 `alg=dir` 复用请求 CEK（客户端不需要密钥对）。代价：无 PFS、双向不独立（记为可接受）。
3. 载体 = 单个 `jwe` 字段（query/JSON/form），取代 5 字段信封。
4. `nonce` 由客户端生成、放保护头（服务端不参与下发，保持无状态）。
5. 默认 `max-response-size=4MiB`、`ttl=5m`。
6. 不做客户端侧 SDK（只在示例里给 JS）。

**留给 builder 的空白（实现细节，不必回头问我）**
- `jose` 库在前端的选型（`jose` vs `node-jose`）与打包方式。
- 包/类命名细节、Spring 条件注解的具体写法、`@ConfigurationProperties` 的分组方式。
- JMH 基准的具体参数与阈值实现方式。
- 指标命名与 Micrometer 接入方式（是否做成 optional 依赖）。

**已由用户确认的（原"需要确认"，现已定）**
- ✅ 采用 `com.nimbusds:nimbus-jose-jwt` 作为新依赖（决定 1）。
- ✅ 接受"响应复用请求 CEK、无 PFS、双向不独立"（决定 2）。
- ✅ **放弃 v1 兼容**、前后端同批升级（§7）。
- ✅ **密钥发现 = 方案 A**（JWKS 只读端点，见 §3.8）。
- ✅ 范围口径：**加解密（机密性）+ 防篡改（完整性）是本项目承诺**；**防伪造（身份认证）不是**（交 TLS + Spring Security）。
- ✅ 命中范围但无合法 `jwe` ⇒ **fail-closed 400**（`require-encrypted=true`）；`x-skip-encryptor` 维持现状（`skip-able` 默认 `false`，header 直接忽略，开启时启动告警 + README 写明必须内网部署）。
- ✅ 前端 `crypto.subtle` 要求安全上下文 ⇒ 部署需 HTTPS 或 localhost（§5.1）。

**仍未定（用户可直接指定或交由我在计划阶段拍）**：无。
