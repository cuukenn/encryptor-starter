# encryptor-core 深潜（零 Spring / 零 BouncyCastle / 零 metrics）

JWE 编解码、密钥库、防重放、协议栈与三个"单点"抽象（CarrierKit / SkipListsConfigBase / RouteRule）。协议面硬性限定全在本文件。

## 目录地图

| 子域 | 位置 |
| --- | --- |
| JWE 编解码 / crit / typ / sanitize | `jose/JweCodec.java` |
| AAD 与路径规范化 | `jose/ContextAad.java`（`canonicalPath`：折叠 `..`/`//`/`%2E%2E` → 解码 → 再折叠） |
| 算法套件 SPI | `jose/CipherSuite.java`（4 参抽象 → 5/6 参 default 链；`pairsWith` 默认 true） |
| 内置套件 | `jose/JceCipherSuite.java`（RSA-OAEP-256 + AES-GCM）、`jose/EcCipherSuite.java`（ECDH-ES） |
| KDF | `jose/ConcatKdf.java`（OtherInfo = enc ‖ apu ‖ apv ‖ keydatalen） |
| 防重放 | `jose/ReplayGuard.java` + `jose/InMemoryNonceStore.java`（分片锁 + 摊还驱逐） |
| 协议栈组装 | `protocol/DefaultProtocol.java`（Builder：密钥→白名单联动 + fail-fast）+ `protocol/ProtocolAssembler.java` |
| 运行期开关 | `runtime/EncryptorRuntime.java`（volatile 快照整包换面 + 失效器异常隔离） |
| 载体编解码单点 | `kit/CarrierKit.java` |
| skip 机制单点 | `config/base/SkipListsConfigBase.java` |
| per-route 单点 | `config/base/RouteRule.java`（`effectiveKids` 合并查找） |
| 通用配置模型 | `config/base/EncryptorConfigBase.java`（两侧 `EncryptorConfig` 只留 PREFIX，三件套同） |
| 工具 | `kit/StrKit.java`（正则缓存有上限；`mediaType` 剥 `;` 参数）、`kit/DigestKit.java`、`audit/`（`EncryptorListener` 全 default + Composite） |

## 协议面硬性限定

1. ECDH-ES：`encrypted_key` 段**为空**（compact 形如 `header..iv.ct.tag`）；`epk` 属 protected header **参与 AAD**（改 epk 解析口径 = 改 AAD，会全量 AAD_MISMATCH）；只支持 **P-256**（`epk.crv` 不符一律拒）；`apu`/`apv` 存在时必须进 Concat-KDF OtherInfo；共享秘密 Z 左补零 32 字节再派生（个别 JCE Provider 剥前导零）。
2. AAD 的 uri 输入口径**两侧有意不同**：servlet 用原始 `requestURI`（兼容百分号编码路径的客户端），网关用 `canonicalPath` 折叠形（防 `..`/`//` 白名单绕过）——改任一侧前确认这个差异是有意的。
3. `ReplayGuard.verify` 必须在 AEAD tag 校验**之后**（未认证输入不得污染 nonce 存储）；`InMemoryNonceStore` retention ≥ 2·ttl 构造期强制。
4. `JweContext.destroy()` 后 `cek()/plaintext()` 抛 `IllegalStateException`（全零是合法 AES 密钥，不得静默返回）；5 参 `encryptResponse`（按 CEK 长度猜 enc）在装配套件含非 AES-GCM enc 时拒绝。
5. 演进通道唯一：additive claim + 服务端软接受；`crit` 一律 fail-closed；`typ` 软锚点（`JweCodec.PROTOCOL_TYPE="encryptor+jwe"`，未知值记 INFO 不拒绝）——设计文档 §3.11 是契约。
6. `Cipher` 非线程安全：每次新建；KDF 型套件必须覆写 `pairsWith`（交叉组合在解封前拒）。nimbus 坑：`Base64URL` 无 `decode(String)` → `java.util.Base64.getUrlDecoder()`；parse base64url 段用 `JWEHeader.parse(new Base64URL(...))`。
7. 审计不双计：codec 内失败由 `JweCodec` 回调；codec 外失败由两侧过滤器补发。`EncryptorListener` 保持全 default（加回调零破坏的 API 演进范本）。
8. 客户端可控头字段（alg/enc/kid/crit）进日志/异常消息前过 `JweCodec.sanitize`（控制字符与 U+2028/U+2029 → `·`，codePoint 截断）。

## 单点契约（两侧不得写本地实现）

- **CarrierKit**：QUERY/FORM 明文是 form 语义 urlencoded（`+`=空格）且明文即完整 query（jwe 外原始参数被丢弃）；jwe 在 query string 上一律按 QUERY 载体；编解码互逆有单测钉住。
- **SkipListsConfigBase**：skip-* 字段 + black-* alias 合并 + precompile + 不可命中告警（大写 / `;` 参数），`initSkipLists(prefix)` 单点；black/skip 不能共用同一个 list（Spring 就地绑定互清）。
- **RouteRule**：`Map<正则, RouteRule>` 键结构**已固定**（改值类型 = 绑定期硬破坏）；扩展只往里加字段（当前仅 `kids`）；合并查找 `effectiveKids`（跨 crypto-config/routes 两正则空间最长命中、同长并集、无命中不限）。

## 配置模型装配（两侧 AutoConfiguration 衔接）

两侧 `EncryptorAutoConfiguration`/`EncryptorReactiveAutoConfiguration` 近乎同构（CI 结构 parity 守卫盯公共 bean 面）；共享机制一律下沉 `config/base` 继承，两侧只留前缀与模块特有字段。密钥解析失败/白名单不相交/SM2 缺解析器等一律启动期 fail-fast。

## core 自检

- [ ] 没引入 Spring / BC / metrics 依赖；`META-INF/services` 注册新增 SPI。
- [ ] 改了协议（claims/alg/enc/载体）→ `topics/sync-map.md` 全文的同步清单。
- [ ] 新增白名单默认值要联动密钥类型（`DefaultProtocol` 的推导链）。
- [ ] 改完：`mvn -pl encryptor-core install -DskipTests` 后跑 `-Pmain-module`。
