# encryptor-core

> 与框架无关的加解密内核：定义全部策略接口（SPI）与默认实现，**不依赖 Spring**。

| 项 | 值 |
| --- | --- |
| 目录 | `encryptor-core/` |
| artifactId | `encryptor-core`（`jar`） |
| 父 | `encryptor-parent`（根目录 `pom.xml`） |
| 包名 | `io.github.cuukenn.encryptor` |
| 依赖 | `cn.hutool:hutool-all`、`org.bouncycastle:bcpkix-jdk18on`、`spring-boot-starter-data-redis`(optional)、`logback-classic`(optional)、`junit-jupiter-engine`(test) |
| 测试 | `src/test/java/io/github/cuukenn/encryptor/lectotype/`（`EncryptorStrategyTest`、`EncoderStrategyTest`、`SignerStrategyTest`） |

## 职责

- 定义"可替换点"：加密算法、编码算法、签名算法、摘要算法、校验策略。
- 提供默认实现（全部包在 hutool 之上）。
- 提供与传输无关的报文模型 `EncryptorDataWrapper` 和编排工具 `EncryptorKit`。
- **不出现任何 Spring 注解**——所有装配在 `encryptor-spring-boot-starter*` 里做。

## 包结构

| 包 | 内容 |
| --- | --- |
| `core/` | 策略接口 |
| `core/encryptor/` | 加解密实现 |
| `core/encoder/` | 编码实现 + 加密/签名与编码的组合器 |
| `core/signer/` | 签名实现 |
| `core/digester/` | 摘要实现 |
| `core/checker/` | 校验实现（nonce 防重放） |
| `facade/` | `EncryptorFacade`、`IEncryptorFacadeFactory` |
| `kit/` | `EncryptorKit`（流程编排）、`StrKit`（正则匹配） |
| `pojo/` | `EncryptorDataWrapper`（传输报文） |
| `constant/` | `CoreEncryptorConstant.KEY = "x-key"` |
| `exception/` | `EncryptorException extends RuntimeException` |

## 策略接口（扩展点）

| 接口 | 文件 | 方法 | 泛型含义 |
| --- | --- | --- | --- |
| `IEncryptorStrategy<I, O>` | `core/IEncryptorStrategy.java` | `O encrypt(I)` / `I decrypt(O)` | 最底层加解密 |
| `EncryptorStrategy` | `core/EncryptorStrategy.java` | 继承 `IEncryptorStrategy<byte[], byte[]>` | 原始字节加解密 |
| `IEncoderStrategy<T>` | `core/IEncoderStrategy.java` | `T encode(byte[])` / `byte[] decode(T)` | 编码 |
| `EncoderStrategy` | `core/EncoderStrategy.java` | 继承 `IEncoderStrategy<byte[]>` | 字节编解码 |
| `ISignerStrategy<S, D>` | `core/ISignerStrategy.java` | `S sign(byte[])` / `boolean verify(S, byte[])` | 签名 |
| `SignerStrategy` | `core/SignerStrategy.java` | 继承 `ISignerStrategy<byte[], byte[]>` | 原始字节签名 |
| `IDigesterStrategy<T>` | `core/IDigesterStrategy.java` | `T digest(byte[])` | 摘要 |
| `DigesterStrategy` | `core/DigesterStrategy.java` | 继承 `IDigesterStrategy<byte[], byte[]>` | 字节摘要 |
| `CheckerStrategy` | `core/CheckerStrategy.java` | `void check(EncryptorDataWrapper)` | 报文校验；抛 `EncryptorException` 即拒绝 |

> `EncryptorStrategy`/`SignerStrategy`/`EncoderStrategy`/`DigesterStrategy` 是为了简化泛型而存在的"原始类型"子接口，新增算法实现它们即可。

## 默认实现

| 类 | 文件 | 作用 |
| --- | --- | --- |
| `HtlSymmetricCryptoEncryptor` | `core/encryptor/` | 包裹 hutool `SymmetricCrypto`（如 `AES`），用于**数据体**加解密 |
| `HtlASymmetricCryptoEncryptor` | `core/encryptor/` | 包裹 hutool `AbstractAsymmetricCrypto<?>`（如 `RSA`）；**加密用公钥、解密用私钥** |
| `GroupEncryptor` | `core/encryptor/` | 分段加解密，`groupSplit` 默认 `"."`；**2026-10-16 已实现**（按 `groupSize` 切片，`decrypt` 用 `Pattern.quote(groupSplit)` 切分；未验证） |
| `EncryptorEncoder` | `core/encoder/` | 组合 `EncryptorStrategy` + `EncoderStrategy`，实现 `IEncryptorStrategy<byte[], String>` |
| `SignerEncoder` | `core/encoder/` | 组合 `SignerStrategy` + `EncoderStrategy`，实现 `ISignerStrategy<String, byte[]>` |
| `Base64Encoder` | `core/encoder/` | Base64 编解码（当前默认使用） |
| `HexEncoder` | `core/encoder/` | Hex 编解码 |
| `DigestWithEncryptSigner` | `core/signer/` | 摘要 + 非对称加密的签名方案（当前默认使用） |
| `HtlSigner` | `core/signer/` | 包裹 hutool `Sign`（标准非对称签名） |
| `HtlDigester` | `core/digester/` | 包裹 hutool `Digester`（如 `MD5`）；⚠️ 返回的是 **hex 字符串的 bytes**，不是 digest 原始字节 |
| `InMemoryNonceChecker` | `core/checker/` | 内存版 nonce 防重放，构造参数 `(容量, Duration 有效期)`；2026-10-16 起用 `ConcurrentHashMap` + 原子 `compute`（原 Hutool LRU 非线程安全），无新依赖 |
| `InRedisNonceChecker` | `core/checker/` | Redis 版防重放（依赖 optional 的 `spring-boot-starter-data-redis`） |

## 门面与报文

`facade/EncryptorFacade`：一次加解密所需的三件套 + 校验器。

```java
public EncryptorFacade(EncryptorEncoder negotiateEncoder,        // 协商密钥加密器（RSA）
                      Function<String, EncryptorEncoder> encryptorEncoder,  // 参数 -> 数据加密器（AES）
                      Function<String, SignerEncoder> signerEncoder,        // 参数 -> 签名器
                      List<CheckerStrategy> checkerStrategies)
```

- `encrypt(byte[] data, String key)`：先用 `negotiateEncoder` 解 `key` 得到参数，再用参数选数据加密器与签名器。
- `decrypt(EncryptorDataWrapper data)`：同上，先校验再解密。

`facade/IEncryptorFacadeFactory<T>`：`EncryptorFacade apply(T config)`。**这是"换整套算法组合"的注册点**——starter 里注册 bean，名字由配置 `encryptor.config.crypto-config.encryptor-factory` 指定。

`pojo/EncryptorDataWrapper`：线上报文，字段 `nonce`、`timestamp`、`signature`、`key`、`data`。

- `key`：**用协商密钥（RSA 私钥）解密后得到的参数 JSON 的密文**，参数内容形如 `{"mode":..., "padding":..., "key":..., "iv":...}`，用于现场构造 AES。
- `data`：业务数据经数据加密器加密 + 编码后的字符串。
- `signature`：对 `(nonce + timestamp + data)` 的 **UTF-8 字节**签名后再编码。

## 流程（`kit/EncryptorKit`）

```text
加密 encrypt(encryptorEncoder, signerEncoder, data, key):
    encryptData = encryptorEncoder.encrypt(data)
    nonce       = UUID(无横线)
    timestamp   = System.currentTimeMillis()
    sign        = signerEncoder.sign((nonce + timestamp + encryptData).getBytes(StandardCharsets.UTF_8))
    -> new EncryptorDataWrapper(nonce, timestamp, sign, key, encryptData)

解密 decrypt(encryptorEncoder, signerEncoder, checkers, wrapper):
    1. 依次执行所有 CheckerStrategy.check(wrapper)     // 失败抛 EncryptorException
    2. signerEncoder.verify(signature, (nonce + timestamp + data).getBytes(StandardCharsets.UTF_8))
       失败抛 EncryptorException("sig check error")
    3. encryptorEncoder.decrypt(data)
```

## 扩展点：新增一种加密/编码/签名/摘要算法

1. 在对应子包新增实现（例如 `core/encryptor/MyEncryptor.java implements EncryptorStrategy`），或者直接复用 hutool 实现。
2. **不要**在这里加 Spring 注解。
3. 到 `encryptor-spring-boot-starter` 与 `encryptor-spring-boot-starter-reactive` 的 `encryptorFacadeFactory(...)` 里把它接进 `EncryptorFacade`（两边是**两份逐行几乎相同的代码**，见下）。
4. 或在业务侧实现自己的 `IEncryptorFacadeFactory<T>` 并注册为 bean，用配置 `encryptor.config.crypto-config.encryptor-factory=<bean 名>` 切换。

> 如果新算法改动了参数 JSON 的字段契约（不再用 `mode`/`padding`/`key`/`iv`），那是一次**协议变更**：还要同步两套前端 Demo（`encryptor-examples/*/front/encryptor/*.js`）和两个端到端脚本（`encryptor-examples/web-example/.../HttpTest.java`、`encryptor-examples/gateway-example/gateway/.../HttpTest.java`，它们也硬编码了 mode/padding）。

## 改动影响面

`encryptor-core` 被 **所有** starter 依赖。改这里的方法签名 = 同时改 servlet 与 reactive 两套装配，再改示例。

- `EncryptorKit` 的签名/校验输入顺序变了 → 前端 `front/encryptor/*.js` 也必须同步（协议变更）。
- `EncryptorDataWrapper` 字段变了 → 前端、web converter、gateway converter 三处都要同步。
- `StrKit.anyMatch` 用的是**正则**匹配（`ReUtil.isMatch`），白名单配置写的是正则不是通配符。

## 已知问题（改动前先确认）

- `GroupEncryptor.encrypt/decrypt` 曾是未完成的实现（直接返回 `null`），2026-10-16 已补全（**未经 `mvn` 验证**）。
- 协议路径上的字符集已全部显式化为 `StandardCharsets.UTF_8`（`EncryptorKit` 签名输入、`EncryptorFacade` 参数 JSON、两个自动装配类的 `iv`）。
- `HtlDigester.digest` 返回 hex 文本的字节，长度是摘要长度的两倍。
