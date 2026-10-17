# encryptor-starter-reactive（artifactId: `encryptor-spring-boot-starter-reactive`）

> ⚠️ **本文是 v1 协议时代的架构记录（2026-10-16）；v2 JWE 协议重做（2026-10-17）后大部分内容已失效。**
> 当前事实以源码为准：入口 `AGENTS.md`，协议定义 `docs/superpowers/specs/2026-10-16-payload-security-protocol-design.md`，v1→v2 处置见 `open-issues.md`/`security-review.md` 顶部状态表。


> **reactive 侧**的 Spring Boot 通用装配。结构与 `encryptor-starter` 一一对应，只是包名和 bean 名不同——**这是一份被复制的代码**。

| 项 | 值 |
| --- | --- |
| 目录 | `encryptor-starters/encryptor-starter-reactive/` |
| artifactId | `encryptor-spring-boot-starter-reactive`（`jar`） |
| 包名 | `io.github.cuukenn.encryptor.reactive` |
| 依赖 | `encryptor-core`、`spring-boot-starter`、`spring-boot-configuration-processor`(optional) |
| 自动装配入口 | `spring.factories` → `io.github.cuukenn.encryptor.reactive.configuration.EncryptorReactiveAutoConfiguration` |

## 职责

与 `encryptor-starter` 相同：声明 `encryptor.config.*` 配置、注册门面工厂 bean。被 `encryptor-gateway-spring-boot-starter` 依赖。

## 关键类

| 类 | 文件 | 对应 servlet 侧 |
| --- | --- | --- |
| `EncryptorReactiveAutoConfiguration` | `reactive/configuration/` | `EncryptorAutoConfiguration` |
| `EncryptorConfig` | `reactive/config/` | `config/EncryptorConfig` |
| `CryptoConfig` | `reactive/config/` | `config/CryptoConfig` |
| `EncryptorConstant` | `reactive/constant/` | `constant/EncryptorConstant`（bean 名不同） |

## 与 servlet 侧的差异（只有这三处）

1. **配置前缀多一层**：`EncryptorConfig.PREFIX = "encryptor.config.reactive"`（servlet 侧是 `"encryptor.config"`）。所以 reactive 应用的配置写在 **`encryptor.config.reactive.*`**，而 `GatewayEncryptorConfig` 因为这个前缀变成 **`encryptor.config.reactive.gateway.*`**。
2. bean 名：`reactive-default-encryptor-factory`（servlet 侧是 `default-encryptor-factory`）。
   - 因此两套 starter 同时存在于一个应用时**不会冲突**。
3. AES 密钥取值：reactive 用 `obj.getBytes("key")`，servlet 用 `encoder.decode(obj.getStr("key"))`（即 reactive 侧少了一次 Base64 解码）。改动 `key` 字段含义时要意识到这个不对称。
   - 2026-10-16 只把字符集显式化为 `obj.getStr("key").getBytes(StandardCharsets.UTF_8)`——对 Base64/ASCII 字符串**字节完全相同**，所以这个不对称**仍然存在**（见 `open-issues.md` 的 P0-2）。

其余（RSA 协商、`DigestWithEncryptSigner` + `HtlDigester(new MD5())`、`Base64Encoder`、参数 JSON 的 `mode/padding/key/iv`）完全一致。

## ⚠️ 双写警告

以下三对文件是**逐行重复**的，改任何一边都必须同步另一边：

| servlet 侧 | reactive 侧 |
| --- | --- |
| `encryptor-starter/.../config/CryptoConfig.java` | `encryptor-starter-reactive/.../reactive/config/CryptoConfig.java` |
| `encryptor-starter/.../config/EncryptorConfig.java` | `encryptor-starter-reactive/.../reactive/config/EncryptorConfig.java` |
| `encryptor-starter/.../constant/EncryptorConstant.java` | `encryptor-starter-reactive/.../reactive/constant/EncryptorConstant.java` |

（`CryptoConfig` 两边连注释和默认值都一样；`EncryptorConfig` 只差 `PREFIX` 常量——servlet 是 `encryptor.config`，reactive 是 `encryptor.config.reactive`。）

## 坑

- 只改了一边是这类项目最常见的回归来源：servlet 应用正常、网关莫名失败（或反之）。
- `EncryptorReactiveAutoConfiguration` 里的 logger 名字是 `EncryptorReactiveAutoConfiguration`，但 gateway 侧的 `GatewayEncryptorConfiguration` 误用了**这个类名**做 logger（见 `encryptor-gateway-starter`），排查日志时别被误导。
