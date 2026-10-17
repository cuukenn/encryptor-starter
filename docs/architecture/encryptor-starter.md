# encryptor-starter（artifactId: `encryptor-spring-boot-starter`）

> ⚠️ **本文是 v1 协议时代的架构记录（2026-10-16）；v2 JWE 协议重做（2026-10-17）后大部分内容已失效。**
> 当前事实以源码为准：入口 `AGENTS.md`，协议定义 `docs/superpowers/specs/2026-10-16-payload-security-protocol-design.md`，v1→v2 处置见 `open-issues.md`/`security-review.md` 顶部状态表。


> **servlet 侧**的 Spring Boot 通用装配：注册"默认门面工厂"，并声明 `encryptor.config.*` 配置属性。不含任何 Filter、不感知 HTTP。

| 项 | 值 |
| --- | --- |
| 目录 | `encryptor-starters/encryptor-starter/` |
| artifactId | `encryptor-spring-boot-starter`（`jar`） |
| 包名 | `io.github.cuukenn.encryptor`（与 core 同名不同类：`config` / `configuration` / `constant`） |
| 依赖 | `encryptor-core`、`spring-boot-starter`、`spring-boot-configuration-processor`(optional) |
| 自动装配入口 | `src/main/resources/META-INF/spring.factories` → `io.github.cuukenn.encryptor.configuration.EncryptorAutoConfiguration` |

## 职责

1. 声明全局加密配置 `EncryptorConfig`（前缀 `encryptor.config`）。
2. 注册 bean `default-encryptor-factory`：把 core 里的策略类拼成一个可用的 `EncryptorFacade`。
3. 提供 `EncryptorConstant.DEFAULT_ENCRYPTOR_FACTORY = "default-encryptor-factory"`。

## 关键类

| 类 | 文件 | 作用 |
| --- | --- | --- |
| `EncryptorAutoConfiguration` | `configuration/EncryptorAutoConfiguration.java` | 自动装配；唯一的 `@Bean` 是门面工厂 |
| `EncryptorConfig` | `config/EncryptorConfig.java` | `@ConfigurationProperties(prefix = EncryptorConfig.PREFIX)`，`PREFIX = "encryptor.config"`；内嵌 `CryptoConfig cryptoConfig` |
| `CryptoConfig` | `config/CryptoConfig.java` | `privateKey`、`publicKey`、`algorithm`(默认 `RSA/ECB/PKCS1Padding`)、`encryptorFactory`(默认 `default-encryptor-factory`)；`getOrDefaultFill(default, override)` 做逐字段兜底 |
| `EncryptorConstant` | `constant/EncryptorConstant.java` | 默认门面工厂的 bean 名 |

## 装配做了什么

```
@EnableConfigurationProperties(EncryptorConfig.class)
@ConditionalOnProperty(prefix = "encryptor.config", name = "enable", havingValue = "true", matchIfMissing = true)
@Configuration(proxyBeanMethods = false)
EncryptorAutoConfiguration
└── @Bean(DEFAULT_ENCRYPTOR_FACTORY)
    IEncryptorFacadeFactory<CryptoConfig> encryptorFacadeFactory(List<CheckerStrategy> checkerStrategies)
```

工厂内部固定构造这一套（**硬编码，配置改不了**）：

| 角色 | 实现 |
| --- | --- |
| 协商密钥加密器 `negotiateEncoder` | `EncryptorEncoder(HtlASymmetricCryptoEncryptor(new RSA(algorithm, privateKey, publicKey)), Base64Encoder)` |
| 数据加密器 | 由 `key` 解出的参数 JSON 现场构造：`HtlSymmetricCryptoEncryptor(new AES(mode, padding, key, iv))`，外层 `EncryptorEncoder(..., Base64Encoder)` |
| 签名器 | `SignerEncoder(DigestWithEncryptSigner(HtlDigester(new MD5()), 同一套 AES), Base64Encoder)` |
| 校验器 | 注入的 `List<CheckerStrategy>`（由业务方注册 bean，例如示例里的 `InMemoryNonceChecker`） |

参数 JSON 字段：`mode`、`padding`、`key`、`iv`（`iv` 可缺省）。

## 配置示例

```yaml
encryptor:
  enable: true                # 关闭后整个 EncryptorAutoConfiguration 不生效
  config:
    crypto-config:
      private-key: <RSA 私钥 Base64>
      public-key: <RSA 公钥 Base64>
      algorithm: RSA/ECB/PKCS1Padding      # 默认值
      encryptor-factory: default-encryptor-factory   # 默认值；换成自定义 bean 名即可整体换算法组合
```

## 扩展点

- **整体换算法组合**：实现 `IEncryptorFacadeFactory<CryptoConfig>` 并注册为 bean，然后把 `encryptor.config.crypto-config.encryptor-factory` 设成该 bean 名。
- **加校验**：注册任意数量的 `CheckerStrategy` bean，会自动注入门面（示例：`WebApplication` 里注册 `InMemoryNonceChecker`）。
- **改默认算法组合**：改本模块的 `encryptorFacadeFactory(...)` 方法体。

## 改动影响面

- 本模块是 `encryptor-web-spring-boot-starter` 的父依赖，**改 bean 名或方法签名会同时影响 web 与 gateway 两套装配**（gateway 走的是 reactive 版，但链路结构一致）。
- 改 `CryptoConfig` 字段 → 同步 `encryptor-starter-reactive/config/CryptoConfig.java`（逐行重复）→ 再看 `README.md` 的配置说明。

## 坑

- 只有 `enable=true` 且 `matchIfMissing=true`（即默认开）时本自动装配才生效；排查"没加密"先看 `encryptor.enable`。
- `spring.factories` 是 Boot 2.4 的写法。工程整体升级 Spring Boot 2.7+ 时必须迁移到 `META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports`。
- `CryptoConfig.getOrDefaultFill` 的语义是"某个字段为空才用默认"，不是整体替换；uri 级覆盖配置依赖它。
