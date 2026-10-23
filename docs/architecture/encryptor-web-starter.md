# encryptor-web-starter（artifactId: `encryptor-web-spring-boot-starter`）

> ⚠️ **本文是 v1 协议时代的架构记录（2026-10-16）；v2 JWE 协议重做（2026-10-17）后大部分内容已失效。**
> 配置名以 README 为准：主名是 `skip-*`，文中出现的 `black-*` 是已弃用 alias（启动 WARN，新旧合并去重）。
> 当前事实以源码为准：入口 `AGENTS.md`，协议定义 `docs/superpowers/specs/2026-10-16-payload-security-protocol-design.md`，v1→v2 处置见 `open-issues.md`/`security-review.md` 顶部状态表。


> **servlet / Spring MVC 侧**的 HTTP 接入层：4 个 Filter + 消息编解码器 + `ThreadLocal` 请求上下文。

| 项 | 值 |
| --- | --- |
| 目录 | `encryptor-starters/encryptor-web-starter/` |
| artifactId | `encryptor-web-spring-boot-starter`（`jar`） |
| 依赖 | `encryptor-spring-boot-starter`、`spring-boot-starter-web`、`spring-boot-configuration-processor`(optional) |
| 包名 | `io.github.cuukenn.encryptor.web` |
| 自动装配入口 | `spring.factories` + `AutoConfiguration.imports`（双注册） → `io.github.cuukenn.encryptor.web.configuration.WebEncryptorConfiguration` |

## 职责

把 HTTP 请求/响应和 core 的 `EncryptorFacade` 接起来：

1. 判断这次请求/响应是否需要加解密（uri / method / contentType 名单）。
2. 从请求里取出 `EncryptorDataWrapper`（可能藏在 **query/form 参数**里，也可能藏在 **body** 里），解密后把明文交回业务。
3. 把响应体加密封装成 `EncryptorDataWrapper` 写回。

## Filter 链（顺序即执行顺序）

| Order | Bean 名 | 类 | 作用 |
| --- | --- | --- | --- |
| `-12` | `defaultWebEncryptorFilter` | `filter/EncryptorWebFilter` | 门面：判名单、选 `CryptoConfig`、把 `EncryptorFacade` 放进 `WebContext` |
| `-11` | `defaultRequestParameterEncryptorFilter` | `filter/EncryptorRequestParameterFilter` | 解密**参数形态**的报文 |
| `-10` | `defaultRequestBodyEncryptorFilter` | `filter/EncryptorRequestBodyFilter` | 解密**请求体形态**的报文 |
| `-3` | `defaultResponseEncryptorFilter` | `filter/EncryptorResponseFilter` | 加密响应体 |

顺序默认值定义在 `config/WebFilterConfig.java`，可用 `encryptor.config.web.filter-config.*-order` 覆盖。每个 bean 都有 `@ConditionalOnMissingBean(name = ...)`，**同名 bean 存在时自动装配让位**——想替换实现就注册同名 bean。

### 每个 Filter 在做什么

- **`EncryptorWebFilter`**：`getRequestURI()` 命中名单 → 直接放行；`method` 命中名单 → 直接放行；否则 `WebContext.setEncryptor(true)`，再看请求 `Content-Type` 是否命中名单决定 `setReqEncryptor(true)`，最后按 uri 选 `CryptoConfig` 并 `setEncryptorFacade(facadeFactory.apply(cryptoConfig))`。
- **`EncryptorRequestParameterFilter`**：把 `request.getParameterMap()` 整体反序列化成 `EncryptorDataWrapper`（即 `nonce/timestamp/signature/key/data` 是**参数名**），解密后得到明文 JSON/表单，包一层 `HttpServletRequestWrapper` 覆盖 `getParameterNames/getParameterValues`，并把 `key` 存进 request attribute `x-key`（`CoreEncryptorConstant.KEY`）。
- **`EncryptorRequestBodyFilter`**：`Content-Type` 选一个 `MessageReader`，`reader.read()` 解密 body，包成新的 `InputStream` 继续走链。
- **`EncryptorResponseFilter`**：用 `ContentCachingResponseWrapper` 拦住响应，`MessageWriter.write()` 加密后 `resetBuffer()` + 写回（`copyBodyToResponse()`）。

## 消息编解码器（SPI）

`converter/` 下两个对称接口（`FormMessageConverter`/`JsonMessageConverter` 实现它们；**2026-10-16 起**由 `WebEncryptorConfiguration` 以 `@Bean + @ConditionalOnMissingBean` 显式注册，不再 `@ComponentScan`）：

| 接口 | 方法 |
| --- | --- |
| `MessageReader` | `boolean canRead(MediaType)` / `RewriteFunction<byte[], byte[]> read()` |
| `MessageWriter` | `boolean canWrite(MediaType)` / `RewriteFunction<byte[], byte[]> write()` |

| 实现 | 覆盖的 contentType |
| --- | --- |
| `JsonMessageConverter` | `application/json`、`application/*+json`、`application/x-ndjson` |
| `FormMessageConverter` | `application/x-www-form-urlencoded` |
| `DefaultMessageConverter` | 兜底（`canRead/canWrite` 恒 `false`，内部委托 `JsonMessageConverter`） |

匹配失败时统一 `orElseGet(DefaultMessageConverter::new)`，所以**兜底行为等价于 JSON**。

`JsonMessageConverter.read()`：body → `EncryptorDataWrapper` → `facade.decrypt(...)`，并把 `key` 存进 `x-key` attribute。
`JsonMessageConverter.write()`：从 `x-key` attribute 取回 `key`，`facade.encrypt(input, key)` → JSON 字符串。**`key` 由请求侧写入、响应侧读取**，这是请求-响应配对的关键。

## 请求上下文

`kit/WebContext`：`ThreadLocal`（`ThreadUtil.createThreadLocal`）持有 `reqEncryptor` / `jweContext` / `carrier` / `bodyPlaintext` / `parameters` / `config` / `protocol`。

- `WebContext.current()` 取当前线程上下文；`WebContext.clear()` 在参数过滤器最外层 `finally` 清理并清零明文/CEK。
- 异步请求：所有过滤器注册为 `asyncSupported`；响应过滤器拦截 `startAsync()`，在 `AsyncListener.onComplete` 中加密响应，`onError` / `onTimeout` 回空 500。异步周期结束前，CEK 的所有权会从 ThreadLocal 转移给监听器，不会被参数过滤器提前销毁。
- ⚠️ **业务自定义线程池仍不会自动传递 `WebContext`**：异步业务代码若需要读取解密参数，必须由调用方显式传递数据，不能依赖 `ThreadLocal`。

## 配置

```yaml
encryptor:
  config:
    web:
      enable: true
      crypto-config:                 # Map<String, CryptoConfig>，key 是 uri 正则（整串匹配）
        "[^/api/.*]": { ... }        # 按 uri 覆盖加密参数 —— 含 `.` 的 key 必须用 [key] 括号写法！
      filter-config:
        encryptor-filter-order: -12
        encryptor-req-params-filter-order: -11
        encryptor-req-body-filter-order: -10
        encryptor-res-filter-order: -3
      black-uris: [ ... ]            # 命中则完全跳过加解密
      black-methods: [ ... ]         # 命中则完全跳过
      black-req-content-type: [ ... ]# 命中则不处理请求
      black-res-content-type: [ ... ]# 命中则不处理响应（**在业务链跑完后判定**，见下方"坑"）
      failure-status: 400            # 报文解不开时返回的状态码（默认 400）
      max-request-size: 1048576      # 请求体上限（字节，<=0 表示不限；超限回 413 且不进业务链）
```

继承 `encryptor.config.crypto-config`（`EncryptorConfig`）作为默认值，uri 级配置通过 `CryptoConfig.getOrDefaultFill(default, override)` 做**逐字段兜底**。

### uri 级 `crypto-config` 的写法（⚠️ 必须用括号）

key 是 **uri 正则**，且是**整串**匹配（等价 `Pattern.matches`，要前缀匹配得自己写 `.*`）。命中时该请求用这里的密钥，未命中的回落到全局 `encryptor.config.crypto-config`。多规则命中时按"最长正则优先、等长按声明顺序"（`StrKit.getBestMatchStr`）。

**key 里只要含 `.`（例如 `.*`），就必须写成 `[key]` 形式** —— 否则 Spring Boot 的 `Map` key 绑定会把 `.` 当分隔符并把 `^`、`/`、`*` 等非法字符**静默剥离**（实测：裸写 `^/test/secret.*` 会被绑成 `testsecret`，不报错、配置形同不存在）。

```yaml
# YAML：外层双引号是 YAML 需要的，方括号是 key 内容的一部分
encryptor:
  config:
    web:
      crypto-config:
        "[^/test/secret.*]":
          private-key: <base64 PKCS8>
          public-key: <base64 X509>
```

```properties
# properties：直接把方括号写进属性名
encryptor.config.web.crypto-config.[^/test/secret.*].private-key=<base64 PKCS8>
encryptor.config.web.crypto-config.[^/test/secret.*].public-key=<base64 X509>
```

可回归的证据：`encryptor-examples/web-example` 的 `CryptoConfigBindingTest`（绑定，CI 可跑）+ `HttpTest#test_get_uri_level_crypto_config`（端到端正向 200）/ `#test_get_uri_level_crypto_config_wrong_key_rejected`（用全局密钥打同端点 → 400）。

## 扩展点

| 想做的事 | 做法 |
| --- | --- |
| 支持新的请求/响应 contentType | 新增 `MessageReader`/`MessageWriter` 实现并注册成 Spring bean（`@Component` 或自己的 `@Bean`；starter 已不再 `@ComponentScan`，见"坑"） |
| 换掉某个 Filter | 注册同名 bean（`defaultWebEncryptorFilter` 等）覆盖 |
| 调整执行顺序 | 改 `encryptor.config.web.filter-config.*-order` |
| 换整套算法组合 | 见 `encryptor-starter.md` 的 `IEncryptorFacadeFactory` |

## 改动影响面

- 本模块与 `encryptor-gateway-starter` 的 `converter/`、`filter/` 是**平行实现**（名字相同、包不同）。改协议（`EncryptorDataWrapper` 的字段、`x-key` attribute 名）必须两边一起改。
- 改 `WebFilterConfig` 的默认顺序 → 会影响所有使用方，慎改。
- 新增 `MessageReader` 实现**只要是个 Spring bean** 就会被注入使用（2026-10-16 起 starter 不再 `@ComponentScan`，改为显式 `@Bean` + `@ConditionalOnMissingBean`，所以你自己的同类型 bean 可以覆盖默认的 `FormMessageConverter`/`JsonMessageConverter`）。注意 `canRead` 的匹配范围不要写太宽。

## 坑

- 🟩（2026-10-16 已修，**经 `mvn` 验证**）**uri 级 `crypto-config` 曾经实际取不到**：`EncryptorWebFilter` 第 49–50 行先算 `bestMatchStr`，却用 `config.getCryptoConfig().get(uri)` 取值——只有当 uri 恰好等于配置 key 时才命中，正则 key 永远拿不到。现已改为 `get(bestMatchStr)`，并配了回归用例 `web/filter/EncryptorWebFilterTest`（gateway 侧同源问题一并在 `EncryptorGatewayFilter.java:48-49` 修掉）。同一处现在还顺带**按命中的 key 缓存 facade**（不再每请求 `new RSA`）。
- 🟩（2026-10-16 已修）**`black-res-content-type` 曾经是死配置**：`EncryptorResponseFilter` 进入时响应还没有 Content-Type，在链前判定等于永远不命中。现已挪到业务链**跑完之后**判定（命中则不加密、原样回写）。
- `black*` 命名与语义相反：Javadoc 写"白名单"，行为和字段名写"命中即跳过"。别望文生义。
- 名单匹配用的是**正则**（`StrKit.anyMatch` → `ReUtil.isMatch`），不是 ant 风格通配符。
- 🟩（2026-10-16 已修）`WebContext` 是 `ThreadLocal`，**曾经不清理**（泄漏面等于线程池规模，会串号）；现在 `WebContext.clear()` 已在 `EncryptorWebFilter` 的 `finally` 里调用。**新增过滤器时不要绕开这一点。**
- 本模块里也有一个 `io.github.cuukenn.encryptor.web.constant.GatewayConstant`（网关头常量），与 `encryptor-gateway-starter` 的 `reactive.gateway.constant.GatewayConstant` 同名不同包，容易看错。
