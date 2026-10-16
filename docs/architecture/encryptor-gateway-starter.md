# encryptor-gateway-starter（artifactId: `encryptor-gateway-spring-boot-starter`）

> **Spring Cloud Gateway（reactive）侧**的接入层：`GlobalFilter` 链 + `ModifyRequestBody/ResponseBody` 改写 + 上下文放在 `exchange.attributes` 里。

| 项 | 值 |
| --- | --- |
| 目录 | `encryptor-starters/encryptor-gateway-starter/` |
| artifactId | `encryptor-gateway-spring-boot-starter`（`jar`） |
| 依赖 | `encryptor-spring-boot-starter-reactive`、`spring-cloud-starter-gateway`、`spring-boot-configuration-processor`(optional) |
| 包名 | `io.github.cuukenn.encryptor.reactive.gateway` |
| 自动装配入口 | `spring.factories` → `io.github.cuukenn.encryptor.reactive.gateway.configuration.GatewayEncryptorConfiguration` |

## 职责

和 `encryptor-web-starter` 对应，但运行在 **Netty / reactive** 环境：

1. 判定是否加解密，并把 `EncryptorFacade` 与开关存进 `ServerWebExchange.attributes`。
2. 用 Gateway 自带的 `ModifyRequestBodyGatewayFilterFactory` / `ModifyResponseBodyGatewayFilterFactory` 改写请求体与响应体。
3. 处理 query / form 参数形态的密文，以及"跳过加密"的联调开关。

## GlobalFilter 链（Order 即执行顺序）

| Order（默认） | 类 | 作用 |
| --- | --- | --- |
| `-13` | `filter/rewrite/EncryptorGatewayFilter` | 门面：判名单、选 `CryptoConfig`、把 facade 放进 exchange |
| `-12` | `filter/EncryptorSkipFilter` | 读请求头 `x-skip-encryptor`，命中则移除加密开关 |
| `-11` | `filter/rewrite/EncryptorRequestParameterFilter` | 解密 **query 参数**形态的报文，重建 URI |
| `-10` | `filter/rewrite/EncryptorRequestFilter` | 解密**请求体**形态的报文 |
| `NettyWriteResponseFilter.WRITE_RESPONSE_FILTER_ORDER - 1` | `filter/rewrite/EncryptorResponseFilter` | 加密响应体 |

顺序默认值定义在 `config/GatewayFilterConfig.java`（响应那个刻意用 `NettyWriteResponseFilter.WRITE_RESPONSE_FILTER_ORDER - 1` 计算，改动前先理解写回时机）。配置前缀是 **`encryptor.config.reactive.gateway.filter-config.*`**（比 servlet 侧多一层 `reactive`）。

### 每个 Filter 在做什么

- **`EncryptorGatewayFilter`**：门面，构造参数 `(GatewayEncryptorConfig, IEncryptorFacadeFactory<CryptoConfig>, order)`，与 web 侧的 `EncryptorWebFilter` 同构，但状态写进 `exchange`（`GatewayConstant.GATEWAY_ENCRYPTOR_*`）而不是 `ThreadLocal`。
- **`EncryptorSkipFilter`**：`exchange.getRequest().getHeaders().getFirst("x-skip-encryptor")` 非空就 `attributes.remove(GATEWAY_ENCRYPTOR_ENABLE)`。
- **`EncryptorRequestParameterFilter`**：`request.getQueryParams().toSingleValueMap()` → `EncryptorDataWrapper` → `facade.decrypt(...)` → 明文 map 重新拼成 query（`UriComponentsBuilder.replaceQueryParams`），并把 `key` 放进 attributes（`CoreEncryptorConstant.KEY`）。
- **`EncryptorRequestFilter` / `EncryptorResponseFilter`**：按 `Content-Type` 选一个 `MessageReader`/`MessageWriter`，然后**用 `ResolvableType` 反射取出该实现的泛型参数**（`getGeneric(0)/getGeneric(1)`）来设置 `inClass/outClass`，最后交给 Gateway 的改写工厂。

## 消息编解码器（SPI）

`converter/` 与 web 侧平行：

| 接口 | 方法 |
| --- | --- |
| `MessageReader<I, O>` | `boolean canRead(MediaType)` / `RewriteFunction<I, O> read()` |
| `MessageWriter<I, O>` | `boolean canWrite(MediaType)` / `RewriteFunction<I, O> write()` |

实现：`JsonMessageConverter`（`EncryptorDataWrapper` ↔ `byte[]`，覆盖 `application/json`、`application/*+json`、`application/x-ndjson`）、`FormMessageConverter`、`DefaultMessageConverter`（兜底，委托 JSON）。**2026-10-16 起**由 `GatewayEncryptorConfiguration` 以 `@Bean + @ConditionalOnMissingBean` 显式注册（不再 `@Component`/`@ComponentScan`），加密/解密的 RSA/AES 运算跑在 `Schedulers.boundedElastic()` 上。

## 上下文与常量

- `kit/GatewayKit`：`isReqEncryptorEnable(exchange)` / `isResEncryptorEnable(exchange)` / `getEncryptorFacade(exchange)` / `setEncryptorFacade(exchange, ...)` / `anyMatch(...)`——全部基于 `exchange.getAttributes()`。**reactive 侧没有 `ThreadLocal`**，这是与 web 侧最大的结构差异。
- `constant/GatewayConstant`：`x-gateway-encryptor-config`、`x-gateway-encryptor-enable`（`GATEWAY_ENCRYPTOR_ENABLE` 与 `GATEWAY_ENCRYPTOR_REQUEST_ENABLE` **值相同**）、`x-gateway-encryptor-bean`。

## 配置

```yaml
encryptor:
  config:
    reactive:                        # ← 多这一层！reactive 侧 EncryptorConfig.PREFIX = encryptor.config.reactive
      crypto-config: { ... }         # rsa 私钥/公钥、algorithm、encryptor-factory
      gateway:                       # 即完整前缀 encryptor.config.reactive.gateway
        enable: true
        skip-able: false             # 是否允许客户端用 x-skip-encryptor 跳过加密（仅联调；发版不应信任客户端）
        crypto-config: { ... }       # 同 web 侧，key 是 uri 正则
        filter-config: { ... }       # 各 filter order
        black-uris / black-methods / black-req-content-type / black-res-content-type
        failure-status: 400          # 报文解不开时返回的状态码（默认 400）
        max-request-size: 1048576    # 请求体上限（字节，<=0 不限；网关上暂未强制，仅 web 侧生效）
```

## 扩展点

| 想做的事 | 做法 |
| --- | --- |
| 支持新的 contentType | 新增 `MessageReader`/`MessageWriter` 实现并注册成 Spring bean（starter 已不再 `@ComponentScan`，改显式 `@Bean` + `@ConditionalOnMissingBean`，可被使用方覆盖） |
| 换掉某个 filter | 注册同类型 bean（装配方法上有 `@ConditionalOnMissingBean`） |
| 调整顺序 | 改 `encryptor.config.reactive.gateway.filter-config.*-order`（响应顺序要连带考虑 `NettyWriteResponseFilter`） |
| 换整套算法组合 | 见 `encryptor-starter-reactive.md` / `IEncryptorFacadeFactory` |

## 改动影响面

- 与 `encryptor-web-starter` 的 `filter/`、`converter/` 是**平行实现**：改协议必须两边同步（尤其 `x-key`/`x-gateway-encryptor-*` 属性名与 `EncryptorDataWrapper` 字段）。
- 请求/响应改写依赖**反射读泛型**：如果新增的 `MessageReader`/`MessageWriter` 实现没有直接声明接口泛型（例如继承中间抽象类），`ResolvableType` 会取不到而抛 `EncryptorException("Get ResolvableType Error")`。新增实现时**必须直接 `implements MessageReader<A, B>, MessageWriter<C, D>`**。
- 响应加密排在 `NettyWriteResponseFilter` 之前，改 order 很容易导致响应已被写回而加密失效。

## 坑

- 🟩（2026-10-16 已修）`GatewayEncryptorConfiguration` 的 logger **曾**用 `LoggerFactory.getLogger(EncryptorReactiveAutoConfiguration.class)`（类名写错），现已改用本类。
- **网关没有任何 gzip 处理**（`README.md` 曾声称"支持网关 gzip 的 encode/decode"，该错误声明已于 2026-10-16 删除）。不要照着 README 去找实现；需要的话就是从零加。
- 🟩（2026-10-16 已修）`GATEWAY_ENCRYPTOR_ENABLE` 与 `GATEWAY_ENCRYPTOR_REQUEST_ENABLE` 两个常量**曾**值相同（导致 `black-req-content-type` 静默失效），现已给请求侧独立值；请求方向需两个属性都置位才生效。
- ⚠️（2026-10-16 端到端发现）**网关的下游必须是没引入 encryptor 的普通应用**：网关转发给下游的已经是**明文**参数（见 `security-review.md` S16），下游若自己也带 starter 会再解一次密 → `key=null` → 回 `failure-status`（默认 400）。示例里正确的下游是 `encryptor-examples/gateway-example/web`。
- ⚠️ 网关的加解密运算自 2026-10-16 起跑在 `Schedulers.boundedElastic()`（不再阻塞 Netty event loop）；`max-request-size` 目前在网关侧**未强制**（网关是流式的，留待后续）。
- **配置前缀比 servlet 侧多一层 `reactive`**：reactive 侧是 `encryptor.config.reactive.*`，不是 `encryptor.config.*`。从 web 侧抄配置到网关时最容易踩这个。
- 与 web 侧一样，`black*` 名字与实际"跳过名单"语义相反，且匹配是**正则**。
