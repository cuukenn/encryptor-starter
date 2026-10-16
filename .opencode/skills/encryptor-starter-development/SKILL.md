---
name: encryptor-starter-development
description: Use when changing this repository's data-encryption code - adding or swapping a crypto, encoding, signature, or digest algorithm; adding a new starter module; editing the servlet-web or Spring Cloud Gateway encrypt/decrypt filter chain (query params, request body, response rewrite, skip-encryption); or debugging why a request bypasses encryption or fails signature checks. Not for unrelated modules.
---

# encryptor-starter 开发导航

本仓库是"数据传输加解密"的 Spring Boot Starter 家族。这个 skill 只做一件事：**按任务把你带到正确的模块文档，并提醒那些一改就坏的复制粘贴处**。

## 第一步

1. 读仓库根的 `AGENTS.md`（模块表、依赖方向、核心数据流、配置前缀）。
2. 按下面的表打开对应模块文档，**以文档给出的文件路径为准**再读代码——不要先全仓库 grep。

## 任务路由

| 任务 | 打开 |
| --- | --- |
| 加密/编码/签名/摘要算法、报文格式、签名输入 | `docs/architecture/encryptor-core.md` |
| servlet 侧过滤器、contentType 名单、uri 级密钥、参数/请求体解密 | `docs/architecture/encryptor-web-starter.md` |
| 网关过滤链、query 解密、跳过加密、响应改写、gzip | `docs/architecture/encryptor-gateway-starter.md` |
| 默认算法组合、`IEncryptorFacadeFactory`、`CheckerStrategy` | `docs/architecture/encryptor-starter.md` |
| reactive 基础模块 / 配置前缀差异 | `docs/architecture/encryptor-starter-reactive.md` |
| 新增 starter 模块、BOM 版本 | `docs/architecture/encryptor-dependencies.md` |
| 跑示例、改前端 Demo | `docs/architecture/encryptor-examples.md` |

## 动手前自检

- [ ] 我改的是 **servlet 侧还是 reactive 侧**？两边是不是复制粘贴的同一份代码？
- [ ] 我改的东西是否跨了协议边界（`EncryptorDataWrapper` 字段 / 参数 JSON 的 `mode`/`padding`/`key`/`iv` / `x-key` attribute / 签名输入顺序）？跨了就要同步 `encryptor-examples/*/front/encryptor/*.js` **和两个 `HttpTest.java`**。
- [ ] 新增 gateway 的 `MessageReader`/`MessageWriter` 实现时，**必须直接 `implements MessageReader<A, B>, MessageWriter<C, D>`**——gateway 侧用 `ResolvableType` 反射取泛型，中间抽象类会导致 `EncryptorException("Get ResolvableType Error")`。
- [ ] 配置写对前缀了吗？web 是 `encryptor.config.web.*`，**gateway 是 `encryptor.config.reactive.gateway.*`**（多一层 `reactive`）。
- [ ] 名单类配置（`black-uris` 等）写的是**正则**；命中即**跳过**加密（不是拦截）。

## 复制粘贴对照表（改一处必改另一处）

| servlet | reactive |
| --- | --- |
| `encryptor-starter/.../config/CryptoConfig.java` | `encryptor-starter-reactive/.../reactive/config/CryptoConfig.java` |
| `encryptor-starter/.../config/EncryptorConfig.java` | `encryptor-starter-reactive/.../reactive/config/EncryptorConfig.java`（只差 `PREFIX`） |
| `encryptor-starter/.../constant/EncryptorConstant.java` | `encryptor-starter-reactive/.../reactive/constant/EncryptorConstant.java` |
| `encryptor-web-starter/.../converter/`、`.../filter/` | `encryptor-gateway-starter/.../reactive/gateway/converter/`、`.../filter/` |

## 验证

```bash
mvn -Pmain-module clean install     # 最低限度
```

端到端要自己起服务：`web-example`(8081) / `gateway-example`(8080→8081)，再跑对应 `HttpTest`（**不是纯单测，必须先起服务**）。

## 不要做的事

- 不要在 `encryptor-core` 里引入 Spring。
- 不要相信 `README.md` 的特性列表（历史上"网关 gzip"等特性代码里并不存在，2026-10-16 已删除该错误声明）——以代码为准。
- 不要为了"看起来更干净"去删掉 reactive 侧的重复类：那是一次跨模块重构，需要单独评估。
