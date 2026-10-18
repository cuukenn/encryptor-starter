---
name: encryptor-starter-development
description: Use when changing this repository's JWE payload-security code - adding or swapping a CipherSuite (RSA-OAEP/AES-GCM, SM2/SM4-GCM); editing the servlet-web or Spring Cloud Gateway decrypt/encrypt filter chain (three carriers, response rewrite, JWKS discovery endpoint, skip lists); or debugging why a request fails decryption (400/413) or bypasses encryption. Not for unrelated modules.
---

# encryptor-starter 开发导航（v2 / JWE 协议）

本仓库是"报文层安全（机密性 + 防篡改）"的 Spring Boot Starter 家族，协议对齐 JOSE/JWE（RFC 7516），支持国密 SM2/SM4-GCM。这个 skill 只做一件事：**按任务把你带到正确的模块，并提醒那些一改就坏的成对文件**。

> ⚠️ `docs/architecture/*.md` 是 v1 时代的记录（已加失效横幅），**只用于追溯**。当前事实以源码为准；协议定义见 `docs/superpowers/specs/2026-10-16-payload-security-protocol-design.md`。

## 第一步

1. 读仓库根的 `AGENTS.md`（安全边界、模块表、依赖方向、v2 数据流、配置前缀、坑清单）。
2. 按下表定位**源码目录**（不再是文档），直接读代码。

## 任务路由（源码位置）

| 任务 | 打开 |
| --- | --- |
| JWE 编解码 / AAD / 防重放 / 密钥库 / CipherSuite | `encryptor-core/src/main/java/io/github/cuukenn/encryptor/jose/`、`protocol/`、`runtime/` |
| 默认协议栈组装（算法白名单默认值与装配套件联动） | `encryptor-core/.../protocol/DefaultProtocol.java` |
| servlet 侧过滤器链（三载体/一次解密/失败面） | `encryptor-web-starter/.../filter/` |
| servlet JWKS 发现端点 | `encryptor-web-starter/.../discovery/JwksEndpointFilter.java` |
| 网关链路（GlobalFilter/有界执行器/响应改写） | `encryptor-gateway-starter/.../gateway/filter/` |
| 网关 JWKS 端点 | `encryptor-gateway-starter/.../gateway/discovery/JwksEndpointFilter.java` |
| 配置形态 / 自动装配 / 启动摘要 | 两侧 `EncryptorAutoConfiguration` + `config/EncryptorConfig`（+ KeyMaterial/Discovery/BypassConfig） |
| 新增 CipherSuite（如新国密组合） | `encryptor-core/.../jose/CipherSuite.java` + `JceCipherSuite`/`SmCipherSuite` 对照实现；白名单须同步 `DefaultProtocol` |
| 跑示例 / 前端 JS 客户端 | `encryptor-examples/*/front/encryptor/jwe.js`（WebCrypto 参考实现） |
| 性能回归 | `encryptor-bench/` + `check-thresholds.sh`（RSA 并行度、bytes/op 基线） |

## 动手前自检

- [ ] 我改的是 **servlet 侧还是 reactive 侧**？两边是**成对**文件（见对照表），只改一边 = "servlet 正常、网关失败"。
- [ ] 我改的东西是否跨了协议边界（JWE protected header 的 `uri`/`m`/`dir`/`ts`/`nonce` claims、载体字段名 `jwe`、`kid` 语义、alg/enc 取值）？跨了就要同步：两份 `HttpTest.java` **和两份 `front/encryptor/jwe.js`**，并更新设计文档。
- [ ] 新增算法：CipherSuite 只解决"怎么算"；"许不许用"在白名单（`allowed-algs`/`allowed-encs` + codec 内强制），两边配置默认值都要能联动到。
- [ ] 配置写对前缀了吗？web 是 `encryptor.config.web.*`，**gateway 是 `encryptor.config.reactive.gateway.*`**（多一层 `reactive`，且 failure-status/上限在 reactive 通用段）。
- [ ] 名单类配置（`skip-uris` 等，旧名 `black-uris` 为弃用 alias）是**正则整串匹配**；命中即**跳过**加密（不是拦截）。含 `.` 的 uri 正则 key 必须用括号写法 `"[...]"`。
- [ ] `Cipher` 非线程安全——不要缓存单例；防重放必须在 GCM tag 校验**之后**。

## 成对文件对照表（改一处必改另一处）

| servlet | reactive/gateway |
| --- | --- |
| `encryptor-starter/.../configuration/EncryptorAutoConfiguration.java` | `encryptor-starter-reactive/.../reactive/configuration/EncryptorReactiveAutoConfiguration.java` |
| `encryptor-starter/.../config/EncryptorConfig.java`（+ KeyMaterial/Discovery/BypassConfig） | `encryptor-starter-reactive/.../reactive/config/`（同三件套，只差 `PREFIX`） |
| `encryptor-web-starter/.../filter/`、`.../discovery/JwksEndpointFilter` | `encryptor-gateway-starter/.../gateway/filter/`、`.../discovery/JwksEndpointFilter` |
| `encryptor-examples/web-example/front/encryptor/jwe.js` | `encryptor-examples/gateway-example/gateway/front/encryptor/jwe.js` |

## 验证

```bash
mvn -pl encryptor-core install -DskipTests    # 改 core 后先装本地仓库（reactive/gateway 编译依赖 jar）
mvn -B -Pmain-module clean install            # 最低限度（132 测试）
mvn -B -Pall-modules clean install            # 含 examples（HttpTest 仍被 surefire 排除）
java -jar encryptor-bench/target/bench.jar -wi 2 -i 3 -f 1 -prof gc -rf json -rff encryptor-bench/target/bench.json && encryptor-bench/check-thresholds.sh
```

端到端要自己起服务：`web-example`(8081) / `gateway-example`(8080，下游 `gateway-example/web`=8082 普通应用)；再跑对应 `HttpTest` 或 `node front/test.js`（**必须先起服务**）。

## 不要做的事

- 不要在 `encryptor-core` 里引入 Spring。
- 不要"优化"掉每次新建的 `Cipher`（线程安全换来的）。
- 不要在 tag 校验前消费 nonce（未认证输入不得污染防重放存储）。
- 不要给网关下游接 encryptor（网关转发的已是明文，下游再解一次 → 400）。
- 不要注册 BC 全局 Provider（SM 路径只用轻量级 API）。
