# encryptor-gateway-starter 深潜（reactive 线）

两个 GlobalFilter + 有界执行器 + JWKS WebFilter + `GatewayEncryptorConfig`（模块特有字段）+ micrometer 衔接。

## 结构

```text
JwksEndpointFilter(WebFilter, 最外) → EncryptorGatewayFilter(请求: 决策+解密+改写, order 可配)
                                     → [业务/路由] → EncryptorResponseFilter(响应加密, 包在 NettyWrite 之内)
```

- order 全可配，相对链序启动期校验（jwks < 请求；响应 < `NettyWriteResponseFilter`）。
- AAD 的 uri 用 `ContextAad.canonicalPath` 折叠形（与 servlet 侧原始形态是**有意的口径差异**）；响应 claim 同口径。
- 载体编解码走 core `CarrierKit`（`decodeFormComponent`/`encodeQueryComponent`/`jweFromFormBody`）；QUERY 重建后 URI 保持已编码形态。
- kid 白名单/routes 走 core `RouteRule.effectiveKids`；请求侧明文 body 在 decorate 时 clone 并登记 `GatewayContext`（防 Retry 二次订阅竞态 + 链终止统一清零）。

## 实现面硬性限定

1. **JCA 全部离开 event loop**：解密/加密 `subscribeOn(crypto.scheduler())`；`CryptoExecutor` 是有界 boundedElastic 包装（容量 `encryptor.config.reactive.gateway.crypto-executor.threads/queue-capacity`，threads=0 表示 CPU 核数；队列满 → 503 不伪装 4xx）。
2. `CryptoExecutor` 队列深度不能读 `Scannable.Attr.BUFFERED`（任务派进内部队列后不可见，恒 0）——`pendingTasks()` 自记账且先读 completed 再读 submitted（防 gauge 瞬时负值）；Reactor 的 `Scheduler` 只 extends Disposable，覆写 `scanUnsafe` 编译失败。
3. 响应边界：HEAD/1xx/204/205/304 不加密；3xx 仅空 body 跳过；chunked 走 `writeAndFlushWith` 有界聚合进同一加密路径；content-type skip 按 media-type 段（剥 `;`、小写）；超 max-response-size 500 不发明文；改写后去 `Content-Encoding`。
4. 敏感副本清零：CEK 副本全链终态 `doFinally` 清零；响应明文 bytes 在加密阶段 `doFinally` 清零；`cleanup(exchange)` 覆盖 complete/error/cancel（订阅取消测试钉住）。
5. 审计：codec 外失败（缺载体/kid 白名单/执行器拒绝/超限/非法 query）经 `audit()`/审计重载补发，不双计；失败面 trace 头与日志同值。
6. **网关下游必须是不带 encryptor 的普通应用**（转发的已是明文）。
7. micrometer 衔接：`EncryptorMicrometerAutoConfiguration` 必须 `@AutoConfigureAfter` 本模块装配（`@ConditionalOnBean(CryptoExecutor)` 对排序敏感，否则指标静默不注册）。

## 配置（`encryptor.config.reactive.gateway.*`）

`GatewayEncryptorConfig` 模块特有字段：`skipAble`（共享密钥开关，启动 WARN）、`filterConfig`、`cryptoExecutor`、`cryptoConfig`、`routes`；skip 机制继承 core base。failure-status/上限在 `encryptor.config.reactive.*` 通用段。启动校验：failure-status 可解析、正则预编译、kid 存在性、链序。

## gateway 自检

- [ ] 只改了本侧？查 `topics/sync-map.md`（servlet 对位、boot3 复制对——本模块 3 文件是 API 适配豁免人审面）。
- [ ] 动了 reactive 共享线（无 boot3 副本）= 同时进 boot3 线，测试面在 boot3-example。
- [ ] 取消/拒绝/超时路径改动 → 跑 `GatewayJweTest` 的取消与 503 用例族。
