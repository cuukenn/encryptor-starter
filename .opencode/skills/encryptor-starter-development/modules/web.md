# encryptor-web-starter 深潜（servlet 线）

五过滤器链 + 响应加密包装 + JWKS 端点 + `WebEncryptorConfig`（模块特有字段）。

## 链结构与顺序契约

```text
jwks(最外) → 门面 EncryptorWebFilter（载体判定/一次解密/装 WebContext）
           → 参数视图 EncryptorRequestParameterFilter（finally 清 WebContext——异步感知重载）
           → 请求体视图 EncryptorRequestBodyFilter → [业务] → 响应 EncryptorResponseFilter（最内层加密侧）
```

- order 全部可配（`WebFilterConfig`），但**相对链序启动期校验**（`WebEncryptorConfiguration.validateFilterOrder` + config 内 `validateFilterOrder` 双处）：顺序错 = 启动失败而非静默明文。
- 载体判定与编解码走 core `CarrierKit`（`hasQueryJwe`/`parseUrlencoded`）；`getParameter` 合并 query 与 form——jwe 在 query 上一律 QUERY。
- kid 白名单/routes 合并走 core `RouteRule.effectiveKids`。

## 实现面硬性限定

1. **响应过滤器必须嵌在参数过滤器之内**（参数过滤器 finally 清 WebContext/CEK；加密路径经 `deferAsync`/`startAsync` 拦截做所有权移交豁免）；异步周期**必须可终止**（`setTimeout(0)` 且永不 complete 时 CEK/明文滞留到 GC——Servlet 模型固有，无 per-request 兜底）。
2. 请求体包装器（`EncryptorRequestBodyFilter`/`CachedBodyHttpServletRequest`）的 `setReadListener` 抛 `UnsupportedOperationException`（明文在内存，非阻塞读会静默挂死）。
3. `WebContext.clear(request)` 是异步感知重载：响应未包装（旁路/透传）的异步请求只解绑 ThreadLocal、延迟清零。
4. 响应边界：HEAD/1xx/204/205/304 不加密；3xx 仅空 body 跳过；`sendError` 状态保留、消息作加密 body；已提交响应（`isCommitted`）只 WARN 不改写（明文可能已出网，不可补救）；超 max-response-size 500 不发明文。
5. 审计：codec 外失败分支（缺载体/坏 JSON/超限/kid 白名单/query 非法/响应侧失败出口）经审计重载补发 `onDecryptFailure`/`onEncryptFailure`，不双计。
6. `EncryptorRuntime` bean 与 `protocol.runtime()` 同实例（启动期身份校验，覆盖同类型 bean 即 fail-fast）。
7. `BoundedContentCachingResponseWrapper.getWriter` 对非法字符集名回退 UTF-8；信封写入分段拼（避免 UTF-16 中间串）。
8. JWKS 端点（`discovery/JwksEndpointFilter`）：GET/HEAD 同口径、`If-None-Match` 走 `JwksDocument.etagMatch`（多值/弱比较）、路径 `canonicalPath` 归一。

## 配置（`encryptor.config.web.*`）

`WebEncryptorConfig` 只含模块特有字段：`enable`、`filterConfig`、`crypto-config`、`routes`；skip 名单机制继承 core `SkipListsConfigBase`（勿在此改名单逻辑）。启动校验：正则预编译、kid 存在性（crypto-config 与 routes 都查）、链序。

## web 自检

- [ ] 只改了本侧？查 `topics/sync-map.md` 成对表（reactive 对位、boot3 复制对、ResponseFilterHardeningTest↔GatewayJweTest 用例族、FilterOrderValidationTest↔GatewayEncryptorConfigurationTest）。
- [ ] 动了过滤器 order 默认值 → `FilterChainOrderTest` 与链序校验会红，属预期锁定（不要去"修"测试）。
