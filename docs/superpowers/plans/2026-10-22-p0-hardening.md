# P0 安全加固 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 修复 2026-10-22 优化点扫描中的 P0 项（白名单失效、响应上限绕过、失败面不可观测、敏感材料滞留、配置校验缺口、网关重放/编码缺陷），不改变 JWE 线格式与 AAD 口径。

**Architecture:** 全部为内部实现与校验改动：servlet 门面引入"匹配用归一化路径"与"AAD 用原始路径"的分离；响应包装补齐父类 setter 的有界化；防重放失败面下沉到 `DefaultProtocol.openRequest`；网关补 `Flux.defer` 与 URI 构建口径；配置校验集中到装配期。

**Tech Stack:** Java 8 / Spring Boot 2.7（javax 线）+ Java 17 / Boot 3.5（boot3 复制对）、JUnit 5、AssertJ、MockHttpServletRequest、Reactor Test、nimbus-jose-jwt。

**Spec:** 本计划直接源自 `docs/optimization-backlog.md`（同日扫描结论）；协议语义以 `docs/architecture/encryptor-core.md` 与设计文档为准。

## Global Constraints

- **不改线格式**：JWE header 字段、AAD claims、载体字段名 `jwe`、`kid` 语义保持不变；`uri` claim 仍绑定客户端传入的 pathname（本次不动 AAD 归一化）。
- **双写面**：改 servlet 侧任一文件必须同步 boot3 对位（用 `scripts/javax-to-jakarta.sh` 的 stdin 模式逐字节生成），并跑 `scripts/javax-to-jakarta.sh --diff` 守卫。
- **Java 8 兼容**：javax 线不得使用 JDK 9+ API（`List.of`、`readAllBytes`、`String#repeat` 等）。
- **清零契约**：任何持有 CEK/明文/共享秘密的 `byte[]` 在请求生命周期结束或失败分支都必须 `Arrays.fill(x, (byte) 0)`。
- **测试先行**：每个任务先写失败测试并确认失败原因，再写实现；每个任务结束跑全模块测试。
- **不碰**：`ContextAad.canonicalPath` 的解码口径（`%2F`/`//` 问题单列，属协议变更，需迁移方案）；JMH 阈值脚本；发布流水线。

## Review Focus

- **context-path 部署**：`/app` + `[/pay/.*]` 白名单必须命中；AAD 仍按 `/app/pay/x` 校验（客户端 `location.pathname` 口径）。
- **大 Content-Length**：业务声明 100MB 时不得预先分配 100MB；`setContentLengthLong(>2GB)` 不得把 `IllegalArgumentException` 抛进业务。
- **重放报文**：`REPLAY`/`EXPIRED` 必须进监听器失败回调、上下文必须销毁、`decrypt.success` 不得计数。
- **失败配置**：`ttl=0`、`failure-status=42`、`allowed-algs` 与密钥无交集必须在启动期失败，错误信息含配置项名。
- **网关二次订阅**：请求体被 `Retry`/二次读取时必须仍可读；query 明文含中文/空格不得 500。

---

### Task 1: servlet 名单与 kid 白名单按 contextPath 归一化

**Files:**
- Modify: `encryptor-starters/encryptor-web-starter/src/main/java/io/github/cuukenn/encryptor/web/filter/EncryptorWebFilter.java:71,73,179`
- Test: `encryptor-starters/encryptor-web-starter/src/test/java/io/github/cuukenn/encryptor/web/filter/EncryptorWebFilterTest.java`
- Sync: `encryptor-starters/encryptor-web-boot3-starter/...`（同相对路径，脚本生成）

**Interfaces:**
- Consumes: `ContextAad.canonicalPath(String requestUri, String contextPath) -> String`（已有）
- Produces: 无公开 API 变化；`doFilterInternal` 内部新增局部变量 `matchUri`（归一化路径，仅用于名单/白名单匹配），`uri` 仍为 `getRequestURI()` 用于 AAD 与日志。

- [ ] **Step 1: 写三个失败测试**

在 `EncryptorWebFilterTest` 增加：

```java
@Test
void contextPath部署下uri级白名单按去前缀路径匹配() throws Exception {
    webConfig.setCryptoConfig(singletonMap("/test/hello", singletonList(JweTestSupport.KID)));
    MockHttpServletRequest request = new MockHttpServletRequest("GET", "/app/test/hello");
    request.setContextPath("/app");
    request.setParameter("jwe", support.seal("ok", "/app/test/hello", "GET"));
    MockHttpServletResponse response = new MockHttpServletResponse();
    run(request, response);
    assertThat(response.getStatus()).isEqualTo(200);
    assertThat(chainExecuted).isTrue();
}

@Test
void contextPath部署下白名单kid不符被拒() throws Exception {
    webConfig.setCryptoConfig(singletonMap("/test/hello", singletonList("other-kid")));
    MockHttpServletRequest request = new MockHttpServletRequest("GET", "/app/test/hello");
    request.setContextPath("/app");
    request.setParameter("jwe", support.seal("ok", "/app/test/hello", "GET"));
    MockHttpServletResponse response = new MockHttpServletResponse();
    run(request, response);
    assertThat(response.getStatus()).isEqualTo(400);
    assertThat(chainExecuted).isFalse();
}

@Test
void contextPath部署下skipUris按去前缀路径命中() throws Exception {
    webConfig.setSkipUris(singletonList("/test/skip.*"));
    MockHttpServletRequest request = new MockHttpServletRequest("GET", "/app/test/skip");
    request.setContextPath("/app");
    MockHttpServletResponse response = new MockHttpServletResponse();
    run(request, response);
    assertThat(response.getStatus()).isEqualTo(200);
    assertThat(chainExecuted).isTrue();
}
```

- [ ] **Step 2: 运行并确认失败**

Run: `/usr/local/maven/3.8.9/bin/mvn -pl encryptor-starters/encryptor-web-starter -Dtest=EncryptorWebFilterTest test`
Expected: 三个新用例 FAIL（前两个 status=400 / chain 未执行；第三个 400）。

- [ ] **Step 3: 实现**

`doFilterInternal` 中：

```java
String uri = request.getRequestURI();                       // AAD/日志：与客户端 pathname 一致
String matchUri = ContextAad.canonicalPath(uri, request.getContextPath()); // 名单/白名单：去 contextPath
if (StrKit.anyMatch(matchUri, config.getSkipUris()) || ...) { ... }
...
List<String> accepted = acceptedKid(matchUri);
```

`acceptedKid` 内部对 `config.getCryptoConfig()` 加 null 保护（`Map<String, List<String>> map = config.getCryptoConfig(); if (map == null || map.isEmpty()) return null;`）。

- [ ] **Step 4: 运行确认通过**

Run: 同 Step 2
Expected: `Tests run: 17, Failures: 0, Errors: 0`（14 旧 + 3 新，数量以实际为准）。

- [ ] **Step 5: 同步 boot3 复制对并跑守卫**

```bash
scripts/javax-to-jakarta.sh < encryptor-starters/encryptor-web-starter/src/main/java/.../EncryptorWebFilter.java \
  > encryptor-starters/encryptor-web-boot3-starter/src/main/java/.../EncryptorWebFilter.java
scripts/javax-to-jakarta.sh < .../EncryptorWebFilterTest.java > .../EncryptorWebFilterTest.java
scripts/javax-to-jakarta.sh --diff encryptor-starters/encryptor-web-starter/src encryptor-starters/encryptor-web-boot3-starter/src --exclude spring.factories
```

Expected: `UNIFORM` 且 exit 0。

- [ ] **Step 6: 提交**

```bash
git add -A && git commit -m "fix(web): uri 名单与 kid 白名单按 contextPath 归一化"
```

---

### Task 2: 响应包装对 setContentLength/setBufferSize 有界

**Files:**
- Modify: `encryptor-starters/encryptor-web-starter/src/main/java/io/github/cuukenn/encryptor/web/filter/BoundedContentCachingResponseWrapper.java`
- Test: `encryptor-starters/encryptor-web-starter/src/test/java/io/github/cuukenn/encryptor/web/filter/EncryptorResponseFilterTest.java`（或新建 `BoundedResponseWrapperTest`）

**Interfaces:**
- Produces: `BoundedContentCachingResponseWrapper` 覆写 `setContentLength(int)`、`setContentLengthLong(long)`、`setBufferSize(int)`；超限时置 `overflow=true` 且不调用父类（不预分配）。

- [ ] **Step 1: 失败测试**

```java
@Test
void 声明超大ContentLength不预分配也不抛异常() {
    MockHttpServletResponse raw = new MockHttpServletResponse();
    BoundedContentCachingResponseWrapper wrapper =
        new BoundedContentCachingResponseWrapper(raw, 1024);
    wrapper.setContentLengthLong(100L * 1024 * 1024);
    assertThat(wrapper.isOverflow()).isTrue();
    wrapper.setBufferSize(64 * 1024 * 1024);
    assertThat(wrapper.isOverflow()).isTrue();
}
```

（`BoundedContentCachingResponseWrapper` 是包内可见，新建测试放同包。）

- [ ] **Step 2: 运行确认失败**

Run: `mvn -pl ... -Dtest=BoundedResponseWrapperTest test`
Expected: FAIL（`isOverflow()` 为 false；`setContentLengthLong(100MB)` 实际预分配）。

- [ ] **Step 3: 实现**

```java
@Override
public void setContentLength(int len) {
    if (!acceptDeclared(len)) { return; }
    super.setContentLength(len);
}

@Override
public void setContentLengthLong(long len) {
    if (len > Integer.MAX_VALUE || !acceptDeclared((int) len)) { return; }
    super.setContentLengthLong(len);
}

@Override
public void setBufferSize(int size) {
    if (size > limit) { overflow = true; return; }
    super.setBufferSize(size);
}

private boolean acceptDeclared(int len) {
    if (len > limit) { overflow = true; return false; }
    return true;
}
```

注意：`limit` 为 `Long.MAX_VALUE` 时（关闭上限）不得误判。

- [ ] **Step 4: 运行确认通过 + 全模块**

Run: `mvn -pl encryptor-starters/encryptor-web-starter test`
Expected: 全绿。

- [ ] **Step 5: 同步 boot3 + 守卫 + 提交**

同上（`BoundedContentCachingResponseWrapper` 含 `javax.servlet`，属复制对）。

---

### Task 3: 重放/过期的失败面（监听器 + 上下文销毁）

**Files:**
- Modify: `encryptor-core/src/main/java/io/github/cuukenn/encryptor/protocol/DefaultProtocol.java:102-107`
- Modify: `encryptor-core/src/main/java/io/github/cuukenn/encryptor/jose/JweCodec.java:100-116`（把 success 回调移到防重放之后，或由 protocol 补发失败）
- Test: `encryptor-core/src/test/java/io/github/cuukenn/encryptor/protocol/DefaultProtocolOpenRequestTest.java`（新建）
- 同步：`encryptor-starters/encryptor-starter{,-reactive}` 的装配无改动；两侧 starter 测试只需在 core 变更后复跑。

**Interfaces:**
- `DefaultProtocol.openRequest(String compactJwe, String uri, String method) -> JweContext`：REPLAY/EXPIRED 时 `context.destroy()` 后抛出；监听器收到 `onDecryptFailure(REPLAY|EXPIRED, e)`，且不再收到 `onDecryptSuccess`。

- [ ] **Step 1: 失败测试**

```java
@Test
void 重放不回调解密成功且上下文被销毁() {
    RecordingListener listener = new RecordingListener();
    DefaultProtocol protocol = newProtocolWith(listener);
    String compact = seal("x", "/a", "GET", "nonce-1");
    protocol.openRequest(compact, "/a", "GET");
    assertThatThrownBy(() -> protocol.openRequest(compact, "/a", "GET"))
        .isInstanceOf(EncryptorException.class)
        .extracting(e -> ((EncryptorException) e).failure())
        .isEqualTo(EncryptorFailure.REPLAY);
    assertThat(listener.successes).isZero();
    assertThat(listener.failures).containsExactly(EncryptorFailure.REPLAY);
}
```

（需要 `EncryptorListener` 的测试替身；`JweTestSupport` 在 web 模块，core 测试需自带 RSA 夹具。）

- [ ] **Step 2: 运行确认失败**

Expected: 失败回调为空 / successes=1。

- [ ] **Step 3: 实现**

在 `DefaultProtocol.openRequest` 中：

```java
JweContext context = codec.decryptRequest(compactJwe, uri, method);
try {
    replayGuard.verify(context.ts(), context.nonce());
} catch (EncryptorException e) {
    context.destroy();
    listener.onDecryptFailure(e.failure(), e);   // 防重放失败也属于解密失败面
    throw e;
}
listener.onDecryptSuccess(context);
return context;
```

并把 `JweCodec.doDecryptRequest` 的成功/失败回调移除（由 `openRequest` 统一发），或让 codec 接受"不回调"标志——二选一，优先改 protocol 并删除 codec 回调，避免双发。

注意：`DefaultProtocol` 需持有 `EncryptorListener` 字段（Builder 已有 `listener`）。

- [ ] **Step 4: 全 core 测试**

Run: `mvn -pl encryptor-core test`
Expected: 全绿（含既有 `JweCodecListenerTest`，需同步调整其断言到 protocol 层）。

- [ ] **Step 5: 提交**

---

### Task 4: 失败路径与 ECDH 中间材料清零

**Files:**
- Modify: `encryptor-core/.../jose/JweCodec.java:184-196`
- Modify: `encryptor-core/.../jose/EcCipherSuite.java:100-125`
- Modify: `encryptor-core/.../jose/ConcatKdf.java:40-75`
- Test: `encryptor-core/.../jose/JweCodecZeroizationTest.java`（新建；用注入的 `CipherSuite` 捕获传入的 cek 引用，解密失败后断言数组全 0）

**Interfaces:** 无 API 变化。

- [ ] **Step 1: 失败测试**

用自定义 `CipherSuite` 包装 Jce 实现：`aeadDecrypt` 抛异常前记录 `cek` 引用；断言 `JweCodec.decryptRequest` 失败后该引用内容全 0。

- [ ] **Step 2: 运行确认失败**（当前 cek 保留原值）
- [ ] **Step 3: 实现**：`doDecryptRequest` 中 `cek` 长度非法与 AEAD 失败分支 `Arrays.fill(cek, (byte) 0)`；`EcCipherSuite` 在 `derive` 后清零 `shared`；`ConcatKdf` 在 finally 清零 `input`/`otherInfo`。
- [ ] **Step 4: `mvn -pl encryptor-core test` 全绿**
- [ ] **Step 5: 提交**

---

### Task 5: nonce 容量可观测性

**Files:**
- Modify: `encryptor-core/.../protocol/DefaultProtocol.java:294-300`
- Modify: `encryptor-core/.../jose/InMemoryNonceStore.java:150-180`
- Modify: `encryptor-starters/encryptor-starter/src/main/java/.../configuration/EncryptorAutoConfiguration.java`（启动摘要）
- Modify: `encryptor-starters/encryptor-starter-reactive/.../EncryptorReactiveAutoConfiguration.java`（同）
- Test: `InMemoryNonceStoreTest` + `DefaultProtocolTest` + 两侧启动摘要测试

**Interfaces:**
- `InMemoryNonceStore` 首次驱逐时 `logger.warn` 一次（`evictedCount()==1` 时）。
- 启动摘要新增一行：`nonce-capacity=100000, retention=600000ms => 稳态上限 ≈166 req/s`。

- [ ] **Step 1:** 失败测试（默认 capacity/retention 下摘要含 `166`；驱逐一次后 WARN 计数=1）。
- [ ] **Step 2:** 运行确认失败。
- [ ] **Step 3:** 实现（日志用 `long rps = capacity * 1000L / retentionMillis`）。
- [ ] **Step 4:** 全绿。
- [ ] **Step 5:** 提交。

---

### Task 6: 配置校验（ttl / failure-status / allowed-algs 交集）

**Files:**
- Modify: `encryptor-core/.../protocol/DefaultProtocol.java:236-238,259-266`
- Modify: `encryptor-core/.../jose/ReplayGuard.java`（复用校验语义，不改）
- Modify: `encryptor-starters/encryptor-starter/src/main/java/.../configuration/EncryptorAutoConfiguration.java:60-90`
- Modify: `encryptor-starters/encryptor-starter-reactive/.../EncryptorReactiveAutoConfiguration.java:60-80`
- Test: `DefaultProtocolTest`、两侧 `EncryptorAutoConfigurationTest`（若无则新建最小 `ApplicationContextRunner` 用例）

**Interfaces:**
- `ttl <= 0` → `EncryptorException("encryptor.config.ttl 非法: 0（必须 > 0）")`（前缀由调用方传入或消息不含前缀，二选一，全仓库一致）。
- `failureStatus` 不在 `[400, 599]` 或 `HttpStatus.resolve(...) == null` → 启动失败。
- `allowedAlgs` 与已装密钥推导集合交集为空 → 启动失败并打印两侧集合。

- [ ] **Step 1:** 三条失败测试（ttl=0 不再回退、failureStatus=42 启动失败、只有 RSA 密钥 + allowed-algs=[ECDH-ES] 启动失败）。
- [ ] **Step 2:** 运行确认失败。
- [ ] **Step 3:** 实现。
- [ ] **Step 4:** 全绿（同步改 `DefaultProtocolTest` 里把 ttl=0 当容错的旧断言）。
- [ ] **Step 5:** 提交。

---

### Task 7: 网关请求体重放补 `Flux.defer`

**Files:**
- Modify: `encryptor-starters/encryptor-gateway-starter/.../filter/EncryptorGatewayFilter.java:199-203`
- Test: `.../filter/GatewayJweTest.java` 增加二次订阅用例

- [ ] **Step 1:** 失败测试：解密后取 `exchange.getRequest().getBody()` 订阅两次，两次都得到完整明文 `byte[]`。
- [ ] **Step 2:** 运行确认失败（第二次为空/异常）。
- [ ] **Step 3:** 改为 `Flux.defer(() -> Flux.just(...))`。
- [ ] **Step 4:** 全绿。
- [ ] **Step 5:** 提交（gateway 无 boot3 差异豁免，仍需跑 boot3 复制对守卫）。

---

### Task 8: 网关 QUERY 载体明文编码

**Files:**
- Modify: `encryptor-starters/encryptor-gateway-starter/.../filter/EncryptorGatewayFilter.java:182-196`
- Test: `GatewayJweTest`

- [ ] **Step 1:** 失败测试：QUERY 载体明文 `q=张三&x=a b`，解密后 `getURI()` 可构建且 `getQueryParams()` 含 `张三`。
- [ ] **Step 2:** 运行确认失败（`IllegalArgumentException`）。
- [ ] **Step 3:** 用非 encoded 模式构建（`build()`/`encode()`），并捕获 `IllegalArgumentException` → `failure-status`。
- [ ] **Step 4:** 全绿。
- [ ] **Step 5:** 提交。

---

### Task 9: 空 200 响应统一封装 JWE

**Files:**
- Modify: gateway `EncryptorResponseFilter.java:82-97` 与 servlet `EncryptorResponseFilter.java`（200 + 空 body 分支）
- Test: 两侧响应过滤器测试 + `jwe.js` 契约说明（README / docs）

**Ruling:** 除 HEAD/1xx/204/205/304 外，200/201 等空 body 也封装为 `{"jwe":"<空明文 JWE>"}`；3xx 空 body 保持现状（不加密）。

- [ ] **Step 1:** 失败测试（gateway + servlet 各一条：200 空 body → 响应是 `{"jwe":...}` 且能解出空串）。
- [ ] **Step 2:** 运行确认失败。
- [ ] **Step 3:** 实现。
- [ ] **Step 4:** 全绿。
- [ ] **Step 5:** 提交。

---

### Task 10: CryptoExecutor 随上下文关闭

**Files:**
- Modify: `encryptor-starters/encryptor-gateway-starter/.../configuration/GatewayEncryptorConfiguration.java:39-43`
- Test: `.../runtime/CryptoExecutorTest.java` + 新增 `GatewayEncryptorConfigurationTest`（`ApplicationContextRunner`）

- [ ] **Step 1:** 失败测试：关闭 `ApplicationContext` 后 `CryptoExecutor.dispose()` 被调用（用子类/监听器断言 scheduler 已 dispose）。
- [ ] **Step 2:** 运行确认失败。
- [ ] **Step 3:** `@Bean(destroyMethod = "dispose")`；`CryptoExecutor` 实现 `DisposableBean` 兜底。
- [ ] **Step 4:** 全绿。
- [ ] **Step 5:** 提交。

---

## 后续批次（不在本计划内，另行立项）

- P1 性能：响应多次拷贝、SSE 默认跳过、form chunked 有界读、readBounded/JSON 解析、Cipher/StrKit 微优化。
- P2 可运维：crypto-config 交叉校验与 `LinkedHashMap`、filter order 校验、失败面 trace 日志、`getQueryString`。
- P3 工程：JMH 定时 CI、HttpTest 集成化、守卫自测进 CI、editorconfig/.gitattributes、发布流水线清理、boot3 共享模块抽取、依赖/文档/CHANGELOG。
- P4 测试缺口：`openRequest` 安全不变量、并发隔离。
