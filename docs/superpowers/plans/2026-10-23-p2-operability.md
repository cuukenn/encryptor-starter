# P2 可运维性 Implementation Plan

> TDD：先写失败测试，再实现；boot3 复制对逐字节同步。

**Goal:** 把"配置写错在启动期失败"扩展到 crypto-config 与过滤器顺序；失败响应的 trace 能在日志里对上；query string 不再向业务/日志暴露密文。

**Spec:** `docs/superpowers/specs/2026-10-16-payload-security-protocol-design.md`（协议不变）

## Global Constraints

- 不改 AAD / compact / header claim。
- 错误信息必须带配置前缀与非法值。
- 每个任务跑对应模块测试；改 core 先 install。

---

### Task 1: crypto-config 的 kid 交叉校验 + 声明顺序

**Files:** `WebEncryptorConfig.java`（`HashMap` → `LinkedHashMap`）、`WebEncryptorConfiguration.java`（启动校验）
**Test:** `WebCryptoConfigBindingTest`

- [ ] 测试 1：`crypto-config` 配不存在的 kid → 上下文启动失败，消息含 kid 与配置项名。
- [ ] 测试 2：两个等长正则按声明顺序返回（`getBestMatchStr` 契约在 web 侧成立）。
- [ ] 实现：map 改 `LinkedHashMap`；在 `webEncryptorFilter` bean 方法里校验每个白名单 kid `protocol.keys().contains(kid)`，缺失即抛 `EncryptorException`。
- [ ] 跑 web 全量；boot3 同步 + 守卫。

### Task 2: 过滤器 order 启动期校验

**Files:** `WebEncryptorConfig.afterPropertiesSet()`
**Test:** `WebCryptoConfigBindingTest`

- [ ] 测试：`encryptor-res-filter-order` 配成 `-13`（早于门面）→ 启动失败，消息含 `filter-config` 与顺序要求。
- [ ] 实现：断言 `jwks < facade < params < body < res`，非法抛 `EncryptorException` 并打印五个实际值。
- [ ] 跑 web 全量；boot3 同步 + 守卫。

### Task 3: 失败面 trace 与日志同值

**Files:** `EncryptorWebFilter.fail(...)`
**Test:** `EncryptorWebFilterTest`（Logback `ListAppender`）

- [ ] 测试：缺 jwe 的失败响应，`X-Encryptor-Trace` 的值出现在同一请求的 WARN 日志里。
- [ ] 实现：`fail(response, status, reason, args...)` 生成 trace → `logger.warn("encrypt request failed, trace: {}, ...", trace, ...)` → 写头/状态。
- [ ] 跑 web 全量；boot3 同步 + 守卫。

### Task 4: `getQueryString()` 剔除 jwe

**Files:** `EncryptorRequestParameterFilter`
**Test:** `FilterChainOrderTest` 或新增 `EncryptorRequestParameterFilterTest`

- [ ] 测试：`?jwe=<密文>&a=1` → 参数视图无 jwe，且 `getQueryString()` 为 `a=1`；只有 jwe 时为 `null`。
- [ ] 实现：wrapper 覆写 `getQueryString()`，按 `&` 过滤 name（URL 解码后等于 `jwe`）的分段。
- [ ] 跑 web 全量；boot3 同步 + 守卫。

## 验证

- `mvn -B -o -Pmain-module clean install`
- `JAVA_HOME=…17 mvn -B -o -Pboot3 clean install`
- 三对复制对守卫 + 自测。
