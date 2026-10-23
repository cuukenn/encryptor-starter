# P1 性能与流式安全 Implementation Plan

> **For agentic workers:** 逐任务 TDD（先写失败测试、看它失败、再实现）。步骤用 `- [ ]` 跟踪。

**Goal:** 消除热路径上的整份复制、让流式/表单的边界与默认配置安全，并修掉非热路径的小额浪费。

**Architecture:** 只改内部实现与默认值，不动 JWE 线格式与 AAD 口径；boot3 复制对逐字节同步。

**Tech Stack:** Java 8 / Spring Boot 2.7（boot3 线 JDK 17），Maven 多模块。

**Spec:** `docs/superpowers/specs/2026-10-16-payload-security-protocol-design.md`（协议不变）

## Global Constraints

- core 不得新增 Spring 依赖；不得引入 BouncyCastle。
- AAD / compact 分段 / header claim 一律不变（改口径 = 协议变更，需三份 jwe.js + 两份 HttpTest）。
- 每个任务结束跑对应模块测试；改 core 先 `install -DskipTests` 再跑下游。
- 改 javax 源必须脚本同步 boot3 对位并跑 `scripts/javax-to-jakarta.sh --diff`。

---

### Task 1: AEAD 解密不再拼接 ciphertext+tag

**Files:** Modify `encryptor-core/src/main/java/io/github/cuukenn/encryptor/jose/JceCipherSuite.java:88-95`;
Test `encryptor-core/src/test/java/io/github/cuukenn/encryptor/jose/JceCipherSuiteTest.java`

**Interfaces:** 不变（`aeadDecrypt(enc, cek, iv, cipherText, authTag, aad)`）。

- [ ] Step 1: 加测试 `分离tag解密结果与拼接输入一致`：同一 cek/iv/aad，encrypt 后手工拆 ct/tag，分别用 `aeadDecrypt` 解出原文；篡改 tag 末字节抛异常。
- [ ] Step 2: 跑该测试，确认现有实现通过（行为基线）。
- [ ] Step 3: 改为 `cipher.update(cipherText)` + `cipher.doFinal(authTag)`，去掉临时数组。
- [ ] Step 4: 跑 `JceCipherSuiteTest` 与 `JweCodecTest`，全绿。
- [ ] Step 5: commit。

### Task 2: 响应封装去掉 AAD 的 String↔bytes 往返

**Files:** Modify `JweCodec.java:281-293`

- [ ] Step 1: 基线测试已覆盖（`JweCodecTest` 响应往返 / `JweCodecZeroizationTest`）。
- [ ] Step 2: `String headerB64 = header.toBase64URL().toString();` 一次；AAD 用其 ASCII bytes；compact 用 `headerB64 + ".." + ...` 拼接（不再 `new String(aad)`）。
- [ ] Step 3: 跑 core 全量测试；确认响应仍可被客户端解开（现有用例断言）。
- [ ] Step 4: commit（与 Task 1 同一提交）。

### Task 3: servlet 响应信封分三段写，避免超长 String 拼接

**Files:** Modify `BoundedContentCachingResponseWrapper.java`（新增 `writeEncryptedEnvelope(String compact)`）、`EncryptorResponseFilter.java:136-142`；Test `EncryptorResponseFilterTest.java`

- [ ] Step 1: 测试 `响应信封按三段写出且内容完整`：写出后 body 等于 `{"jwe":"<compact>"}`，`writtenSize` 等于字节数。
- [ ] Step 2: 实现：前缀/compact/后缀分别 `write`，compact 用 US_ASCII。
- [ ] Step 3: 跑 web 全量；同步 boot3 web 复制对并跑 `--diff`。
- [ ] Step 4: commit。

### Task 4: 网关响应信封同样分三段写

**Files:** Modify `encryptor-gateway-starter/.../filter/EncryptorResponseFilter.java:111-112`；Test `GatewayJweTest.java`

- [ ] Step 1: 测试空 body 与非空 body 的响应都能被客户端解开（现有 `decrypt` helper）。
- [ ] Step 2: 用 `bufferFactory().wrap(prefix)` + compact bytes + suffix 组合（`Flux.just(...)` 或一次性写 `byte[]`，避免 `"{\"jwe\":\"" + jwe + "\"}"`）。
- [ ] Step 3: 跑 gateway 全量；同步 boot3 对位（豁免文件人审）+ 守卫。
- [ ] Step 4: commit。

### Task 5: readBounded 按 Content-Length 预分配、避免 toByteArray 复制

**Files:** Modify `EncryptorWebFilter.java:214-229` + 调用点 `:110`

- [ ] Step 1: 测试 `已知ContentLength时一次读完`（1MiB）、`chunked仍按上限拒绝`（limit+1 → null）。
- [ ] Step 2: 实现 `readBounded(InputStream, long limit, long contentLength)`：`0 < cl <= limit` 时 `new byte[(int) cl]` + 循环读满；否则保留扩容策略；返回 `out.toByteArray()` 仅在未知长度时使用。
- [ ] Step 3: 跑 web 全量；boot3 同步。
- [ ] Step 4: commit。

### Task 6: StrKit 去掉 stream/Comparator，匹配循环化

**Files:** Modify `StrKit.java:77-102`；Test `StrKitTest.java`

- [ ] Step 1: 测试钉住契约：`anyMatch` 空列表 false；`getBestMatchStr` 最长优先、等长取迭代顺序先者。
- [ ] Step 2: 手写 for 循环 + `int bestLen`，保持 `matches` 语义（整串）。
- [ ] Step 3: 跑 core 全量（web/gateway 复用）。
- [ ] Step 4: commit。

### Task 7: InMemoryNonceStore 序号在锁内分配

**Files:** Modify `InMemoryNonceStore.java:150-165`

- [ ] Step 1: 测试 `并发插入后驱逐顺序与插入序号一致`（现有并发测试扩展：容量=2，插 3 条，断言 evicted 的是第一条）。
- [ ] Step 2: 将 `sequence.incrementAndGet()` 移入 `synchronized(lock)` 内（`evictIfNeeded` 内分配 Entry 或传 supplier）；`consume` 的 `compute` 仍需原子占位。
- [ ] Step 3: 跑 core 全量（含 4 线程并发用例）。
- [ ] Step 4: commit。

### Task 8: chunked 表单请求显式 413（不再进容器 getParameter 无界解析）

**Files:** Modify `EncryptorWebFilter.java:91-101`；Test `EncryptorWebFilterTest.java`

- [ ] Step 1: 测试 `chunked表单超过上限时413且不调用getParameter`：`Content-Length=-1`、form content-type、maxRequestSize>0 → 413，`getParameter` 未被调用。
- [ ] Step 2: 在现有 Content-Length 预检后加：form 且 `getContentLengthLong() < 0` → 413（日志提示改用带 Content-Length 的请求）。
- [ ] Step 3: 跑 web 全量；boot3 同步；README 记一句限制。
- [ ] Step 4: commit。

### Task 9: 流式响应默认跳过 + 启动告警

**Files:** Modify `WebEncryptorConfig` / `GatewayEncryptorConfig` 默认 `skipResContentType`；两侧 autoconfig 摘要
Test `WebCryptoConfigBindingTest`、`GatewayEncryptorConfig` 对位测试

- [ ] Step 1: 测试默认名单包含 `text/event-stream`；配置覆盖后仍可清空。
- [ ] Step 2: 默认值改为 `["text/event-stream"]`；空名单且 `maxResponseSize>0` 时启动 WARN。
- [ ] Step 3: 跑 web/gateway 全量；boot3 同步；README/CHANGELOG 更新。
- [ ] Step 4: commit。

## 验证

- `mvn -B -o -Pmain-module clean install`
- `JAVA_HOME=…17 mvn -B -o -Pboot3 clean install`
- 三对复制对守卫 + `scripts/javax-to-jakarta.test.sh`
