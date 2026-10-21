# 多 Spring Boot 版本支持设计（JDK 8 + Boot 2.7 ⇄ JDK 17 + Boot 3.5 双线）

日期：2026-10-21
状态：待用户最终确认（builder check 之后)

## 1. 意图与为什么

`encryptor-starter` 是报文层安全 Spring Boot Starter，现状只支持 **JDK 8 + Spring Boot 2.7.18 + Spring Cloud 2021.0.8 + Spring Cloud Alibaba 2021.1**。需求：下游用户按自己环境**选型**使用——既要服务存量 JDK 8 / Boot 2.7 用户，也要服务新项目 JDK 17 / Boot 3.x 用户。

用户明确拒绝多 git 分支方案（维护成本高），选定：**单分支、每代独立 Maven 模块、独立 artifactId（`-boot3` 后缀）**。版本语义 = artifact 名字上直接可读：原名模块 = Boot 2.7 线，`-boot3` 后缀 = Boot 3 线。

已核实的版本配对（2026-10）：

| 线 | JDK | Spring Boot | Spring Cloud | Spring Cloud Alibaba |
| --- | --- | --- | --- | --- |
| 现状（javax） | 8/11/17 | 2.7.18 | 2021.0.8 | 2021.1 |
| 新线（jakarta） | 17/21 | 3.5.x | 2025.0.x (Northfields) | 2025.0.x |

（SC Alibaba 官方版本说明：2025.0.x 适配 Boot 3.5.x + SC 2025.0.x，最低 JDK 17。）

## 2. 目标

1. **javax 线零扰动**：现有 9 个模块源码、依赖、测试矩阵保持不变，继续作为 JDK 8 用户的产品线。
2. **新增 boot3 代际模块**：用 Boot 3.5 + JDK 17 编译，通过与 javax 线**对等**的测试（安全语义、三载体、防重放、失败面全部覆盖）。
3. **README 选型表**：按 JDK/Boot 版本 → artifact 后缀的对照表，用户零歧义。
4. **CI 双矩阵**：现有 JDK 8/11/17 矩阵继续守卫 javax 线；新增 JDK 17/21 任务构建并测试 boot3 模块。
5. **防漂移机制**：双份 starter 源码必须有 CI 守卫证明"jakarta 版 == javax 版经机械包名替换后的结果"（同类 `jwe.js` diff 守卫，见第 6 节）。

## 3. 非目标

- Spring Boot 4 / Spring Cloud 2025.1 支持（生态尚在收敛，届时单独立项）。
- 修改 JWE 协议、AAD claims、防重放语义（协议只有一份规范，两线共享）。
- 抬高 javax 线的 baseline（不做中间代际，只保两端）。
- 双分支、双仓库。

## 4. 反目标（出现即视为失败）

- 因复制导致**协议逻辑**分叉：安全语义必须只有一份源（core 不复制；starter 复制面只允许 servlet/reactive 装配层）。
- 双份代码靠人工同步（必须由 CI diff 守卫兜底，不靠自觉）。
- javax 线因迁出 boot3 模块而出现任何行为/依赖树变化（发布面 1.x 用户无感知）。

## 5. 模块拓扑与命名（已定）

```
encryptor-core / encryptor-sm            零 Spring 零 servlet，单份，release 8 编译，两代通用
encryptor-starters/
  encryptor-starter                      (javax, J8, 现状, 不动)
  encryptor-starter-reactive             (javax, 现状, 不动)
  encryptor-web-starter                  (javax, 现状, 不动)
  encryptor-gateway-starter              (javax, 现状, 不动)
  encryptor-micrometer-starter           (javax, 现状, 不动)
  encryptor-spring-boot3-starter         (jakarta, J17, 新增)
  encryptor-web-boot3-starter            (jakarta, J17, 新增)
  encryptor-gateway-boot3-starter        (jakarta, J17, 新增)   ← 视验证可能免复制，见 6.2
  encryptor-reactive-boot3-starter       (jakarta, J17, 新增)   ← 视验证可能免复制
  encryptor-micrometer-boot3-starter     (jakarta, J17, 新增)   ← 视验证可能免复制
```

版本号：新线从 `3.0.0` 起始（与 Boot 3 代际对齐，选型防歧义），javax 线继续 `1.x`。

## 6. 技术要点（builder 必须逐条处理）

### 6.1 单 reactor 双 Java baseline / 双 BOM

- 根 POM 需容纳：javax 模块 release=8，boot3 模块 release=17，且 boot3 模块的 Boot/Cloud/SCA BOM 与根不同。
- **builder check 已核实（2026-10-21）**：根 `pom.xml:23-25` 的 `spring-boot.version`/`spring-cloud.version`/`spring-cloud-alibaba.version` 是普通 property，BOM import（`pom.xml:41-63`）对其插值，**子模块覆写 property 是首选路径**；显式重复 dependencyManagement 块保留为兜底。编译接线是同一模式（`java.version=8` → source/target，根未设 `release`）。根 POM 未 pin compiler 插件版本，boot3 模块需显式 pin。
- **新制品版本管理**：`encryptor-dependencies` 用 `${revision}` 统一管理本仓库 G:A（都是 1.0.0），管不住 3.0.0 的 `-boot3` 制品——需新增一个 boot3 BOM（或 boot3 模块自理版本）。混合版本（parent 1.0.0 + boot3 3.0.0）在 `central-publishing-maven-plugin` 整 reactor 上传的是否可用需 spike 验证。

### 6.2 reactive/gateway/micrometer 的共享验证（减少复制面）

- **builder check 已核实（2026-10-21）**：reactive/gateway/micrometer main 源码 `javax.*` 零命中；Spring 面 = `GlobalFilter`/`GatewayFilterChain`/`NettyWriteResponseFilter`(SCG)、`WebFilter`/`ServerWebExchange`/`ServerHttpRequestDecorator`/`ServerHttpResponseDecorator`/`DataBufferUtils`/`UriComponentsBuilder`、Reactor `Scheduler`、Micrometer `MeterRegistry`——全部在 Spring 6 / SCG 4.3 / Micrometer 1.15 中仍存在，共享 jar 假设通过初筛；5 个 starter 均已带 `AutoConfiguration.imports`，Boot 3 移除 spring.factories 装配不阻塞。**验证必须显式覆盖三个风险点**：
  1. SCG 过滤器 ordering：`NettyWriteResponseFilter.WRITE_RESPONSE_FILTER_ORDER - 1`（`GatewayFilterConfig.java:19`）在 SCG 3.1→4.x 的内部排序变化，响应加密次序需重新验证（不能假设一致）；
  2. `onErrorResume(DataBufferLimitException.class, ...)` 413 路径（`EncryptorGatewayFilter`/`EncryptorResponseFilter`）：Spring 6.x `maxInMemorySize` 异常浮出点可能变化；
  3. `@AutoConfigureAfter` 在 Boot 3 的语义（Boot 推 `@AutoConfiguration(after=)`）：共享 jar 走 legacy 注解，验证装配次序仍被尊重。
- **裁定（Task 2 实测，2026-10-21，见 `.superpowers/sdd/2026-10-21-multi-boot-version-support/task-2-report.md`）**：
  1. **gateway starter：复制为 `-boot3`（实测未通过）。** 共享 jar 在 Boot 3.5/SCG 2025.0 下任何请求都无法处理——Spring 6.x 删改了两个 reactive API，字节码级 NoSuchMethodError：①`ServerHttpRequest.getMethodValue()` 已被移除（`JwksEndpointFilter.java:56`、`EncryptorGatewayFilter.java:77`、`EncryptorResponseFilter.java:104/153`）；②`ServerHttpResponse.getStatusCode()` 返回类型 `HttpStatus`→`HttpStatusCode`（`EncryptorResponseFilter.java:151/159/167`）。JWKS 过滤器是 order -14 的 WebFilter，端到端链路在第一个请求即断连（client 侧表现为 PrematureClose），风险点 1/2 无法在共享 jar 上验证。**且注意：机械包名替换（Task 3 脚本）修不了这两处——boot3 复制对这两类调用点需源码级修改（`getMethod().name()`、`getResponseCode`/`HttpStatusCode` 口径），diff 守卫必须把这几处列入 whitelist，或由 Task 5 复制时人工修订并在守卫脚本中登记。**
  2. **reactive starter：共享（实测通过）。** Boot 3.5 下 `EncryptorReactiveAutoConfiguration` 正常装配（配置绑定/bean 接线/fail-fast 全部正常），协议栈行为对等（nibus 封送 → openRequest → encryptResponse → dir 解密 全绿，重放被 REPLAY 拒绝）该模块 main 源码无被删 API。
  3. **micrometer starter：共享（实测通过，带一条跟进项）。** 真实 Boot 3.5 应用（含 actuator）中 `@AutoConfigureAfter(MetricsAutoConfiguration)` 被尊重：listener 装配成功、计数器注册齐、真实协议调用驱动计数递增。跟进项：runner（局部 ApplicationContextRunner）发现仅声明 `AutoConfigureAfter(MetricsAutoConfiguration)` 与 boot 的 SimpleMetricsExport（真正提供 SimpleMeterRegistry bean 的配置）之间无排序约束，靠全量 imports 排序偶然落在其后——若上游调整该配置的排序，listener 会静默缺失；建议 Task 4/5 若建 micrometer-boot3 副本（或维持共享）时把 `@AutoConfigureAfter` 扩名到 `MetricsAutoConfiguration + SimpleMetricsExportAutoConfiguration` 两个名字（legacy name 形式，javax 线不动）。

### 6.3 jakarta 迁移的复制规则（web-starter / spring-boot3-starter 为主）

- **builder check 已核实（2026-10-21）**：`encryptor-web-starter` + `encryptor-starter` 的 main 源码 javax 引用**只有** `javax.servlet`（23 处）/ `javax.servlet.http`（16 处），无 `javax.annotation`/`naming`/`validation`——替换表只需 `javax.servlet`→`jakarta.servlet`（含 `AsyncContext/ReadListener/WriteListener` 直接对位）。注意机械改名意味着**容器代际同时换**（Tomcat 9→10.1），boot3 测试类路径差异不止 Spring 版本。
- 装配注册：**boot3 模块只用 `META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports`**——Boot 3 已完全移除 `spring.factories` 的 EnableAutoConfiguration 机制，不要再带旧文件。
- 类级注解可用 `@AutoConfiguration`（Boot 3 推荐），装配顺序注解（`@AutoConfigureAfter` 等）按 Boot 3 语义核对。
- servlet Web 已在 core 的 `WebContext` 等抽象（历史：JweContext/WebContext/GatewayContext 下沉），复制面应限于过滤器/上下文装配层薄壳；若发现复制体里出现协议逻辑，说明抽象线切错了位置，须回到 core 抽象而不是复制协议代码。

### 6.4 防漂移守卫（硬性 CI 要求）

- 每次 CI：对每个复制的模块对，将 javax 源码做**机械包名变换**（javax→jakarta 的白名单替换）后与 jakarta 模块源码 `diff`，必须逐字节一致（等价于现有两份 `jwe.js` 的 diff 守卫的扩展）。
- 变换脚本进仓库（如 `scripts/javax-to-jakarta.sh`），boot3 模块**不允许**手工 diff 之外的特殊源码（除装配注册文件差异，且该差异也在脚本里 whitelist）。builder check 补充的 whitelist 项：pom.xml（整文件）、`@AutoConfiguration` 与 legacy 顺序注解差异点。

### 6.5 测试对等

- javax 线现状用例全部保持、全绿。
- boot3 线：复制 web-starter/gateway-starter 的测试支撑与用例族（`SmJweTestSupport`⇄`SmGatewayTestSupport`、`ResponseFilterHardeningTest`⇄`GatewayJweTest` 模式），包名替换后跑通对等断言。
- `HttpTest.java` 的 JDK8 helper（`enc(String)`）在 boot3 测试里可放宽，但其两侧成对同步规则延伸到 boot3 副本（或验证后单份共享）。

### 6.6 示例 / bench / 发布面

- `encryptor-examples`（web-example / gateway-example）保留 javax 形态不动；是否新增 boot3 示例工程：**P1**（不是协议验证必需，但对用户体验明显加分，优先级由用户后续定）。若新增且需要 bootstrap/SCA 配置：BOM 固定的 `spring-cloud-starter-bootstrap:3.1.0`（javax 代）需对位 4.x 版本。
- Root profiles `all-modules`（activeByDefault）与 `main-module` 显式列举模块（`pom.xml:96-117`）：**boot3 模块不得加入这两个 profile**（JDK 8 无法编译 release-17 模块），必须独立 `-Pboot3` profile。Enforcer `requireJavaVersion [1.8,)` 在 JDK 17 下天然满足，无需改动。
- `encryptor-bench`：留在 javax 线（性能基线连续性优先），Boot 3 侧性能对比列为后续可选项。
- **发布面守卫**：core + 全部 starter（含 `-boot3`）的 runtime 依赖树守卫继续零 BC / 零 encryptor-sm；`-boot3` 模块允许 test scope 引 boot3 生态依赖。
- Maven 中央发布：`-boot3` 模块补 name/description 元数据（历史上走过 Central 校验坑，见 commit 96d2869/271c9ac）。

## 7. 已定决策（用户拍板，不再讨论）

| 决策 | 结论 |
| --- | --- |
| 分支模型 | 单分支 |
| 模块形态 | 每代独立 Maven 模块 |
| artifactId 策略 | `-boot3` 后缀（绑定 Spring 大版本，非 `-jakarta`） |
| 新线锚点 | Boot 3.5 + SC 2025.0 + SCA 2025.0，JDK 17/21（**两者都进 CI 矩阵**） |
| 新线版本起始 | `3.0.0`（与 Boot 代际对齐） |
| 共享 jar 裁定 | gateway starter：**复制**（Task 2 实测失败：`getMethodValue`/`getStatusCode` 两处 Spring 6 删改 → NoSuchMethodError，见 §6.2）；reactive：**共享**；micrometer：**共享**（跟进项：`@AutoConfigureAfter` 建议扩名到 SimpleMetricsExportAutoConfiguration） |
| 发布形态 | 混合版本（parent 1.0.0 + boot3 制品 3.0.0）先 spike 验证 `central-publishing` 可行性，不行再改版本方案 |
| 测试对等口径 | P0 = 安全关键子集（三载体往返/重放/篡改/失败面/配置绑定，约 30 个）；全量对等移植 = P2 跟进 |
| Boot patch 节奏 | 季度主动复盘 Boot 3.5.x / SC 2025.0.x / SCA patch 升级，CVE 随时插队 |
| Boot 4 / SC 2025.1 | non-goal，后续立项 |

## 8. 留给 builder 的部分

- 根 POM 双 BOM 共存的具体接线方式（基于 6.1 的验证选择）。
- reactive/gateway/micrometer 是否共享的最终拓扑（基于 6.2 验证）。
- 复制/变换脚本、CI job 编排、`-boot3` 模块 pom 细节。
- boot3 线集成测试的具体重心（在迁移中发现的问题清单沉淀）。

## 9. 交付定义（验收)

1. `mvn -B -Pmain-module clean install`（javax 线）全绿——现状不回退。
2. 新增命令（如 `mvn -B -Pboot3 clean install`）JDK 17 全绿。
3. 防漂移 diff 守卫在 CI 中执行且当前全一致。
4. README 选型表 + artifact 对照表。
5. 依赖树守卫扩展到 `-boot3` 模块。
