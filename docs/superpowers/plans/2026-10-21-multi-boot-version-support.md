# 多 Spring Boot 版本支持（boot3 双线）Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 在单分支上并用两条产品线：现有 JDK 8 / Boot 2.7 / javax 线源码零扰动，新增 `-boot3` 系制品（JDK 17 / Boot 3.5 / jakarta），含 CI 双矩阵与防漂移守卫。

**Architecture:** 单 Maven reactor，新 `-Pboot3` profile 收纳新模块（不得进 `all-modules`/`main-module`）；boot3 模块以子模块覆写 `spring-boot.version`/`spring-cloud.version`/`spring-cloud-alibaba.version` 属性实现双 BOM；web/starter 两模块为"javax 源码 + 机械替换脚本"复制对，reactive/gateway/micrometer 先验证共享 jar（通过三风险点实测才免复制）。

**Tech Stack:** Java 8（javax 代）/ Java 17（boot3 代）、Maven 多模块、Spring Boot 2.7.18 vs 3.5.x、Spring Cloud 2021.0.8 vs 2025.0.x、SCA 2021.1 vs 2025.0.x。

**Spec:** `docs/superpowers/specs/2026-10-21-multi-boot-version-support-design.md`（读两份：plan 与 spec；冲突以 spec 为准）

## Global Constraints

- javax 线模块**源码零改动**；若被迫改动，commit 前先在任务里说明并停下问 owner。
- boot3 模块**不得**加入根 profiles `all-modules` / `main-module`（它们被 JDK 8 矩阵默认执行）。
- boot3 代版本锚点：`spring-boot.version=3.5.x`（执行时取 3.5 线最新 patch）、`spring-cloud.version=2025.0.x`、`spring-cloud-alibaba.version=2025.0.x`（同取最新）。
- boot3 模块注册文件只用 `META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports`；**禁止**带 `spring.factories`。
- 机械替换白名单：仅 `javax.servlet` → `jakarta.servlet`（含子包）；`pom.xml` 与 `@AutoConfiguration`/装配时序注解差异进替换脚本的 diff whitelist。
- 协议逻辑（core 的 JWE/AAD/防重放）禁止复制——一切复制面止于过滤器/装配层薄壳；发现协议语义漂移立即停。
- 复制对守卫：`scripts/javax-to-jakarta.sh` 生成 diff，CI 中必须逐字节一致。
- pull-out 依赖树守卫扩展到全部新模块：runtime 树零 `org.bouncycastle`、零 `encryptor-sm`。
- 提交信息沿用仓库 conventional 风格（`feat(...)`/`refactor(...)`/`ci(...)`）。

## Review Focus

1. **javax 线被意外改坏**（依赖树/行为变化）→ 不存在专门测试，靠 Task 1 先建基线：master 全绿 + `-Pall-modules -DskipTests package` 通过，任何后续任务若动了 javax 线 pom，重跑这两个命令；在 Task 1 加"基线快照"步骤（记录 `dependency:tree` 输出哈希），最终验收对比。
2. **boot3 模块被误进 JDK 8 构建** → `mvn -B -Pmain-module clean install` 在 JDK 8 下必须持续全绿；Task 4 的 CI job 把 `-Pmain-module` 设为第一步，JDK 8/11/17 三档都不许红。
3. **复制对漂移**（javax 与 boot3 源码失同步）→ Task 5 的 CI 守卫 job：变换后 diff 非空则 fail；本仓库 commit 前本地跑脚本 smoke。
4. **共享 jar 在 Boot 3.5 的 ordering/413/装配次序**（spec §6.2 三风险点）→ Task 3 建立的验证钩子测试（boot3 测试模块中的对应用例，见任务内步骤）。
5. **发布面混合版本**（parent 1.0.0 + boot3 3.0.0 经 central-publishing）→ Task 7 的 dry-run 发布验证，失败则按 spec §7 行动（改版本方案→回报 owner）。

---

### Task 1: 基线快照与 `-Pboot3` 空 profile

**Files:**
- Modify: `pom.xml`（root，只加 profile）

**Interfaces:**
- Produces: root profile id `boot3`（初始 `<modules>` 为空 + property 覆写样板）；后续所有新模块的加入点。

- [ ] **Step 1: 记录基线。** 跑 `mvn -B -Pmain-module clean install` 与 `mvn -B -Pall-modules -DskipTests package`，确认 BUILD SUCCESS；把两次输出尾部（Tests counts / BUILD 状态）粘贴到执行记录。

- [ ] **Step 2: 在根 `pom.xml` 加 `boot3` profile（不激活）：**

```xml
<profile>
  <id>boot3</id>
  <properties>
    <spring-boot.version>3.5.x-BUILDER-PIN</spring-boot.version>          <!-- pin 执行时 3.5 线最新 patch -->
    <spring-cloud.version>2025.0.x-BUILDER-PIN</spring-cloud.version>    <!-- pin 2025.0 线最新 -->
    <spring-cloud-alibaba.version>2025.0.x-BUILDER-PIN</spring-cloud-alibaba.version> <!-- pin 2025.0 线最新 -->
    <maven.compiler.source>17</maven.compiler.source>
    <maven.compiler.target>17</maven.compiler.target>
    <java.version>17</java.version>
  </properties>
  <modules>
  <!-- 新模块逐个加入 -->
  </modules>
</profile>
```

- [ ] **Step 3: property 覆写 spike（顺序：先这个，再写任何 boot3 模块）。** 用一个临时只读实验确认"子模块覆写 `spring-boot.version` 后其 BOM import 用子值"：在临时目录构造最小两模块 pom 模拟根 import + 子属性覆写，`mvn help:effective-pom` 验证。**如果失败**：记录输出，改用 spec §6.1 兜底（boot3 模块显式 dependencyManagement 三件套版本），并在执行记录中注明选择。

- [ ] **Step 4: 验证 javax 线未受影响。** 跑 `mvn -B -Pmain-module clean install`（BUILD SUCCESS，测试计数与 Step 1 相同）。

- [ ] **Step 5: Commit** `chore(pom): 新增 boot3 profile 骨架与版本锚点`。

### Task 2: 三个共享候选 jar 的 Boot 3.5 行为验证（决策型 spike）

**Files:**
- Create: `encryptor-examples/gateway-boot3-verify/`（**一次性验证工程**，不进 main-module/all-modules，验证后按"保留 or 删"问 owner；默认保留为 boot3 示例的起点）

**Interfaces:**
- Consumes: 现有 `encryptor-gateway-starter`（javax 代 jar，以 Boot 2.7 编译产物用于 Boot 3.5 运行时）、`encryptor-micrometer-starter`、`encryptor-starter-reactive`。
- Produces: 共享/复制裁定记录（写入 spec §6.2 处或执行记录），决定 Task 4/5 是否创建对应 `-boot3` 复制模块。

- [ ] **Step 1: 搭验证工程**：Spring Boot 3.5 应用，`spring-cloud-starter-gateway`（2025.0.x），依赖只引 `encryptor-reactive`/`gateway`/`micrometer` 三 jar（Maven 本地 install 版本 1.0.0 后引用）。

- [ ] **Step 2: 写三个风险点测试**（沿用 gateway-starter 现有 `GatewayJweTest` 的断言口径，环境换成 Boot 3.5 test 容器）：
  1. SCG ordering：加密响应过滤器必须仍在 Netty write（`WRITE_RESPONSE_FILTER_ORDER-1`）之前加密 `/api/a` 大响应路径；断言：响应体是有效 JWE 包络而非明文。
  2. 413：构超限请求，断言的是 `failure-status` 语义（Boot 3 下 `DataBufferLimitException` 仍能进 `onErrorResume` 分支）。
  3. 装配次序：`@AutoConfigureAfter(name="...MetricsAutoConfiguration")` 在 Boot 3 下仍被尊重（断言 Micrometer 指标在加密 listener 之前装配/注册，用 `MeterRegistry` 检查 counter 存在性）。

- [ ] **Step 3: 三个用例外加** spec §5 的"安全关键子集"里 reactive/gateway 相关的往返/重放/篡改用例各跑通。

- [ ] **Step 4: 记录裁定结果**（每模块：共享 / 复制），更新 spec §6.2 裁定行；**此步是 Task 4/5 的分叉点，不通过就复制**。

- [ ] **Step 5: Commit** `test(boot3): 共享 jar 兼容性验证工程与三风险点用例`。

### Task 3: `scripts/javax-to-jakarta.sh` 与复制对工程基建

**Files:**
- Create: `scripts/javax-to-jakarta.sh`（可执行）
- Test: `scripts/javax-to-jakarta.test.sh`（自测脚本：给定样例输入/期望输出）

**Interfaces:**
- Produces: 变换脚本（stdin: javax 源文件 → stdout: jakarta 源文件；diff 提供两侧逐字节一致性判定）；Task 4 的复制器与 CI 守卫都用它。

- [ ] **Step 1: 写自测样例**：put 几行含 `javax.servlet.http.HttpServletRequest`、`javax.servlet.AsyncContext`、`javax.crypto`（不动）、comment 里的字面 "javax.servlet"（替换：因注释也本应换）混合内容 → 期望输出样例。

- [ ] **Step 2: 实现脚本**：单向 sed/perl 白名单替换 `javax.servlet` → `jakarta.servlet`；提供 `--diff base/ copied/` 模式输出两目录（变换后）逐字节 diff；whitelist 文件参数默认排除 `pom.xml`（boot3 模块的 pom 结构差异是预期值，不算漂移）。

- [ ] **Step 3: 跑自测**：`bash scripts/javax-to-jakarta.test.sh` 全 PASS。

- [ ] **Step 4: Commit** `build(scripts): javax→jakarta 机械替换与复制对 diff 守卫`。

### Task 4: `encryptor-spring-boot3-starter` + `encryptor-web-boot3-starter` 复制对

**Files:**
- Create: `encryptor-starters/encryptor-spring-boot3-starter/pom.xml`、`src/main/resources/META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports`
- Create: `encryptor-starters/encryptor-web-boot3-starter/pom.xml`
- Modify: `pom.xml`（boot3 profile `<modules>` 加两模块）
- Test: 两模块各 `src/test/java/**`（从 javax 对位模块复制 + Task 3 脚本变换）

**Interfaces:**
- Consumes: Task 1 的 profile 与属性；Task 3 脚本；javax 线 `encryptor-starter` / `encryptor-web-starter` 的源码与测试。
- Produces: 两个 release-17 jar；版本 `3.0.0`（自家 `<version>`，parent 保持 root 1.0.0）；装配类包名不变（同 FQCN 不同 artifactId，两组件不相撞——Boot dedup 允许不同 line 的装配类同名共存于消费者 classpath，因为消费者只会引一条线的 starter，无同时引用场景）。

- [ ] **Step 1: 生成复制对**：`cp -R encryptor-starter encryptor-spring-boot3-starter && cp -R encryptor-web-starter encryptor-web-boot3-starter`，然后对 src/** 与 README 之外逐一过 Task 3 脚本变换（javax→jakarta），pom 各自改写：`<artifactId>` 换 boot3 名、`<version>3.0.0</version>`、加 `<properties>`（Task 1 属性继承，若 spike 失败则走显式 dependencyManagement 兜底）、显式 pin `maven-compiler-plugin` 版本（3.11+）。

- [ ] **Step 2: 移除** `src/main/resources/META-INF/spring.factories`（boot3 只有 imports）。

- [ ] **Step 3: 修 pom 依赖坐标**：依赖 core（1.0.0）不变；任何 starter 间依赖换成 `-boot3` 对位（如 web-boot3 依赖 spring-boot3-starter）。SCA/Cloud 依赖名不变（BOM 已换版本）。

- [ ] **Step 4: 对位测试跑通（安全关键子集，spec P0）**：复制并变换后的测试中**保留**：三载体往返（query/json/form）、重放拒绝、篡改拒绝、未知 kid、AAD 不匹配、失败面（413/黑名单/bypass）、配置绑定。**丢弃**非核心用例（P2 剩余）。跑 `mvn -B -Pboot3 -pl encryptor-starters/encryptor-spring-boot3-starter,encryptor-starters/encryptor-web-boot3-starter clean install`。

- [ ] **Step 5: Task 3 diff 守卫通过**：`bash scripts/javax-to-jakarta.sh --diff encryptor-starter/src encryptor-spring-boot3-starter/src` 等双向跑，0 差异（imports 装配文件不在 diff 范围——它是**同名内容**，也应一致，验证之）。

- [ ] **Step 6: Commit** `feat(boot3): 新建 encryptor-spring-boot3-starter 与 encryptor-web-boot3-starter（复制的 jakarta 对位）`。

### Task 5: reactive/gateway/micrometer 拓扑落地（共享 or 复制）+ 示例

**Files:**
- Create（若 Task 2 裁定复制）: `encryptor-starters/encryptor-gateway-boot3-starter/`、（同理 reactive-boot3、micrometer-boot3）
- Create（若裁定共享）: 无新模块，仅 Task 2 验证工程固化为 `encryptor-examples/boot3-example/`（P1，例程：web 简单接口 + gateway 转发链）
- Modify: `pom.xml`（boot3 profile modules 补齐）

**Interfaces:**
- Consumes: Task 2 裁定结论、Task 4 的模块构建模式。
- Produces: 完整 boot3 产物面（README 表可引用的最终 artifact 列表）。

- [ ] **Step 1: 按 Task 2 裁定执行**（复制路径 = 复用 Task 4 步骤 1-5 模式，模块名 `-boot3`；共享路径 = 无新模块，写 README 结论）。

- [ ] **Step 2: （共享路径）把 Task 2 验证工程重命名/整理为 `encryptor-examples/boot3-example`，纳入 boot3 profile**（可执行运行 + node 前端与生命周期对齐 javax examples 模式）；**复制路径则新建**（网关下游 `encryptor-examples/gateway-example/web` 保持 javax 不带 encryptor 的约束继续有效——boot3 网关示例的下游用**同一个**非加密 web 应用端口 8082，README 标注）。

- [ ] **Step 3: 跑 `mvn -B -Pboot3 clean install` 全模块（含新条目）→ BUILD SUCCESS**。

- [ ] **Step 4: 完整落 README 选型表**（对照 spec §7，注明各 artifact、对应的 JDK/Boot/Cloud 代际）。

- [ ] **Step 5: Commit** `feat(boot3): 补齐 reactive/gateway/micrometer 拓扑与 boot3 示例`。

### Task 6: CI 扩展（-Pboot3 双矩阵 JDK 17/21）

**Files:**
- Modify: `.github/workflows/ci.yml`

**Interfaces:**
- Consumes: Task 1 `boot3` profile（含模块列表）、Task 3 脚本、Task 4/5 测试。
- Produces: 三类新 job（boot3 构建、复制对 diff 守卫、依赖树守卫扩展）+ 现有 JDK 8/11/17 job 不变。

- [ ] **Step 1: 加一档 boot3 job：runs-on matrix `17`,`21`，steps = checkout/setup-java/maven boot3 profile 清理安装**（带 `-DtrimStackTrace=false`，测试失败时便于定位）。

- [ ] **Step 2: 在任一 boot3 job 中加 diff 守卫 step：** 跑 Task 3 脚本对每个复制对 diff（共享对不进此 step）。

- [ ] **Step 3: 依赖树守卫扩展**：现有 JDK 8 job 的 BC/encryptor-sm 守卫**保持原样**；boot3 job 新增同口径守卫（含新模块清单）。

- [ ] **Step 4: 验证三种本地命令全绿后推 CI**：JDK 11（javax 三档本就要跑）+ JDK 17/21 `-Pboot3`。

- [ ] **Step 5: Commit** `ci: 新增 boot3 双矩阵与复制对/依赖树守卫`。

### Task 7: 发布面验证 + 文档收尾

**Files:**
- Create: 发布/升级相关文档改动（README 选型表已在 Task 5；此处是发布校验与历史文档）
- Modify: `docs/architecture/encryptor-dependencies.md`（boot3 BOM 阶段性说明）、`AGENTS.md`（模块表加 boot3 行、"必须同步"双写面表加复制对共守卫规则）、`docs/architecture/open-issues-v2-history.md`（本设计来源与裁定记录）

**Interfaces:**
- Consumes: Task 4/5 的全部产物（版本与 artifact 进入发布验证范围）。
- Produces: 本设计在仓库文档体系中的完整落地。

- [ ] **Step 1: 混合版本发布 dry-run spike**：模拟 `central-publishing-maven-plugin` 上传（`-DskipTests package` 后对其 dryRun 模式跑一次——查插件支持的命令，如 `central-publishing-maven-plugin:publish -DdryRun`），验证 parent 1.0.0 + boot3 3.0.0 混合 reactor 上传可行性。**失败**按 spec §7 注（回报 owner、机构的可选项）。

- [ ] **Step 2: 完成三个附带交付**（`docs/architecture/encryptor-dependencies.md`、`AGENTS.md` 双写面表与§模块表、`open-issues-v2-history.md` 记录）。

- [ ] **Step 3: 全量回归（命根）：** `mvn -B -Pmain-module clean install` + `mvn -B -Pboot3 clean install` + `mvn -B -Pall-modules clean install`（虽然 boot3 不在 all-modules，仍要确保该 profile 无遗漏）三绿。

- [ ] **Step 4: Commit** `docs(boot3): 发布面验证与双代架构文档落地`。

---

## Self-Review

按 writing-plans 检查清单过一遍：

1. **Spec 覆盖**：spec §2 五条目标 → 任务对应：①javax 零扰动 = Task 1 基线 + 全程禁令；②新模块对等 = Task 2/4/5；③README 表 = Task 5 Step 4；④CI 双矩阵 = Task 6；⑤防漂移守卫 = Task 3+6。§6.1/6.2/6.3/6.4/6.5/6.6 逐条在任务内消化；发布面与文档 = Task 7。
2. **步骤扫描**：每步均为"写 X / 跑 X / 断言 X / commit"级别；spike 判定带明确失败分支。
3. **类型/名称一致**：profile id `boot3`、脚本名 `scripts/javax-to-jakarta.sh`、模块名 `-boot3` 后缀、版本 `3.0.0` 全程一致。
4. **Review Focus 均有 owner 任务**：①Task 1、②Task 4/6、③Task 5/6、④Task 2、⑤Task 7。
5. **篇幅比例**：plan 长度 ≈ spec 的 1.5 倍，代码块只承载结构/断言值，不贴实现。

## Execution Handoff

执行者读取 plan + spec 后按任务序执行；验证型任务（2）是分叉点，绝不先写复制模块再补验证。
