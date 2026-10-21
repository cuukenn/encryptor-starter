# encryptor-dependencies

> ⚠️ **本文是 v1 协议时代的架构记录（2026-10-16）；v2 JWE 协议重做（2026-10-17）后大部分内容已失效。**
> 当前事实以源码为准：入口 `AGENTS.md`，协议定义 `docs/superpowers/specs/2026-10-16-payload-security-protocol-design.md`，v1→v2 处置见 `open-issues.md`/`security-review.md` 顶部状态表。


> 纯 BOM 模块：集中管理本项目与三方库的版本，不产出任何代码。

| 项 | 值 |
| --- | --- |
| 目录 | `encryptor-dependencies/` |
| artifactId | `encryptor-dependencies`（`pom`） |
| 独立 groupId | `io.github.cuukenn`（注意：**没有**继承 `encryptor-parent`，是独立声明的 POM） |
| 被引用方式 | 根 `pom.xml` 以 `scope=import` 导入，因此全工程无需写版本号 |

## 管理的内容

本项目的可发布制品（版本 `${revision}`）：

| artifactId | 对应目录 |
| --- | --- |
| `encryptor-core` | `encryptor-core/` |
| `encryptor-sm` | `encryptor-sm/`（可选：国密 SM2/SM4-GCM + BouncyCastle） |
| `encryptor-spring-boot-starter` | `encryptor-starters/encryptor-starter/` |
| `encryptor-spring-boot-starter-reactive` | `encryptor-starters/encryptor-starter-reactive/` |
| `encryptor-web-spring-boot-starter` | `encryptor-starters/encryptor-web-starter/` |
| `encryptor-gateway-spring-boot-starter` | `encryptor-starters/encryptor-gateway-starter/` |
| `encryptor-micrometer-spring-boot-starter` | `encryptor-starters/encryptor-micrometer-starter/` |

三方依赖版本（属性定义在本模块 `<properties>` 里）：

| 依赖 | 版本 |
| --- | --- |
| `cn.hutool:hutool-all` | `5.8.25` |
| `org.bouncycastle:bcprov-jdk18on` | `1.78.1`（仅 `encryptor-sm` 使用） |
| `org.bouncycastle:bcpkix-jdk18on` | `1.78.1`（仅 `encryptor-sm` 使用） |
| `org.springframework.cloud:spring-cloud-starter-bootstrap` | `3.1.0` |

> **BouncyCastle 是显式可选依赖**：`encryptor-core` 与全部 starter 的 **compile/runtime** 依赖树里都没有 BouncyCastle
> （gateway 已排除 `spring-security-rsa` 传递的 `*-jdk15on`；starter 的 SM 集成测试只以 `test` scope 引入 bcprov）。
> 只有 `encryptor-sm`（国密）在 compile/runtime 依赖它，且不会被任何 starter 传递。
> 使用 `type: SM2` 的服务必须自己添加 `io.github.cuukenn:encryptor-sm`；缺失时启动期失败并提示该依赖。
> SM 路径只使用 BC 轻量级 API，不注册全局 JCA Provider。

Spring Boot / Spring Cloud / Spring Cloud Alibaba 的版本**不在这里**，而在根 `pom.xml`：`spring-boot 2.7.18`、`spring-cloud 2021.0.8`、`spring-cloud-alibaba 2021.1`。

## 常见任务

- **升级 hutool / bouncycastle**：只改本模块 `<properties>`（`hutool.version` / `bouncycastle.version`）。
- **升级 Spring Boot / Cloud**：改根 `pom.xml` 的属性。`META-INF/spring.factories`（已弃用）与 `META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports` 项目内已双注册（5 个 starter 各两份文件指向同一装配类）；删除 `spring.factories` 前需确认放弃 Boot < 2.7 兼容，并同步 5 个 starter。
- **新增一个 starter 制品**：必须同时在本模块补 `dependencyManagement` 条目，否则消费方要写版本号。

## 坑

- 本模块与根 POM 是**两个独立声明的 POM**（本模块自己写了 `groupId`/`version`），不要顺手给它加 `<parent>`，否则 `${revision}` 的解析路径会变（根 POM 用 `${project.version}` 指向它）。
- 本模块自身也重复声明了 `licenses`/`developers`/`scm` 以及 release 插件（`maven-source-plugin`、`maven-javadoc-plugin`、`maven-gpg-plugin`、`nexus-staging-maven-plugin`），改发布流程时要**两处一起看**（根 `pom.xml` 的 `release` profile 与这里）。
