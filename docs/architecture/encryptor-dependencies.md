# encryptor-dependencies

> 纯 BOM 模块：集中管理本项目与三方库的版本，不产出任何代码。

| 项 | 值 |
| --- | --- |
| 目录 | `encryptor-dependencies/` |
| artifactId | `encryptor-dependencies`（`pom`） |
| 独立 groupId | `io.github.cuukenn`（注意：**没有**继承 `encryptor-parent`，是独立声明的 POM） |
| 被引用方式 | 根 `pom.xml` 以 `scope=import` 导入，因此全工程无需写版本号 |

## 管理的内容

本项目的四个可发布制品（版本 `${revision}`）：

| artifactId | 对应目录 |
| --- | --- |
| `encryptor-core` | `encryptor-core/` |
| `encryptor-spring-boot-starter` | `encryptor-starters/encryptor-starter/` |
| `encryptor-spring-boot-starter-reactive` | `encryptor-starters/encryptor-starter-reactive/` |
| `encryptor-web-spring-boot-starter` | `encryptor-starters/encryptor-web-starter/` |
| `encryptor-gateway-spring-boot-starter` | `encryptor-starters/encryptor-gateway-starter/` |

三方依赖版本（属性定义在本模块 `<properties>` 里）：

| 依赖 | 版本 |
| --- | --- |
| `cn.hutool:hutool-all` | `5.8.25` |
| `org.bouncycastle:bcpkix-jdk18on` | `1.78.1` |
| `org.springframework.cloud:spring-cloud-starter-bootstrap` | `3.1.0` |

Spring Boot / Spring Cloud / Spring Cloud Alibaba 的版本**不在这里**，而在根 `pom.xml`：`spring-boot 2.4.2`、`spring-cloud 2020.0.1`、`spring-cloud-alibaba 2021.1`。

## 常见任务

- **升级 hutool / bouncycastle**：只改本模块 `<properties>`（或对应 `<version>`）。
- **升级 Spring Boot / Cloud**：改根 `pom.xml` 的属性，注意 Boot 2.4.2 仍然使用 `META-INF/spring.factories` 做自动装配（不是 `AutoConfiguration.imports`），升级到 2.7+ 后需要同步迁移四个 starter 的 `spring.factories`。
- **新增一个 starter 制品**：必须同时在本模块补 `dependencyManagement` 条目，否则消费方要写版本号。

## 坑

- 本模块与根 POM 是**两个独立声明的 POM**（本模块自己写了 `groupId`/`version`），不要顺手给它加 `<parent>`，否则 `${revision}` 的解析路径会变（根 POM 用 `${project.version}` 指向它）。
- 本模块自身也重复声明了 `licenses`/`developers`/`scm` 以及 release 插件（`maven-source-plugin`、`maven-javadoc-plugin`、`maven-gpg-plugin`、`nexus-staging-maven-plugin`），改发布流程时要**两处一起看**（根 `pom.xml` 的 `release` profile 与这里）。
