# boot3 线（Jakarta / Spring Boot 3.5）

> 面向维护者：javax 线（`master` 默认）与 boot3 线共用同一份 core，starter 以复制对维持两套 Servlet API。
> 事实入口仍是 `AGENTS.md`；本文只汇总 boot3 独有的结构。

## 模块与坐标

| 目录 | artifactId | 版本 | 来源 |
| --- | --- | --- | --- |
| `encryptor-starters/encryptor-spring-boot3-starter/` | `encryptor-spring-boot3-starter` | `3.0.0` | 复制自 `encryptor-starter` |
| `encryptor-starters/encryptor-web-boot3-starter/` | `encryptor-web-boot3-starter` | `3.0.0` | 复制自 `encryptor-web-starter` |
| `encryptor-starters/encryptor-gateway-boot3-starter/` | `encryptor-gateway-boot3-starter` | `3.0.0` | 复制自 `encryptor-gateway-starter` |
| `encryptor-examples/boot3-example/` | `boot3-gateway-example` | — | 端到端示例（不发布） |

- `encryptor-core`、`encryptor-spring-boot-starter-reactive`、`encryptor-micrometer-spring-boot-starter` **没有** boot3 副本：main 源码零 `javax.*`，Boot 3.5 直接复用 1.0.0 制品。
- boot3 reactor 不含 core，构建前必须先把 javax 线制品装进 `~/.m2`。

## 构建与验证

```bash
# 1) 预装 javax 线制品（core / reactive / micrometer / BOM）
mvn -B -Pmain-module -DskipTests clean install
# 2) boot3 线（JDK 17/21）
JAVA_HOME=…/jdk-17 mvn -B -Pboot3 clean install
```

⚠️ `-Pmain-module,boot3` 不能同时激活：boot3 profile 的 `spring-boot.version=3.5.16` 等属性会污染整个 reactor，掀掉 javax 线 BOM 锚点。

## 复制对守卫

`scripts/javax-to-jakarta.sh --diff <javax>/src <boot3>/src --exclude spring.factories`

- 变换规则：`javax.servlet` → `jakarta.servlet`；逐字节比对。
- starter 对 9 文件、web 对 25 文件零豁免；gateway 对 15 文件 + 3 个 `--expect-diff` 人审文件（`EncryptorGatewayFilter` / `EncryptorResponseFilter` / `JwksEndpointFilter`，只有 Spring 6 API 签名差异）。
- 守卫脚本自测：`bash scripts/javax-to-jakarta.test.sh`（37 例，CI 已接入）。
- 改 javax 侧任一文件 → 必须脚本同步 boot3 对位，否则 CI 红。

## CI 与发布

- `.github/workflows/ci.yml` 的 `boot3` job：JDK 17/21 矩阵，先预装 javax 制品，再 `-Pboot3 clean install`；复制对与依赖树守卫只在 17 档跑一次。
- `publish.yml` 目前**只发 javax 线**；boot3 三坐标尚未纳入发布流水线，升级/发布需单独执行（见 `AGENTS.md`「发布面」）。
