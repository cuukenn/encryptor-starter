# 构建、CI 守卫与双线发布

## 构建命令

```bash
mvn -B -Pmain-module clean install     # dependencies/core/starters（最低限度）
mvn -B -Pall-modules clean install     # 全量（含 examples + JMH bench）
mvn -B -Pboot3 clean install           # boot3 线（reactor 不含 core，需先 install 过 javax 线制品）
mvn -pl encryptor-core test            # 单模块（改 core 后先 install -DskipTests，下游用本地仓库 jar）
java -jar encryptor-bench/target/bench.jar -wi 2 -i 3 -f 1 -prof gc -rf json -rff encryptor-bench/target/bench.json && encryptor-bench/check-thresholds.sh
```

## 构建环境限定

- 本机 Maven 在 `/usr/local/maven/`（不在 PATH）；brew 的 Maven 可交叉验证。**改 POM 必须兼容 Maven 3.9+**：`pluginManagement` 同一插件重复声明是硬错误（3.8 仅告警覆盖）——改后双版本各跑一次。
- 根 pom 无 checkstyle/spotless；surefire 版本被 root pom 固定（与 JUnit Platform 组合的假绿坑见 pom 注释），boot3 复制对 pom 各自 pin——不要解析到 root 的版本。
- `**/HttpTest.java` 被 surefire 排除；`examples/*/front/test.js` 需先起服务。surefire 默认 `trimStackTrace=true`，定位失败加 `-DtrimStackTrace=false`。
- ⚠️ `-Pmain-module,boot3` 组合激活会把 boot3 版本属性混进整个 reactor——两条命令分先后跑。

## JMH / bench 限定

- `EcdhEsBenchmark` 必须显式传 `allowedAlgs={ECDH-ES}`（空集合取协议默认 → 构造期 fail-fast）。
- JMH setup 失败只打日志、**exit code 仍 0**——必须看 `check-thresholds.sh` 输出，不能只看退出码。
- 阈值脚本故意不进 CI（共享 runner 噪声）；阈值与口径以脚本为准（RSA 并行度、bytes/op 基线、ECDH 比率与 ReplayGuard 为 INFO 行）。

## 双线发布（必须成对）

- 发版只 bump root 的 `project.version` + `encryptor.javax.line.version`（boot3 pom 的 BOM/core 引用一律走该 property，**禁止字面量**——否则 core 修复漏发 boot3 线）。
- `scripts/check-dual-line-versions.sh`（CI 已接）断言三者一致；CHANGELOG 顶部有成对发布约定（javax 1.x ⇔ boot3 3.x 同一变更列车，条目成对标注）。
- `publish.yml` 只发 javax 线；boot3 线 deploy 命令与发布面结论见 `docs/architecture/open-issues-v2-history.md`。

## CI 守卫清单（数字以 CI 为准）

`.github/workflows/ci.yml`（JDK 矩阵与 profile 以文件为准）：双线构建测试、boot3 复制对 diff、jwe.js pairwise、`EncryptorConstant` parity、servlet↔reactive 结构 parity（常量值 / skip-base 继承 / 装配 bean 面）、双线版本守卫、BC 依赖树（javax 与 boot3 两档——core 与各 starter 的 runtime 树不得出现 BC 或 encryptor-sm）、守卫脚本自测。
