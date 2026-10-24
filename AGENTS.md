# AGENTS.md

本文件**每次会话都会加载**，只放不可违反的强制约束——架构导航、模块表、双写面清单、构建命令、坑目录全部在 skill 里按需读取。**改本仓库任何代码/配置/POM 前，先读 `.opencode/skills/encryptor-starter-development/SKILL.md`**（触发本仓库开发任务时它会自动带出）。

## 这是什么（一句话）

报文层安全的 Spring Boot Starter 家族（v2/JWE 协议，RSA-OAEP-256 / ECDH-ES / 可选国密 SM2），javax 线 Java 8 与 boot3 复制线 Java 17 双线发布。

## 安全边界（不可越）

- **承诺**：机密性 + 完整性（AEAD）+ 现代算法 + 密钥轮换。**不承诺**客户端身份认证（TLS + Spring Security 承担；公钥公开是设计内 non-goal）。不是 TLS 的替代。

## 红线（违反即坏）

1. **core 零 Spring、零 `org.bouncycastle`**；BC 只允许出现在可选模块 `encryptor-sm`（且不注册全局 Provider、不被任何 starter 传递；enforcer 禁 `*-jdk15on`）。
2. **v1 残留必须 0 命中**：`EncryptorDataWrapper|AES_K|md5withaes|DigestWithEncryptSigner|GroupEncryptor|HexEncoder`。
3. **ReplayGuard 必须在 AEAD tag 校验之后调用**；`InMemoryNonceStore` retention ≥ 2·ttl 构造期强制。
4. **`Cipher` 非线程安全**——每次新建，不缓存单例；KDF 型 `CipherSuite` 必须覆写 `pairsWith`。
5. **epk 参与 AAD**（改 epk 解析口径 = 改 AAD）；ECDH 只支持 P-256；`apu`/`apv` 必须进 Concat-KDF；共享秘密左补零 32 字节。
6. **`JweContext.destroy()` 后 `cek()/plaintext()` 抛 `IllegalStateException`**——不得改回静默返回全零。
7. **协议演进通道唯一**：additive claim + 服务端软接受；`crit` 一律 fail-closed 拒绝；`typ` 是软锚点（`JweCodec.PROTOCOL_TYPE`，未知值不拒绝）。设计文档 §3.11 是契约。
8. **载体编解码只走 core `CarrierKit`**（QUERY 明文 = form 语义 urlencoded 且即完整 query；jwe 在 query 上一律按 QUERY 载体）——两侧门面不得再写本地实现。
9. **skip 机制只改 core `config/base/SkipListsConfigBase`**（两侧配置类只继承）；content-type 名单按 media-type 段（剥 `;` 参数、小写）整串正则匹配。
10. **`routes`/`crypto-config` 的键结构已固定**（`Map<正则, RouteRule>`、合并查找走 `RouteRule.effectiveKids`）——扩展只往 RouteRule 加字段，禁止改 Map 值类型。
11. **过滤器 order 全可配但相对链序启动期校验**（顺序错 = 启动失败而非静默明文）；网关下游必须是不带 encryptor 的普通应用。
12. **审计不双计**：codec 内失败由 `JweCodec` 回调、codec 外失败由过滤器补发；`EncryptorListener` 保持全 default 方法（API 演进范本）。
13. **双线成对发布**：只 bump root 的 `project.version` + `encryptor.javax.line.version`（boot3 pom 禁止字面量版本）；`scripts/check-dual-line-versions.sh` 守卫。**改 POM 必须兼容 Maven 3.9+**（pluginManagement 重复声明 = 硬错误）；`-Pmain-module,boot3` 不可组合。
14. **改 core 后先 `mvn -pl encryptor-core install -DskipTests`**——下游（reactive/gateway/boot3）编译解析的是 `~/.m2` 的 jar，不装会编到旧制品。
15. **架构导航按模块拆在 skill 内**（`modules/core|web|gateway|sm.md` + `topics/sync-map|build-and-release.md`，入口为该 skill 的 `SKILL.md` 路由表）：协议/双写面变更必读 `topics/sync-map.md`；改 POM/发版必读 `topics/build-and-release.md`；其余按模块加载对应文件。
16. **不写会变化的数字**（测试计数/基准数字/版本清单）进 AGENTS.md 与 skill——事实以 pom / 脚本 / CI 为准；历史明细只在 git log 与 CHANGELOG。

## 约定

注释/Javadoc 中文 + `@author changgg`；配置类 getter/setter（无 Lombok）；共享机制一律下沉 core `config/base` 继承；非法配置启动期 fail-fast。
