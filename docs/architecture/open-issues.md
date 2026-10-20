# 已知问题与可修改点（Open Issues）

> 📌 **v2 状态表（2026-10-17，JWE 协议重做后复核）**：v1 时代的逐条记录已归档，本文只保留状态表与 v2 之后的复查记录。除标注"仍开放"外，其余条目问题已不复存在（所在代码已删或行为已重写）。
>
> | 条目 | v2 处置 | 说明 |
> | --- | --- | --- |
> | P0-1 | 🟩 消除 | uri 级配置重做为 kid 白名单（`crypto-config` → Map&lt;String,List&lt;String&gt;&gt;），有绑定回归测试 |
> | P0-2、P0-3、P0-6、P0-7 | 🟩 消除 | 所在代码（reactive 加密路径/pom 残留/常量撞值/EncryptorKit）已删 |
> | P0-4、P0-5、P1-1 | 🟩 消除 | v2 防重放默认开启：`ReplayGuard` 对称时间窗 + `InMemoryNonceStore.compute` 原子消费，且在 GCM tag 校验后 |
> | P1-2 | 🟩 消除 | v2 熵源：客户端 WebCrypto `getRandomValues`，服务端 `SecureRandom` |
> | P1-3、P1-4、P1-6 | 🟩 消除 | v2 无 MD5/无 PKCS1v15/客户端不可选算法（白名单在 codec 内强制） |
> | P1-5、P1-7、P1-8 | 🟩 消除 | 统一 UTF-8；JWE 结构解析；WebContext 入口重置 + 最外层 clear |
> | P1-9、P1-10、P1-11 | 🟩 消除 | 响应过滤器链后判黑名单；converter 已删；请求视图单一来源（明文） |
> | P1-12、P1-13 | 🟩 消除 | `EncryptorFailure` 分类 + 统一 failure-status + traceId；max-request/response-size 两侧强制 + 有界执行器 |
> | P2-1、P2-4、P2-6 | 🟩 消除 | HttpTest 真断言；GroupEncryptor 已删；surefire 固定 2.22.2 |
> | P2-5 | 🟩 消除 | 三载体（query/JSON/form）统一为单字段 `jwe` |
> | P2-7、P2-8、P2-9、P2-10 | 🟩 消除 | 密钥库缓存已解析密钥 + 每次新建 Cipher；死代码/伪签名栈/ComponentScan 全删 |
> | P3-1、P3-2、P3-3 | 🟩 消除 | AGENTS.md/README 已按 v2 重写 |
> | P3-6、P3-7 | 🟩 消除 | StrKit 正则缓存 + 确定性保留；`[key]` 括号写法有绑定回归测试 |
> | P3-8 | 🟩 保持 | enforcer/工程卫生仍在 |
> | P2-2 | ⚠️ 仍开放 | CI 是否覆盖新模块（bench 不随发布）待确认，非协议问题 |
> | P2-3 | ⚠️ 仍开放 | 两份 `jwe.js`（web/gateway 示例）仍对称复制，接受（无共享发布物） |
> | P3-4 | 🟩 已修（2026-10-18） | 名单正名 `skip-*`（命中即跳过），旧名 `black-*` 保留为**弃用 alias**（启动 WARN、新旧合并去重、绑定测试钉死） |
> | P3-5 | 🟩 已修（2026-10-18） | 改为 `.github/ISSUE_TEMPLATE/bug_report.md`（front-matter 形式）；`pull_request_template.md` 本就在规范路径 |
>

> 📦 v1 原始记录：[docs/archive/open-issues-v1.md](../archive/open-issues-v1.md)；v2 之后的复查记录：[open-issues-v2-history.md](open-issues-v2-history.md)。
