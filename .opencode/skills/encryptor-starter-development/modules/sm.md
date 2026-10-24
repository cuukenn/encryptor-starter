# encryptor-sm 深潜（可选国密：SM2 封装 + SM4-GCM）

唯一允许依赖 BouncyCastle 的制品；用户显式添加，不被任何 starter 传递。

## 位置与接线

- `sm/SmCipherSuite.java`（`alg=SM2` + `enc=SM4-GCM`；经 `CipherSuite` 的 `META-INF/services` 被 `DefaultProtocol` 发现）与 `sm/SmKeyEntryParser.java`（经 `KeyEntryParser` SPI 接线；包名 `io.github.cuukenn.encryptor.sm`，与 core 的 `jose` 包不构成 split package）。

## 硬性限定

1. **只用 BC 轻量级 API，不注册全局 Provider**（库代码不改进程级状态）。
2. **core（main/test）与各 starter main 源码零 `org.bouncycastle`**；starter 的 SM 集成测试可用 `<scope>test</scope>` 的 encryptor-sm/bcprov，不得进 compile/runtime 树（CI 依赖树守卫）。
3. classpath 没有 encryptor-sm 时配置 SM2 密钥必须**启动期失败**并提示显式添加该依赖（`ServerKeyStore` 经 ServiceLoader 找解析器）。
4. 密钥解析：BC 自产 SM2 PKCS#8 可能是显式曲线参数而非命名 OID（`isSm2Algorithm` 兼容三形态）；曲线等价性比对阶/生成元/**a/b 模数值**（BC `FieldElement` 跨实例 equals 不可靠）；SPKI 公钥分支显式比对公钥曲线与私钥域参数；公私钥匹配用"私钥推导公钥逐点比对"。
5. SM2 解封前校验 `nativePrivateKey` 是 BC `ECPrivateKeyParameters`（不是则给 `ALG_NOT_ALLOWED` 精确分类，不让 NPE 退化成笼统失败）；SM4-GCM tag 失败异常带 BC cause。
6. enforcer 禁 `org.bouncycastle:*-jdk15on`（防与 `*-jdk18on` 双 BC 血统）——新增依赖不得把旧系列带回。

## sm 自检

- [ ] SM2 路径的套件/解析器改动同时考虑 `SmJweTestSupport` ↔ `SmGatewayTestSupport` 成对副本（见 `topics/sync-map.md`）。
- [ ] 示例验证：两示例自带 SM2 演示密钥，独立 SM 客户端（手拼 C1C3C2，不复用 core）打 `/test/sm.*`。
