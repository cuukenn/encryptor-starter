package io.github.cuukenn.encryptor.jose;

/**
 * 可选密钥类型的解析 SPI（通过 {@link java.util.ServiceLoader} 发现）。
 *
 * <p>core 内置 RSA（JCE）与 EC（P-256/JCE）两种解析；其他类型（例如国密 SM2）由独立的
 * {@code encryptor-sm} 模块提供实现，并在 jar 里放
 * {@code META-INF/services/io.github.cuukenn.encryptor.jose.KeyEntryParser}。
 * 这样 core 与各 starter 的依赖面保持零 BouncyCastle，而 SM2 用户只需显式添加
 * {@code io.github.cuukenn:encryptor-sm}。</p>
 *
 * <p>实现必须是线程安全且无状态的：{@link ServerKeyStore.Builder} 只会在启动期调用一次。</p>
 *
 * @author changgg
 */
public interface KeyEntryParser {

    /** 是否支持该密钥类型。 */
    boolean supports(KeyType type);

    /**
     * 解析一把密钥（启动期 fail-fast）。
     *
     * @param kid              密钥标识
     * @param privateKeyBase64 私钥（PKCS#8 DER 的 base64；具体类型自行解释）
     * @param publicKeyBase64  公钥（SPKI DER 的 base64；SM2 也允许裸 64 字节 x||y）
     * @return 解析并校验（曲线/公私钥配对）后的条目
     * @throws RuntimeException 解析失败；{@link io.github.cuukenn.encryptor.exception.EncryptorException}
     *                          会被 {@link ServerKeyStore.Builder#add(String, String, String, KeyType)} 原样透出
     */
    KeyEntry parse(String kid, String privateKeyBase64, String publicKeyBase64);
}
