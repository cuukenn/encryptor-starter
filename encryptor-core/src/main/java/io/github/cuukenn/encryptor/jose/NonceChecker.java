package io.github.cuukenn.encryptor.jose;

/**
 * nonce 一次性校验 SPI。
 *
 * <p>实现必须保证"检查 + 占用"是<b>原子</b>的：并发下同一个 nonce 只能有一个调用者得到 {@code true}。
 * 单机实现见 {@link InMemoryNonceStore}；多实例部署需换成 Redis 等共享存储实现。
 *
 * @author changgg
 */
public interface NonceChecker {

    /**
     * 原子地检查并占用一个 nonce。
     *
     * @return {@code true} = 此前未出现过（已成功占用）；{@code false} = 已经用过（重放）
     */
    boolean consume(String nonce);
}
