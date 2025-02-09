package io.github.cuukenn.encryptor.core;

/**
 * @author changgg
 */
public interface ISignerStrategy<I, O> {
    /**
     * 验证签名
     *
     * @return 校验结果
     */
    boolean verify(I signature, O data);

    /**
     * 签名
     *
     * @return 签名
     */
    I sign(O data);
}
