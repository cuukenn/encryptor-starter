package io.github.cuukenn.encryptor.core.digester;

import cn.hutool.crypto.digest.Digester;
import io.github.cuukenn.encryptor.core.DigesterStrategy;

import java.util.function.Supplier;

/**
 * hutool内置摘要算法
 *
 * @author changgg
 */
public class HtlDigester implements DigesterStrategy {
    protected final Digester digester;

    public HtlDigester(Digester digester) {
        this.digester = digester;
    }

    public HtlDigester(Supplier<Digester> digester) {
        this.digester = digester.get();
    }

    @Override
    public byte[] digest(byte[] data) {
        return digester.digest(data);
    }
}
