package com.github.cuukenn.demo.encrypt.lectotype.core.digester;

import cn.hutool.crypto.digest.Digester;
import com.github.cuukenn.demo.encrypt.lectotype.core.DigesterStrategy;

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
