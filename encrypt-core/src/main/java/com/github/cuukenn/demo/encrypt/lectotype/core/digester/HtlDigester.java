package com.github.cuukenn.demo.encrypt.lectotype.core.digester;

import cn.hutool.crypto.digest.Digester;
import com.github.cuukenn.demo.encrypt.lectotype.DigesterStrategy;

import java.util.function.Supplier;

/**
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
