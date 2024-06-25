package io.github.cuukenn.encryptor.core;

import io.github.cuukenn.encryptor.pojo.EncryptorDataWrapper;

/**
 * @author changgg
 */
public interface CheckerStrategy {
    void check(EncryptorDataWrapper data);
}
