package io.github.cuukenn.encryptor.core.encryptor;

import io.github.cuukenn.encryptor.core.IEncryptorStrategy;
import io.github.cuukenn.encryptor.core.encoder.EncryptorEncoder;
import io.github.cuukenn.encryptor.exception.EncryptorException;

/**
 * 分组加解密
 *
 * @author changgg
 */
public class GroupEncryptor implements IEncryptorStrategy<byte[], String> {
    private final EncryptorEncoder delegate;
    private final String groupSplit;
    private final int groupSize;

    public GroupEncryptor(EncryptorEncoder delegate, int groupSize) {
        this.groupSplit = ".";
        this.delegate = delegate;
        if (groupSize <= 0) {
            throw new EncryptorException("groupSize cannot less then 0");
        }
        this.groupSize = groupSize;
    }

    public GroupEncryptor(EncryptorEncoder delegate, String groupSplit, int groupSize) {
        this.groupSplit = groupSplit;
        this.delegate = delegate;
        this.groupSize = groupSize;
    }

    @Override
    public String encrypt(byte[] data) {
        return null;
    }

    @Override
    public byte[] decrypt(String data) {
        return null;
    }
}
