package io.github.cuukenn.encryptor.core.encryptor;

import cn.hutool.core.util.StrUtil;
import io.github.cuukenn.encryptor.exception.EncryptorException;
import io.github.cuukenn.encryptor.core.IEncryptorStrategy;
import io.github.cuukenn.encryptor.core.encoder.EncryptorEncoder;

import java.util.Arrays;
import java.util.stream.Collectors;

/**
 * 分组加解密
 *
 * @author changgg
 */
public class GroupEncryptor implements IEncryptorStrategy<String, String> {
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
    public String encrypt(String data) {
        return Arrays.stream(StrUtil.cut(data, groupSize)).map(delegate::encrypt).collect(Collectors.joining(groupSplit));
    }

    @Override
    public String decrypt(String data) {
        return StrUtil.split(data, groupSplit).stream().map(delegate::decrypt).collect(Collectors.joining());
    }
}
