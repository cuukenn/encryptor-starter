package io.github.cuukenn.encryptor.core.encryptor;

import io.github.cuukenn.encryptor.core.IEncryptorStrategy;
import io.github.cuukenn.encryptor.core.encoder.EncryptorEncoder;
import io.github.cuukenn.encryptor.exception.EncryptorException;

import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Pattern;

/**
 * 分组加解密：把明文按 groupSize 切成若干组分别加密，再用 groupSplit 拼接
 *
 * @author changgg
 */
public class GroupEncryptor implements IEncryptorStrategy<byte[], String> {
    private final EncryptorEncoder delegate;
    private final String groupSplit;
    private final int groupSize;

    public GroupEncryptor(EncryptorEncoder delegate, int groupSize) {
        this(delegate, ".", groupSize);
    }

    public GroupEncryptor(EncryptorEncoder delegate, String groupSplit, int groupSize) {
        if (groupSize <= 0) {
            throw new EncryptorException("groupSize cannot less then 0");
        }
        this.groupSplit = groupSplit;
        this.delegate = delegate;
        this.groupSize = groupSize;
    }

    @Override
    public String encrypt(byte[] data) {
        if (data == null || data.length == 0) {
            return "";
        }
        List<String> groups = new ArrayList<>((data.length + groupSize - 1) / groupSize);
        for (int i = 0; i < data.length; i += groupSize) {
            groups.add(delegate.encrypt(Arrays.copyOfRange(data, i, Math.min(data.length, i + groupSize))));
        }
        return String.join(groupSplit, groups);
    }

    @Override
    public byte[] decrypt(String data) {
        if (data == null || data.isEmpty()) {
            return new byte[0];
        }
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        for (String group : data.split(Pattern.quote(groupSplit))) {
            byte[] groupData = delegate.decrypt(group);
            output.write(groupData, 0, groupData.length);
        }
        return output.toByteArray();
    }
}
