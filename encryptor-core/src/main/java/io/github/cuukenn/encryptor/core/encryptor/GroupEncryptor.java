package io.github.cuukenn.encryptor.core.encryptor;

import io.github.cuukenn.encryptor.core.IEncryptorStrategy;
import io.github.cuukenn.encryptor.core.encoder.EncryptorEncoder;
import io.github.cuukenn.encryptor.exception.EncryptorException;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/**
 * 分组加解密：整段数据**只加密一次**，再按 groupSize 把编码后的密文切成若干分片，用 groupSplit 拼接。
 * <p>
 * 分组只影响传输分片，不影响加密粒度 —— 避免"按明文分组各自加密"退化成分组 ECB、
 * 让相同的明文分组产生相同的密文分组（泄漏明文结构）。
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
        return String.join(groupSplit, split(delegate.encrypt(data)));
    }

    @Override
    public byte[] decrypt(String data) {
        if (data == null || data.isEmpty()) {
            return new byte[0];
        }
        StringBuilder cipher = new StringBuilder(data.length());
        for (String group : data.split(Pattern.quote(groupSplit))) {
            cipher.append(group);
        }
        return delegate.decrypt(cipher.toString());
    }

    /**
     * 按 groupSize 把编码后的密文切成传输分片，最后一片允许不足 groupSize。
     */
    private List<String> split(String cipher) {
        List<String> groups = new ArrayList<>((cipher.length() + groupSize - 1) / groupSize);
        for (int i = 0; i < cipher.length(); i += groupSize) {
            groups.add(cipher.substring(i, Math.min(cipher.length(), i + groupSize)));
        }
        return groups;
    }
}
