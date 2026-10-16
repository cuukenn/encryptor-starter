package io.github.cuukenn.encryptor.kit;

import cn.hutool.core.util.IdUtil;
import io.github.cuukenn.encryptor.core.CheckerStrategy;
import io.github.cuukenn.encryptor.core.encoder.EncryptorEncoder;
import io.github.cuukenn.encryptor.core.encoder.SignerEncoder;
import io.github.cuukenn.encryptor.exception.EncryptorException;
import io.github.cuukenn.encryptor.pojo.EncryptorDataWrapper;

import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.List;

/**
 * @author changgg
 */
public class EncryptorKit {
    public static EncryptorDataWrapper encrypt(EncryptorEncoder encryptorEncoder, SignerEncoder signerEncoder, byte[] data, String key) {
        final String encryptData = encryptorEncoder.encrypt(data);
        final String nonce = IdUtil.fastSimpleUUID();
        final long timestamp = System.currentTimeMillis();
        final String sign = signerEncoder.sign((nonce + timestamp + encryptData).getBytes(StandardCharsets.UTF_8));
        return new EncryptorDataWrapper(
                nonce, timestamp, sign,
                key,
                encryptData
        );
    }

    public static byte[] decrypt(EncryptorEncoder encryptorEncoder, SignerEncoder signerEncoder, EncryptorDataWrapper data) {
        return decrypt(encryptorEncoder, signerEncoder, Collections.emptyList(), data);
    }

    public static byte[] decrypt(EncryptorEncoder encryptorEncoder, SignerEncoder signerEncoder, List<CheckerStrategy> checkStrategies, EncryptorDataWrapper data) {
        if (data == null) {
            throw new EncryptorException("request body is missing");
        }
        final String encryptData = data.getData();
        final String nonce = data.getNonce();
        final Long timestamp = data.getTimestamp();
        // 字段缺失必须在拆箱/进加密库之前拦住：否则 timestamp 拆箱 NPE、签名解码会抛 CryptoException，
        // 调用方拿到的是无法分类的 500，而不是"报文非法"
        if (nonce == null || timestamp == null || encryptData == null || data.getSignature() == null) {
            throw new EncryptorException("request field is missing: nonce/timestamp/signature/data must be present");
        }
        for (CheckerStrategy checkerStrategy : checkStrategies) {
            checkerStrategy.check(data);
        }
        boolean sigCheck = signerEncoder.verify(data.getSignature(), (nonce + timestamp + encryptData).getBytes(StandardCharsets.UTF_8));
        if (!sigCheck) {
            throw new EncryptorException("sig check error");
        }
        return encryptorEncoder.decrypt(encryptData);
    }
}
