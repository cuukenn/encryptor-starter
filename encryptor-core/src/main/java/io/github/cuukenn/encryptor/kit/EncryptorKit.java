package io.github.cuukenn.encryptor.kit;

import cn.hutool.core.util.IdUtil;
import io.github.cuukenn.encryptor.core.CheckerStrategy;
import io.github.cuukenn.encryptor.core.encoder.EncryptorEncoder;
import io.github.cuukenn.encryptor.core.encoder.SignerEncoder;
import io.github.cuukenn.encryptor.exception.EncryptorException;
import io.github.cuukenn.encryptor.pojo.EncryptorDataWrapper;

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
        final String sign = signerEncoder.sign((nonce + timestamp + encryptData).getBytes());
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
        final String encryptData = data.getData();
        final String nonce = data.getNonce();
        final long timestamp = data.getTimestamp();
        for (CheckerStrategy checkerStrategy : checkStrategies) {
            checkerStrategy.check(data);
        }
        boolean sigCheck = signerEncoder.verify(data.getSignature(), (nonce + timestamp + encryptData).getBytes());
        if (!sigCheck) {
            throw new EncryptorException("sig check error");
        }
        return encryptorEncoder.decrypt(encryptData);
    }
}
