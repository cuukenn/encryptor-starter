package io.github.cuukenn.encryptor.facade;

import io.github.cuukenn.encryptor.core.CheckerStrategy;
import io.github.cuukenn.encryptor.core.encoder.EncryptorEncoder;
import io.github.cuukenn.encryptor.core.encoder.SignerEncoder;
import io.github.cuukenn.encryptor.kit.EncryptorKit;
import io.github.cuukenn.encryptor.pojo.EncryptorDataWrapper;

import java.util.List;
import java.util.function.Function;

/**
 * @author changgg
 */
public class EncryptorFacade {
    private final EncryptorEncoder negotiateEncoder;
    private final Function<String, EncryptorEncoder> encryptorEncoder;
    private final Function<String, SignerEncoder> signerEncoder;
    private final List<CheckerStrategy> checkerStrategies;

    public EncryptorFacade(EncryptorEncoder negotiateEncoder, Function<String, EncryptorEncoder> encryptorEncoder, Function<String, SignerEncoder> signerEncoder, List<CheckerStrategy> checkerStrategies) {
        this.negotiateEncoder = negotiateEncoder;
        this.encryptorEncoder = encryptorEncoder;
        this.signerEncoder = signerEncoder;
        this.checkerStrategies = checkerStrategies;
    }

    public EncryptorDataWrapper encrypt(String data, String key) {
        final String params = negotiateEncoder.decrypt(key);
        EncryptorEncoder encryptorEncoderL = encryptorEncoder.apply(params);
        SignerEncoder signerEncoderL = signerEncoder.apply(params);
        return EncryptorKit.encrypt(encryptorEncoderL, signerEncoderL, data, key);
    }

    public String decrypt(EncryptorDataWrapper data) {
        final String params = negotiateEncoder.decrypt(data.getKey());
        EncryptorEncoder encryptorEncoderL = encryptorEncoder.apply(params);
        SignerEncoder signerEncoderL = signerEncoder.apply(params);
        return EncryptorKit.decrypt(encryptorEncoderL, signerEncoderL, checkerStrategies, data);
    }
}
