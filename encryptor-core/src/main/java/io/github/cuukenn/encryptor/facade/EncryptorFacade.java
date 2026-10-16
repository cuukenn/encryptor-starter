package io.github.cuukenn.encryptor.facade;

import io.github.cuukenn.encryptor.core.CheckerStrategy;
import io.github.cuukenn.encryptor.core.encoder.EncryptorEncoder;
import io.github.cuukenn.encryptor.core.encoder.SignerEncoder;
import io.github.cuukenn.encryptor.exception.EncryptorException;
import io.github.cuukenn.encryptor.kit.EncryptorKit;
import io.github.cuukenn.encryptor.pojo.EncryptorDataWrapper;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;

/**
 * @author changgg
 */
public class EncryptorFacade {
    /**
     * 协商参数记忆的默认容量上限。
     *
     * <p>报文里的 {@code key} 来自未认证的客户端，逐个 key 记忆会把内存打爆，
     * 所以容量到顶后整体 {@link ConcurrentHashMap#clear()}（见 {@link #negotiateParams(String)}）。</p>
     */
    static final int DEFAULT_PARAMS_CACHE_CAPACITY = 1024;

    private final EncryptorEncoder negotiateEncoder;
    private final Function<String, EncryptorEncoder> encryptorEncoder;
    private final Function<String, SignerEncoder> signerEncoder;
    private final List<CheckerStrategy> checkerStrategies;
    /**
     * 容量上限（可注入，便于用小容量单测验证有界性）。
     */
    private final int paramsCacheCapacity;
    /**
     * {@code key} → 已用 RSA 私钥解出的协商参数 JSON 的记忆。
     *
     * <p>请求方向（{@link #decrypt}）解出参数后放入，响应方向（{@link #encrypt}）先查，
     * 命中就跳过第二次 RSA 私钥运算——一个加解密往返原本要跑 2 次 RSA，现在只跑 1 次。
     * 语义不变：同一个 {@code key} 必然解出同一份参数。</p>
     */
    private final ConcurrentHashMap<String, String> paramsCache;

    public EncryptorFacade(EncryptorEncoder negotiateEncoder, Function<String, EncryptorEncoder> encryptorEncoder, Function<String, SignerEncoder> signerEncoder, List<CheckerStrategy> checkerStrategies) {
        this(negotiateEncoder, encryptorEncoder, signerEncoder, checkerStrategies, DEFAULT_PARAMS_CACHE_CAPACITY);
    }

    /**
     * 记忆容量可注入版本（包内可见，供测试用小容量验证有界性；正式装配走 4 参构造器用默认容量）。
     */
    EncryptorFacade(EncryptorEncoder negotiateEncoder, Function<String, EncryptorEncoder> encryptorEncoder, Function<String, SignerEncoder> signerEncoder, List<CheckerStrategy> checkerStrategies, int paramsCacheCapacity) {
        this.negotiateEncoder = negotiateEncoder;
        this.encryptorEncoder = encryptorEncoder;
        this.signerEncoder = signerEncoder;
        this.checkerStrategies = checkerStrategies;
        this.paramsCacheCapacity = Math.max(1, paramsCacheCapacity);
        this.paramsCache = new ConcurrentHashMap<>(Math.min(this.paramsCacheCapacity, 64));
    }

    public EncryptorDataWrapper encrypt(byte[] data, String key) {
        // 明文请求（没有协商过 key）走到响应加密时要在 RSA 之前拦住，否则客户端拿到的是 hutool 的 NPE
        if (key == null) {
            throw new EncryptorException("request key is missing: the negotiated key must be present");
        }
        try {
            final String params = negotiateParams(key);
            EncryptorEncoder encryptorEncoderL = encryptorEncoder.apply(params);
            SignerEncoder signerEncoderL = signerEncoder.apply(params);
            return EncryptorKit.encrypt(encryptorEncoderL, signerEncoderL, data, key);
        } catch (EncryptorException e) {
            throw e;
        } catch (RuntimeException e) {
            // 统一错误面：密钥不可用 / 参数 JSON 非法 / 加密失败，对调用方都是同一个"响应加密失败"
            // （原始异常保留在 cause 里，服务端排查不受影响）
            throw new EncryptorException("response encrypt failed: the negotiated key is not usable", e);
        }
    }

    public byte[] decrypt(EncryptorDataWrapper data) {
        // key 要在 RSA 解密之前拦住：否则 null 会变成 hutool 内部的 CryptoException(NPE)
        if (data == null || data.getKey() == null) {
            throw new EncryptorException("request key is missing: the negotiated key must be present");
        }
        try {
            final String params = negotiateParams(data.getKey());
            EncryptorEncoder encryptorEncoderL = encryptorEncoder.apply(params);
            SignerEncoder signerEncoderL = signerEncoder.apply(params);
            return EncryptorKit.decrypt(encryptorEncoderL, signerEncoderL, checkerStrategies, data);
        } catch (EncryptorException e) {
            throw e;
        } catch (RuntimeException e) {
            // 统一错误面：key 不是合法 RSA 密文、签名长度不对（填充/块长错误）、密文解不开……
            // 全是"这份报文解不开"，不要把它们作为 CryptoException 漏给调用方（见 security-review.md S15）
            throw new EncryptorException("request decrypt failed: the request body is not decryptable", e);
        }
    }

    /**
     * 取出（必要时解出并记忆）{@code key} 对应的协商参数 JSON。
     *
     * <p>命中记忆直接返回，跳过 RSA 私钥运算；未命中才真正解密并写入记忆。
     * 记忆是<b>有界</b>的：容量到顶直接整体清空，防止未认证的 {@code key} 把内存打爆
     * （清空后最多再长到上限，不会无限增长）。</p>
     *
     * <p>未命中时 {@link EncryptorEncoder#decrypt(String)} 抛出的异常照旧向上抛，
     * 由调用方的 try/catch 统一包装，错误面不变。</p>
     */
    private String negotiateParams(String key) {
        String params = paramsCache.get(key);
        if (params != null) {
            return params;
        }
        params = new String(negotiateEncoder.decrypt(key), StandardCharsets.UTF_8);
        if (paramsCache.size() >= paramsCacheCapacity) {
            paramsCache.clear();
        }
        paramsCache.put(key, params);
        return params;
    }

    /**
     * 已记忆的协商参数条数（包内可见，仅供测试断言有界性）。
     */
    int paramsCacheSize() {
        return paramsCache.size();
    }

    public EncryptorEncoder getNegotiateEncoder() {
        return negotiateEncoder;
    }

    public Function<String, EncryptorEncoder> getEncryptorEncoder() {
        return encryptorEncoder;
    }

    public Function<String, SignerEncoder> getSignerEncoder() {
        return signerEncoder;
    }

    public List<CheckerStrategy> getCheckerStrategies() {
        return checkerStrategies;
    }
}
