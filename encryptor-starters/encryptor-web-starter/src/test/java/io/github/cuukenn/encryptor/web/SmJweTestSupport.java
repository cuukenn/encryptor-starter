package io.github.cuukenn.encryptor.web;

import cn.hutool.json.JSONUtil;
import io.github.cuukenn.encryptor.jose.Direction;
import io.github.cuukenn.encryptor.jose.KeyType;
import io.github.cuukenn.encryptor.protocol.DefaultProtocol;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.crypto.engines.SM2Engine;
import org.bouncycastle.crypto.engines.SM4Engine;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.UUID;

/**
 * 国密（SM2 + SM4-GCM）测试侧封装：与 {@code JweTestSupport} 同形，但走 SM 套件，
 * 用于在过滤器层钉住"SM 请求 → 响应 enc 仍为 SM4-GCM"（评审 C2）。
 *
 * @author changgg
 */
public class SmJweTestSupport {
    public static final String KID = "sm1";
    private static final String ALG = "SM2";
    private static final String ENC = "SM4-GCM";
    private static final int CEK_LENGTH = 16;
    private static final int IV_LENGTH = 12;
    private static final int TAG_LENGTH = 16;

    private final ECPublicKeyParameters publicKey;
    private final SecureRandom random = new SecureRandom();
    public final DefaultProtocol protocol;

    public SmJweTestSupport() {
        try {
            X9ECParameters domain = CustomNamedCurves.getByName("sm2p256v1");
            ECKeyPairGenerator generator = new ECKeyPairGenerator();
            generator.init(new ECKeyGenerationParameters(new ECDomainParameters(domain), random));
            AsymmetricCipherKeyPair pair = generator.generateKeyPair();
            this.publicKey = (ECPublicKeyParameters) pair.getPublic();
            ECPrivateKeyParameters privateKey = (ECPrivateKeyParameters) pair.getPrivate();
            String priv = Base64.getEncoder().encodeToString(
                PrivateKeyInfoFactory.createPrivateKeyInfo(privateKey).getEncoded(ASN1Encoding.DER));
            String pub = Base64.getEncoder().encodeToString(
                SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(publicKey).getEncoded(ASN1Encoding.DER));
            this.protocol = DefaultProtocol.builder()
                .key(new DefaultProtocol.KeyMaterial(KID, KeyType.SM2, priv, pub))
                .build();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    /**
     * 一次 SM 请求的封装结果：{@code compact} 与调用方必须保留的 {@code cek}（响应复用同一把）。
     */
    public static final class Sealed {
        public final String compact;
        public final byte[] cek;

        private Sealed(String compact, byte[] cek) {
            this.compact = compact;
            this.cek = cek;
        }
    }

    /**
     * 用 SM2(C1C3C2) 封 CEK、SM4-GCM 加密正文，手动拼 JWE compact（AAD = protected header 的 ASCII 字节）。
     */
    public Sealed seal(String plaintext, String uri, String method) {
        byte[] cek = new byte[CEK_LENGTH];
        byte[] iv = new byte[IV_LENGTH];
        random.nextBytes(cek);
        random.nextBytes(iv);
        String header = "{\"alg\":\"" + ALG + "\",\"enc\":\"" + ENC + "\",\"kid\":\"" + KID
            + "\",\"typ\":\"encryptor+jwe\",\"uri\":\"" + uri + "\",\"m\":\"" + method
            + "\",\"dir\":\"" + Direction.REQUEST.code() + "\",\"ts\":" + System.currentTimeMillis()
            + ",\"nonce\":\"" + UUID.randomUUID() + "\"}";
        byte[] headerBytes = header.getBytes(StandardCharsets.US_ASCII);
        String headerSegment = b64u(headerBytes, 0, headerBytes.length);
        // AAD 必须是 protected header 的 base64url 文本字节（与 JweCodec 侧一致），不是 JSON 原文
        byte[] aad = headerSegment.getBytes(StandardCharsets.US_ASCII);
        byte[] wrapped = sm2Wrap(cek);
        byte[] ctTag = sm4Gcm(true, cek, iv, plaintext.getBytes(StandardCharsets.UTF_8), aad);
        String compact = headerSegment + "." + b64u(wrapped, 0, wrapped.length) + "."
            + b64u(iv, 0, iv.length) + "."
            + b64u(ctTag, 0, ctTag.length - TAG_LENGTH) + "."
            + b64u(ctTag, ctTag.length - TAG_LENGTH, TAG_LENGTH);
        return new Sealed(compact, cek);
    }

    /** 解析响应 compact 的 protected header JSON。 */
    public static String responseHeaderJson(String payload) {
        String compact = responseCompact(payload);
        String header = compact.substring(0, compact.indexOf('.'));
        return new String(Base64.getUrlDecoder().decode(header), StandardCharsets.UTF_8);
    }

    /** 从 {@code {"jwe":"…"}} 响应体里取出 compact。 */
    public static String responseCompact(String payload) {
        return JSONUtil.parseObj(payload).getStr("jwe");
    }

    /** 用请求的 CEK 走 SM4-GCM 解响应（AAD = protected header 的 ASCII 字节）。 */
    public static byte[] sm4DecryptResponse(String payload, byte[] cek) {
        String[] parts = responseCompact(payload).split("\\.");
        byte[] aad = parts[0].getBytes(StandardCharsets.US_ASCII);
        byte[] iv = Base64.getUrlDecoder().decode(parts[2]);
        byte[] ct = Base64.getUrlDecoder().decode(parts[3]);
        byte[] tag = Base64.getUrlDecoder().decode(parts[4]);
        byte[] ctTag = new byte[ct.length + tag.length];
        System.arraycopy(ct, 0, ctTag, 0, ct.length);
        System.arraycopy(tag, 0, ctTag, ct.length, tag.length);
        return sm4Gcm(false, cek, iv, ctTag, aad);
    }

    private byte[] sm2Wrap(byte[] cek) {
        try {
            SM2Engine engine = new SM2Engine(SM2Engine.Mode.C1C3C2);
            engine.init(true, new ParametersWithRandom(publicKey, random));
            return engine.processBlock(cek, 0, cek.length);
        } catch (InvalidCipherTextException e) {
            throw new IllegalStateException(e);
        }
    }

    private static byte[] sm4Gcm(boolean forEncryption, byte[] key, byte[] iv, byte[] input, byte[] aad) {
        GCMBlockCipher cipher = new GCMBlockCipher(new SM4Engine());
        cipher.init(forEncryption, new AEADParameters(new KeyParameter(key), 128, iv, aad));
        byte[] out = new byte[cipher.getOutputSize(input.length)];
        int length = cipher.processBytes(input, 0, input.length, out, 0);
        try {
            length += cipher.doFinal(out, length);
        } catch (InvalidCipherTextException e) {
            throw new IllegalStateException(e);
        }
        return out;
    }

    private static String b64u(byte[] bytes, int offset, int length) {
        byte[] slice = new byte[length];
        System.arraycopy(bytes, offset, slice, 0, length);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(slice);
    }
}
