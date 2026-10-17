package io.github.cuukenn.encryptor;

import cn.hutool.http.HttpRequest;
import cn.hutool.http.HttpResponse;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.util.Base64URL;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.SecretKeySpec;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * v2 协议端到端脚本（需先启动 web-example:8081；surefire 已排除，不进 CI）。
 *
 * <p>报文 = 单个 {@code jwe} 字段：请求 alg=RSA-OAEP-256 + enc=A256GCM，
 * protected header 带 uri/m/dir/ts/nonce；响应 alg=dir 复用请求 CEK。</p>
 *
 * @author changgg
 */
public class HttpTest {
    private static final Logger logger = LoggerFactory.getLogger(HttpTest.class);
    private static final String BASE = "http://127.0.0.1:8081";
    /** 与 application.yml {@code keys[0]}（example-2026）一致。 */
    private static final String KID_GLOBAL = "example-2026";
    private static final String PUBLIC_KEY_GLOBAL = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1igj1GnLoqogaMRgb6SiTOOxImrf3Yk6mBMjKDL9MhT85iaU3Hi7O92IaSZvl1xJH5tqEBjldYXdFmmVMWCIY6kM+kZpmXf36pfn+UYg3+aySGHWxwIQe6zeN+MpJ7hFt8HF0yoRdYsSL8rHkcUyEplPsrA1oF0fbfjFFLYhTelq6d/BaC/HNpp8oNpRyfUNP5N53zjJC0mEzXaQ/vD/X2q4ctVz0aaKdhhUM4MBfcYnG07aT4FS+30LB8vzaU0kqDWLQMSZZOX8/UPUYmkf9AxypJr/7X6sAs3Qskl3ZBy+sSde2cXaHMJqUNzfJ4SX02O5M1caD0CHcX75J1lJvQIDAQAB";
    /** 与 application.yml {@code keys[1]}（secret-2026，/test/secret.* 的 uri 级 kid 白名单目标）一致。 */
    private static final String KID_SECRET = "secret-2026";
    private static final String PUBLIC_KEY_SECRET = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwb4k+8NnQGua3lk+Ru/8Jca+WXhVbimFOrOPU+4ixo3/YJT18gvaj8i/c4gmNsrmleezhfxy5+jnimbrHbWLCAUm6p99XqZiStX7jaEuzWnJx6mPRXYQAOf1SUcWWVrmP+SAZ0vvkYQMVybi8KZ51P+i3A18z/IPxf6zvFqbo/t8AwVUF46PFI+LIwS1X+wUwTSXbdYlUp9gsLe7G5t4TGNiRsFJtV4+gPOvSLS26JHXDg5GgPT3yGFglXuP+vNs9e7R7baRHW9rIGHNtGtel2rQN6Nl6VWq7UekXukg98Yq7k/Ss0FGxQxFvSt46nYMUng+u3wXa9Rp3jwnA64ptwIDAQAB";
    private static final SecureRandom RANDOM = new SecureRandom();

    @Test
    public void test_get() {
        String plaintext = "name=" + URLEncoder.encode("小明", StandardCharsets.UTF_8);
        Sealed sealed = seal(plaintext, "/test/hello", "GET", KID_GLOBAL, PUBLIC_KEY_GLOBAL);
        HttpResponse response = sendGet("/test/hello?jwe=" + url(sealed.compact));
        Assertions.assertEquals(200, response.getStatus(), "GET /test/hello 应返回 200");
        String body = decryptResponse(response.body(), sealed.cek);
        logger.info("decrypted: {}", body);
        Assertions.assertTrue(body.contains("Hello"), "响应应包含 Hello，实际为: " + body);
        Assertions.assertTrue(body.contains("小明"), "响应回显 name=小明，实际为: " + body);
    }

    /**
     * uri 级 kid 白名单正向：/test/secret.* 只接受 kid=secret-2026。
     */
    @Test
    public void test_get_uri_level_kid() {
        String plaintext = "name=" + URLEncoder.encode("小明", StandardCharsets.UTF_8);
        Sealed sealed = seal(plaintext, "/test/secret", "GET", KID_SECRET, PUBLIC_KEY_SECRET);
        HttpResponse response = sendGet("/test/secret?jwe=" + url(sealed.compact));
        Assertions.assertEquals(200, response.getStatus(), "GET /test/secret 应返回 200");
        String body = decryptResponse(response.body(), sealed.cek);
        Assertions.assertTrue(body.contains("Secret"), "响应应包含 Secret，实际为: " + body);
    }

    /**
     * 反向对照：用全局 kid（example-2026）请求被 uri 级白名单约束的 /test/secret → 400。
     */
    @Test
    public void test_get_uri_level_kid_rejected() {
        String plaintext = "name=" + URLEncoder.encode("小明", StandardCharsets.UTF_8);
        Sealed sealed = seal(plaintext, "/test/secret", "GET", KID_GLOBAL, PUBLIC_KEY_GLOBAL);
        HttpResponse response = sendGet("/test/secret?jwe=" + url(sealed.compact));
        logger.info("wrong-kid status: {}, body: {}", response.getStatus(), response.body());
        Assertions.assertEquals(400, response.getStatus(),
                "用 uri 级白名单外的 kid 请求应被拒（400），实际: " + response.getStatus());
    }

    @Test
    public void test_post() {
        Sealed sealed = seal("{\"name\":\"小明\"}", "/test/hello", "POST", KID_GLOBAL, PUBLIC_KEY_GLOBAL);
        HttpResponse response = HttpRequest.post(BASE + "/test/hello")
                .header("Content-Type", "application/json")
                .body("{\"jwe\":\"" + sealed.compact + "\"}").execute();
        Assertions.assertEquals(200, response.getStatus(), "POST /test/hello 应返回 200");
        String body = decryptResponse(response.body(), sealed.cek);
        logger.info("decrypted: {}", body);
        Assertions.assertTrue(body.contains("Hello"), "响应应包含 Hello，实际为: " + body);
        Assertions.assertTrue(body.contains("小明"), "响应回显 name=小明，实际为: " + body);
    }

    // ==================== 构造/解密工具（与 web-starter 的 JweTestSupport 同构） ====================

    /** 一次请求的密封结果：compact 报文 + 客户端自留的 CEK（响应 alg=dir 复用它）。 */
    private static final class Sealed {
        final String compact;
        final byte[] cek;

        Sealed(String compact, byte[] cek) {
            this.compact = compact;
            this.cek = cek;
        }
    }

    private static Sealed seal(String plaintext, String uri, String method, String kid, String publicBase64) {
        try {
            byte[] cek = new byte[32];
            RANDOM.nextBytes(cek);
            Map<String, Object> claims = new LinkedHashMap<>();
            claims.put("uri", uri);
            claims.put("m", method);
            claims.put("dir", "req");
            claims.put("ts", System.currentTimeMillis());
            claims.put("nonce", Base64URL.encode(randomBytes(12)).toString());
            JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM)
                    .keyID(kid).customParams(claims).build();
            String headerSegment = header.toBase64URL().toString();
            // CEK 用 RSA-OAEP-256 封装（MGF1 显式 SHA-256，与 JOSE 一致；JCE 默认 MGF1 是 SHA-1）
            Cipher rsa = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
            rsa.init(Cipher.ENCRYPT_MODE, publicKey(publicBase64),
                    new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT));
            byte[] encryptedKey = rsa.doFinal(cek);
            // 内容 A256GCM（AAD = protected header 的 ASCII 字节，JWE 规范）
            byte[] iv = randomBytes(12);
            Cipher gcm = Cipher.getInstance("AES/GCM/NoPadding");
            gcm.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(cek, "AES"), new GCMParameterSpec(128, iv));
            gcm.updateAAD(headerSegment.getBytes(StandardCharsets.US_ASCII));
            byte[] ctTag = gcm.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
            byte[] ct = java.util.Arrays.copyOfRange(ctTag, 0, ctTag.length - 16);
            byte[] tag = java.util.Arrays.copyOfRange(ctTag, ctTag.length - 16, ctTag.length);
            String compact = headerSegment + '.'
                    + Base64URL.encode(encryptedKey) + '.'
                    + Base64URL.encode(iv) + '.'
                    + Base64URL.encode(ct) + '.'
                    + Base64URL.encode(tag);
            return new Sealed(compact.toString(), cek);
        } catch (Exception e) {
            throw new IllegalStateException("构造请求 JWE 失败", e);
        }
    }

    private static PublicKey publicKey(String base64) throws Exception {
        return KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(base64)));
    }

    private static byte[] randomBytes(int n) {
        byte[] bytes = new byte[n];
        RANDOM.nextBytes(bytes);
        return bytes;
    }

    private static HttpResponse sendGet(String url) {
        return HttpRequest.get(BASE + url).execute();
    }

    private static String url(String compact) {
        return URLEncoder.encode(compact, StandardCharsets.UTF_8);
    }

    private static String decryptResponse(String body, byte[] cek) {
        try {
            // body = {"jwe":"<compact>"}；响应 alg=dir，CEK 复用请求的
            String compact = body.substring(body.indexOf('"') + 1);
            compact = compact.substring(compact.indexOf('"') + 1, compact.lastIndexOf('"'));
            String[] parts = compact.split("\\.");
            byte[] iv = Base64.getUrlDecoder().decode(parts[2]);
            byte[] ct = Base64.getUrlDecoder().decode(parts[3]);
            byte[] tag = Base64.getUrlDecoder().decode(parts[4]);
            byte[] ctTag = new byte[ct.length + tag.length];
            System.arraycopy(ct, 0, ctTag, 0, ct.length);
            System.arraycopy(tag, 0, ctTag, ct.length, tag.length);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(cek, "AES"), new GCMParameterSpec(128, iv));
            cipher.updateAAD(parts[0].getBytes(StandardCharsets.US_ASCII));
            return new String(cipher.doFinal(ctTag), StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new IllegalStateException("解响应失败: " + body, e);
        }
    }
}
