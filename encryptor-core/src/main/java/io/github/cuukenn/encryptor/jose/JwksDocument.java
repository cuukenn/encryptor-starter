package io.github.cuukenn.encryptor.jose;

import com.nimbusds.jose.util.JSONObjectUtils;
import io.github.cuukenn.encryptor.kit.DigestKit;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * JWKS 只读文档：公钥集合 + activeKid，以及基于文档内容的强 ETag。
 *
 * <p>密钥库不可变，因此文档与 ETag 在构造期定型；servlet 与 gateway 的发现端点
 * 共用同一份生成逻辑，避免两侧 JSON/摘要口径漂移。</p>
 *
 * @author changgg
 */
public final class JwksDocument {
    private final String body;
    private final String etag;

    public JwksDocument(ServerKeyStore keys) {
        List<Map<String, Object>> jwks = new ArrayList<>();
        for (PublicKeyInfo info : keys.publicKeys()) {
            jwks.add(info.jwk());
        }
        Map<String, Object> root = new LinkedHashMap<>();
        root.put("keys", jwks);
        root.put("activeKid", keys.activeKid());
        this.body = JSONObjectUtils.toJSONString(root);
        this.etag = "\"" + DigestKit.sha256Hex(body) + "\"";
    }

    /** JWKS JSON 正文。 */
    public String body() {
        return body;
    }

    /** 带双引号的 ETag（可直接写入响应头）。 */
    public String etag() {
        return etag;
    }
}
