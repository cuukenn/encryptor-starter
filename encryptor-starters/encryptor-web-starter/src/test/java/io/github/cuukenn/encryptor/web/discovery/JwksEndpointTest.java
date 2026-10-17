package io.github.cuukenn.encryptor.web.discovery;

import cn.hutool.json.JSONArray;
import cn.hutool.json.JSONObject;
import cn.hutool.json.JSONUtil;
import io.github.cuukenn.encryptor.config.DiscoveryConfig;
import io.github.cuukenn.encryptor.jose.KeyType;
import io.github.cuukenn.encryptor.protocol.DefaultProtocol;
import io.github.cuukenn.encryptor.web.JweTestSupport;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * JWKS 只读发现端点：免加密返回公钥，支持缓存/304，可关闭。
 *
 * @author changgg
 */
class JwksEndpointTest {

    private final JweTestSupport support = new JweTestSupport();

    private static JwksEndpointFilter filter(DefaultProtocol protocol, boolean enable) {
        DiscoveryConfig discovery = new DiscoveryConfig();
        discovery.setEnable(enable);
        return new JwksEndpointFilter(protocol.keys(), discovery);
    }

    @Test
    void 路径命中返回Jwks且免加密() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/.well-known/encryptor-keys");
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();
        filter(support.protocol, true).doFilter(request, response, chain);

        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(chain.getRequest()).as("命中端点后不应放行").isNull();
        String body = response.getContentAsString();
        assertThat(body).doesNotContain("\"d\"");
        JSONObject json = JSONUtil.parseObj(body);
        assertThat(json.getStr("activeKid")).isEqualTo(JweTestSupport.KID);
        JSONArray keys = json.getJSONArray("keys");
        assertThat(keys).hasSize(1);
        assertThat(keys.getJSONObject(0).getStr("kid")).isEqualTo(JweTestSupport.KID);
        assertThat(response.getHeader("Cache-Control")).contains("max-age=300");
        assertThat(response.getHeader("ETag")).isNotBlank();
    }

    @Test
    void etag命中返回304且无响应体() throws Exception {
        MockHttpServletRequest first = new MockHttpServletRequest("GET", "/.well-known/encryptor-keys");
        MockHttpServletResponse firstResponse = new MockHttpServletResponse();
        filter(support.protocol, true).doFilter(first, firstResponse, new MockFilterChain());
        String etag = firstResponse.getHeader("ETag");

        MockHttpServletRequest second = new MockHttpServletRequest("GET", "/.well-known/encryptor-keys");
        second.addHeader("If-None-Match", etag);
        MockHttpServletResponse secondResponse = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();
        filter(support.protocol, true).doFilter(second, secondResponse, chain);

        assertThat(secondResponse.getStatus()).isEqualTo(304);
        assertThat(secondResponse.getContentAsString()).isEmpty();
        assertThat(secondResponse.getHeader("ETag")).isEqualTo(etag);
        assertThat(chain.getRequest()).isNull();
    }

    @Test
    void 关闭后路径不存在放行业务() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/.well-known/encryptor-keys");
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();
        filter(support.protocol, false).doFilter(request, response, chain);

        assertThat(chain.getRequest()).as("enable=false 时路径应交给业务").isNotNull();
    }

    @Test
    void 非目标路径与非GET一律放行() throws Exception {
        MockHttpServletRequest getOther = new MockHttpServletRequest("GET", "/api/a");
        MockFilterChain chainGet = new MockFilterChain();
        filter(support.protocol, true).doFilter(getOther, new MockHttpServletResponse(), chainGet);
        assertThat(chainGet.getRequest()).isNotNull();

        MockHttpServletRequest post = new MockHttpServletRequest("POST", "/.well-known/encryptor-keys");
        MockFilterChain chainPost = new MockFilterChain();
        filter(support.protocol, true).doFilter(post, new MockHttpServletResponse(), chainPost);
        assertThat(chainPost.getRequest()).isNotNull();
    }

    @Test
    void activeKid变化后响应跟着变() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair pair = generator.generateKeyPair();
        String privateB64 = Base64.getEncoder().encodeToString(pair.getPrivate().getEncoded());
        String publicB64 = Base64.getEncoder().encodeToString(pair.getPublic().getEncoded());
        DefaultProtocol rotated = DefaultProtocol.builder()
            .key(new DefaultProtocol.KeyMaterial("old", KeyType.RSA, privateB64, publicB64))
            .key(new DefaultProtocol.KeyMaterial("new", KeyType.RSA, privateB64, publicB64))
            .activeKid("new")
            .build();

        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/.well-known/encryptor-keys");
        MockHttpServletResponse response = new MockHttpServletResponse();
        filter(rotated, true).doFilter(request, response, new MockFilterChain());

        JSONObject json = JSONUtil.parseObj(response.getContentAsString());
        assertThat(json.getStr("activeKid")).isEqualTo("new");
        assertThat(json.getJSONArray("keys")).hasSize(2);
    }
}
