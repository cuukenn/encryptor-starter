package io.github.cuukenn.encryptor.config.base;

import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * {@link RouteRule#effectiveKids} 的合并查找契约：最长命中跨两个正则空间、同长并集、无命中不限。
 *
 * @author changgg
 */
class RouteRuleTest {

    private static RouteRule rule(String... kids) {
        RouteRule r = new RouteRule();
        r.setKids(new java.util.ArrayList<>(Arrays.asList(kids)));
        return r;
    }

    @Test
    void 无任何配置返回null表示不限() {
        assertNull(RouteRule.effectiveKids(null, null, "/pay/x"));
        assertNull(RouteRule.effectiveKids(new LinkedHashMap<>(), new LinkedHashMap<>(), "/pay/x"));
    }

    @Test
    void 两个正则空间取最长命中() {
        Map<String, List<String>> crypto = new LinkedHashMap<>();
        crypto.put("/pay/.*", Arrays.asList("k-old"));
        Map<String, RouteRule> routes = new LinkedHashMap<>();
        routes.put("/pay/vip/.*", rule("k-vip"));
        assertEquals(Arrays.asList("k-vip"), RouteRule.effectiveKids(crypto, routes, "/pay/vip/1"));
        assertEquals(Arrays.asList("k-old"), RouteRule.effectiveKids(crypto, routes, "/pay/normal"));
        assertNull(RouteRule.effectiveKids(crypto, routes, "/other"));
    }

    @Test
    void 同长命中取并集() {
        Map<String, List<String>> crypto = new LinkedHashMap<>();
        crypto.put("/pay/.*", Arrays.asList("k1", "k2"));
        Map<String, RouteRule> routes = new LinkedHashMap<>();
        routes.put("/pay/.*", rule("k2", "k3"));
        assertEquals(Arrays.asList("k1", "k2", "k3"), RouteRule.effectiveKids(crypto, routes, "/pay/x"));
    }

    @Test
    void 空kids列表表示不限() {
        Map<String, RouteRule> routes = new LinkedHashMap<>();
        routes.put("/pay/.*", rule());
        assertEquals(Collections.emptyList(), RouteRule.effectiveKids(null, routes, "/pay/x"),
            "空列表语义与 crypto-config 一致：命中但列表为空 = 不限");
    }
}
