package io.github.cuukenn.encryptor.jose;

import io.github.cuukenn.encryptor.exception.EncryptorException;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * {@link ContextAad} 契约测试：上下文绑定（防跨接口/跨方向搬运）。
 *
 * @author changgg
 */
class ContextAadTest {

    @Test
    void canonicalPath去掉contextPath与query并解码() {
        assertEquals("/a b", ContextAad.canonicalPath("/app/a%20b", "/app"));
        // contextPath 为 "/" 视为根上下文（不剥离前缀）；servlet 根上下文实际给的是空串，
        // 且 requestURI 本身不含 contextPath 时结果保持原样
        assertEquals("/app/x", ContextAad.canonicalPath("/app/x", "/"));
        assertEquals("/app/x", ContextAad.canonicalPath("/app/x", ""));
        assertEquals("/", ContextAad.canonicalPath("/app", "/app"));
        assertEquals("/a/b", ContextAad.canonicalPath("/biz/a/b?x=1", "/biz"));
        // 已解码的路径（网关 getURI().getPath() 的情形）结果必须一致
        assertEquals("/a b", ContextAad.canonicalPath("/app/a b", "/app"));
    }

    @Test
    void claims含全部上下文字段且ts为毫秒() {
        long ts = System.currentTimeMillis();
        Map<String, Object> claims = ContextAad.claims("/pay/x", "post", Direction.REQUEST, ts, "n1");

        assertEquals("/pay/x", claims.get("uri"));
        assertEquals("POST", claims.get("m"), "method 必须归一化为大写");
        assertEquals("req", claims.get("dir"));
        assertEquals(ts, claims.get("ts"));
        assertEquals("n1", claims.get("nonce"));
        assertTrue(((Long)claims.get("ts")) > 1_000_000_000_000L, "ts 必须是毫秒");
    }

    @Test
    void verify通过() {
        long ts = System.currentTimeMillis();
        Map<String, Object> claims = ContextAad.claims("/pay/x", "POST", Direction.REQUEST, ts, "n1");
        assertDoesNotThrow(() -> ContextAad.verify(claims, "/pay/x", "POST", Direction.REQUEST));
        // 大小写不敏感
        assertDoesNotThrow(() -> ContextAad.verify(claims, "/pay/x", "post", Direction.REQUEST));
    }

    @Test
    void verify缺字段一律抛异常() {
        Map<String, Object> claims = ContextAad.claims("/pay/x", "POST", Direction.REQUEST, System.currentTimeMillis(), "n1");
        for (String missing : new String[] {"uri", "m", "dir"}) {
            Map<String, Object> copy = new HashMap<>(claims);
            copy.remove(missing);
            EncryptorException e = assertThrows(EncryptorException.class,
                () -> ContextAad.verify(copy, "/pay/x", "POST", Direction.REQUEST));
            assertTrue(e.getMessage().contains("AAD"), "错误信息应含 AAD: " + e.getMessage());
        }
    }

    @Test
    void verify换uri或换方向或换方法抛异常() {
        Map<String, Object> claims = ContextAad.claims("/pay/x", "POST", Direction.REQUEST, System.currentTimeMillis(), "n1");
        assertThrows(EncryptorException.class, () -> ContextAad.verify(claims, "/other/x", "POST", Direction.REQUEST));
        assertThrows(EncryptorException.class, () -> ContextAad.verify(claims, "/pay/x", "POST", Direction.RESPONSE));
        assertThrows(EncryptorException.class, () -> ContextAad.verify(claims, "/pay/x", "GET", Direction.REQUEST));
    }

    @Test
    void canonicalPath折叠dot段防白名单绕过() {
        // 下游容器/路由会归一化：不折叠的话 /x/../pay 在过滤器看到穿越形态（白名单不命中）
        // 而下游落到 /pay 受保护资源
        assertEquals("/pay", ContextAad.canonicalPath("/x/../pay", null));
        assertEquals("/a/b", ContextAad.canonicalPath("/a/./b", null));
        assertEquals("/a/b", ContextAad.canonicalPath("/a/b/../b", null));
        // 百分号编码形态一并覆盖（解码后折叠）
        assertEquals("/pay", ContextAad.canonicalPath("/x/%2e%2e/pay", null));
        // 超出根的 .. 丢弃；全部折叠空 → "/"
        assertEquals("/", ContextAad.canonicalPath("/..", null));
        assertEquals("/", ContextAad.canonicalPath("/../../..", null));
        assertEquals("/pay", ContextAad.canonicalPath("/../../pay", null));
        // 尾斜杠语义保留（合法客户端的 /a/ 不能折叠成 /a，否则 AAD 会误杀）
        assertEquals("/a/", ContextAad.canonicalPath("/a/", null));
        assertEquals("/a/", ContextAad.canonicalPath("/a/.", null));
        assertEquals("/pay/", ContextAad.canonicalPath("/x/../pay/", null));
        // 空段（//）同样折叠：Tomcat 归一化 //pay → /pay，与 .. 同一绕过面
        assertEquals("/pay", ContextAad.canonicalPath("//pay", null));
        assertEquals("/api/a", ContextAad.canonicalPath("//api//a", null));
        assertEquals("/a/b/", ContextAad.canonicalPath("/a//b/", null));
        // 段内的点不是 dot 段（.b/..x/a.b 都是普通段）
        assertEquals("/a/.b/c", ContextAad.canonicalPath("/a/.b/c", null));
        assertEquals("/a/..x", ContextAad.canonicalPath("/a/..x", null));
        assertEquals("/a.b/c", ContextAad.canonicalPath("/a.b/c", null));
        // 无 dot/空段原样返回（含 contextPath 剥离叠加折叠）
        assertEquals("/pay/x", ContextAad.canonicalPath("/app/x/../pay/x", "/app"));
    }
}
