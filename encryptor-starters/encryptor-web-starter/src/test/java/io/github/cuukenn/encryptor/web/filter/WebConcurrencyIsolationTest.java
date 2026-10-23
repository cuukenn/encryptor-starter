package io.github.cuukenn.encryptor.web.filter;

import io.github.cuukenn.encryptor.config.EncryptorConfig;
import io.github.cuukenn.encryptor.jose.JweContext;
import io.github.cuukenn.encryptor.web.JweTestSupport;
import io.github.cuukenn.encryptor.web.config.WebEncryptorConfig;
import io.github.cuukenn.encryptor.web.configuration.WebEncryptorConfiguration;
import io.github.cuukenn.encryptor.web.kit.WebContext;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * 并发隔离：线程池复用 + 异步交接下，每个请求的 CEK/明文必须只属于自己。
 *
 * <p>最严重的回归形态是"响应被另一请求的 CEK 加密"或"业务读到别人的明文"——串行用例发现不了。</p>
 *
 * @author changgg
 */
class WebConcurrencyIsolationTest {

    private static final int CONCURRENCY = 8;

    private final WebEncryptorConfig webConfig = new WebEncryptorConfig();
    private final EncryptorConfig protocolConfig = new EncryptorConfig();
    private final JweTestSupport support = new JweTestSupport();

    @AfterEach
    void tearDown() {
        WebContext.clear();
    }

    @Test
    void 并发请求各自使用自己的CEK() throws Exception {
        ExecutorService pool = Executors.newFixedThreadPool(CONCURRENCY);
        try {
            List<Future<RoundTrip>> futures = new ArrayList<>();
            for (int i = 0; i < CONCURRENCY; i++) {
                final int index = i;
                futures.add(pool.submit((Callable<RoundTrip>) () -> runOne(index)));
            }
            List<RoundTrip> results = new ArrayList<>();
            for (Future<RoundTrip> future : futures) {
                results.add(future.get(10, TimeUnit.SECONDS));
            }
            for (int i = 0; i < results.size(); i++) {
                RoundTrip rt = results.get(i);
                assertThat(new String(JweTestSupport.decryptResponse(rt.response, rt.cek), StandardCharsets.UTF_8))
                    .isEqualTo(rt.plaintext);
                // 别人的 CEK 必须解不开（GCM tag 校验失败）
                RoundTrip other = results.get((i + 1) % results.size());
                assertThatThrownBy(() -> JweTestSupport.decryptResponse(rt.response, other.cek))
                    .isInstanceOf(Exception.class);
            }
        } finally {
            pool.shutdownNow();
        }
    }

    private RoundTrip runOne(int index) throws Exception {
        String plaintext = "{\"index\":" + index + "}";
        String uri = "/api/concurrent";
        String compact = support.seal(plaintext, uri, "POST");
        MockHttpServletRequest request = new MockHttpServletRequest("POST", uri);
        request.setContentType("application/json");
        request.setContent(("{\"jwe\":\"" + compact + "\"}").getBytes(StandardCharsets.UTF_8));
        MockHttpServletResponse response = new MockHttpServletResponse();
        AtomicReference<byte[]> cek = new AtomicReference<>();

        runRealChain(request, response, (req, resp) -> {
            JweContext context = WebContext.current().getJweContext();
            assertThat(context).as("业务阶段必须已装载解密上下文").isNotNull();
            cek.set(context.cek().clone());
            resp.getWriter().write(plaintext);
        });

        assertThat(response.getStatus()).isEqualTo(200);
        return new RoundTrip(plaintext, response.getContentAsString(), cek.get());
    }

    private void runRealChain(MockHttpServletRequest request, MockHttpServletResponse response, FilterChain business)
        throws Exception {
        List<Filter> filters = orderedFilters();
        FilterChain tail = business;
        for (int i = filters.size() - 1; i >= 0; i--) {
            Filter filter = filters.get(i);
            FilterChain next = tail;
            tail = (req, resp) -> filter.doFilter(req, resp, next);
        }
        tail.doFilter(request, response);
    }

    private List<Filter> orderedFilters() {
        WebEncryptorConfiguration configuration = new WebEncryptorConfiguration();
        List<FilterRegistrationBean<? extends Filter>> registrations = new ArrayList<>(Arrays.asList(
            configuration.jwksDiscoveryFilter(webConfig, protocolConfig, support.protocol),
            configuration.webEncryptorFilter(webConfig, protocolConfig, support.protocol, support.protocol.runtime()),
            configuration.encryptorRequestParameterFilterFilterRegistrationBean(webConfig),
            configuration.encryptorRequestBodyFilterFilterRegistrationBean(webConfig),
            configuration.encryptorResponseFilterFilterRegistrationBean(
                webConfig, protocolConfig, support.protocol, support.protocol.runtime())));
        registrations.sort(Comparator.comparingInt(FilterRegistrationBean::getOrder));
        List<Filter> filters = new ArrayList<>();
        for (FilterRegistrationBean<? extends Filter> registration : registrations) {
            filters.add(registration.getFilter());
        }
        return filters;
    }

    private static final class RoundTrip {
        private final String plaintext;
        private final String response;
        private final byte[] cek;

        private RoundTrip(String plaintext, String response, byte[] cek) {
            this.plaintext = plaintext;
            this.response = response;
            this.cek = cek;
        }
    }
}
