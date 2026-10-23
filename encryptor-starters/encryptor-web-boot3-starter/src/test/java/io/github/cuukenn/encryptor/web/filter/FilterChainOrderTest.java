package io.github.cuukenn.encryptor.web.filter;

import io.github.cuukenn.encryptor.config.EncryptorConfig;
import io.github.cuukenn.encryptor.web.JweTestSupport;
import io.github.cuukenn.encryptor.web.config.WebEncryptorConfig;
import io.github.cuukenn.encryptor.web.config.WebFilterConfig;
import io.github.cuukenn.encryptor.web.configuration.WebEncryptorConfiguration;
import io.github.cuukenn.encryptor.web.kit.WebContext;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * 过滤器链的**装配顺序**本身是 v2 的载荷契约（P2-5）：门面过滤器一次性识别载体、解密并把结果装进
 * {@link WebContext}；参数/请求体过滤器只把结果包装成请求视图，**不再各自读请求**；响应过滤器必须在
 * 门面**内层**，才能在业务写完响应后读到同一把 CEK 回加密。所以顺序被改（改 {@link WebFilterConfig}
 * 默认值或调整注册）时，行为会**静默**变化。
 *
 * <p>本用例不手抄链序，而是直接向 {@link WebEncryptorConfiguration} 取生产注册的
 * {@link FilterRegistrationBean}，按 {@code getOrder()} 排序组装链，再跑三载体的往返 ——
 * 顺序一旦漂移这里必红（此前链序只硬编码在 {@code EncryptorResponseFilterTest} 里，改默认值不会报警）。</p>
 *
 * @author changgg
 */
class FilterChainOrderTest {
    private final JweTestSupport support = new JweTestSupport();
    private final WebEncryptorConfig webConfig = new WebEncryptorConfig();
    private final EncryptorConfig protocolConfig = new EncryptorConfig();

    @AfterEach
    void tearDown() {
        WebContext.clear();
    }

    /** 生产同一个装配入口：五个过滤器都从这里取（不是 new 出来的）。 */
    private List<FilterRegistrationBean<? extends Filter>> registrations() {
        WebEncryptorConfiguration configuration = new WebEncryptorConfiguration();
        return new ArrayList<>(Arrays.asList(
            configuration.jwksDiscoveryFilter(webConfig, protocolConfig, support.protocol),
            configuration.webEncryptorFilter(webConfig, protocolConfig, support.protocol, support.protocol.runtime()),
            configuration.encryptorRequestParameterFilterFilterRegistrationBean(webConfig),
            configuration.encryptorRequestBodyFilterFilterRegistrationBean(webConfig),
            configuration.encryptorResponseFilterFilterRegistrationBean(
                webConfig, protocolConfig, support.protocol, support.protocol.runtime())));
    }

    private List<Filter> orderedFilters() {
        List<FilterRegistrationBean<? extends Filter>> registrations = registrations();
        registrations.sort(Comparator.comparingInt(FilterRegistrationBean::getOrder));
        return registrations.stream().map(FilterRegistrationBean::getFilter).collect(Collectors.toList());
    }

    /** 与容器一致：按 order 升序嵌套，business 在最内层。 */
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

    @Test
    void 生产注册的链序与文档约定一致() {
        assertThat(orderedFilters().stream().map(f -> f.getClass().getSimpleName()).collect(Collectors.toList()))
            .containsExactly("JwksEndpointFilter", "EncryptorWebFilter", "EncryptorRequestParameterFilter",
                "EncryptorRequestBodyFilter", "EncryptorResponseFilter");
    }

    @Test
    void 注册名使用小写简单类名() {
        assertThat(registrations().stream().map(FilterChainOrderTest::nameOf).collect(Collectors.toList()))
            .containsExactly("jwksendpointfilter", "encryptorwebfilter", "encryptorrequestparameterfilter",
                "encryptorrequestbodyfilter", "encryptorresponsefilter");
    }

    /** RegistrationBean 只有 setName，没有公开 getter；测试用反射读取实际注册名。 */
    private static String nameOf(FilterRegistrationBean<? extends Filter> bean) {
        try {
            java.lang.reflect.Field field = org.springframework.boot.web.servlet.DynamicRegistrationBean.class
                .getDeclaredField("name");
            field.setAccessible(true);
            return (String) field.get(bean);
        } catch (ReflectiveOperationException e) {
            throw new AssertionError(e);
        }
    }

    @Test
    void 顺序默认值保持门面最外响应最内() {
        WebFilterConfig orders = webConfig.getFilterConfig();
        assertThat(orders.getJwksFilterOrder()).isLessThan(orders.getEncryptorFilterOrder());
        // 门面必须在两个请求视图过滤器之外：WebContext 先被装载，它们才有结果可包装
        assertThat(orders.getEncryptorFilterOrder()).isLessThan(orders.getEncryptorReqParamsFilterOrder());
        assertThat(orders.getEncryptorReqParamsFilterOrder()).isLessThan(orders.getEncryptorReqBodyFilterOrder());
        // 响应过滤器在门面内层：业务写完响应后仍能读到 WebContext 里的同一把 CEK
        assertThat(orders.getEncryptorReqBodyFilterOrder()).isLessThan(orders.getEncryptorResFilterOrder());
    }

    @Test
    void query载体在真实链序下拿到明文() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/q");
        request.setParameter("jwe", support.seal("a=1&b=2", "/api/q", "GET"));
        AtomicReference<String> seen = new AtomicReference<>();
        runRealChain(request, new MockHttpServletResponse(), (req, resp) -> {
            HttpServletRequest r = (HttpServletRequest) req;
            // 业务层只应看到明文参数；承载密文的 jwe 参数必须已被参数过滤器隐藏
            seen.set(r.getParameter("a") + "/" + r.getParameter("b") + "/" + r.getParameterMap().containsKey("jwe")
                + "/" + WebContext.current().getCarrier());
        });
        assertThat(seen.get()).isEqualTo("1/2/false/QUERY");
    }

    @Test
    void queryString剔除jwe密文段() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/q");
        request.setQueryString("jwe=ciphertext&a=1");
        request.setParameter("jwe", support.seal("a=1", "/api/q", "GET"));
        AtomicReference<String> seen = new AtomicReference<>();
        runRealChain(request, new MockHttpServletResponse(), (req, resp) ->
            seen.set(((HttpServletRequest) req).getQueryString()));
        assertThat(seen.get()).isEqualTo("a=1");
    }

    @Test
    void queryString只有jwe时返回null() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/q");
        request.setQueryString("jwe=ciphertext");
        request.setParameter("jwe", support.seal("a=1", "/api/q", "GET"));
        AtomicReference<String> seen = new AtomicReference<>("unset");
        runRealChain(request, new MockHttpServletResponse(), (req, resp) ->
            seen.set(((HttpServletRequest) req).getQueryString()));
        assertThat(seen.get()).isNull();
    }

    @Test
    void form载体在真实链序下同时拿到参数与body视图() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/f");
        request.setContentType("application/x-www-form-urlencoded");
        request.setContent("jwe=x".getBytes(StandardCharsets.UTF_8));
        request.setParameter("jwe", support.seal("a=1&b=2", "/api/f", "POST"));
        AtomicReference<String> seen = new AtomicReference<>();
        runRealChain(request, new MockHttpServletResponse(), (req, resp) -> {
            HttpServletRequest r = (HttpServletRequest) req;
            seen.set(r.getParameter("a") + "/" + WebContext.current().getCarrier() + "/" + body(r));
        });
        // form 载体：明文既是参数视图、也是 body 视图（下游按 content-type 自行取用）
        assertThat(seen.get()).isEqualTo("1/FORM/a=1&b=2");
    }

    @Test
    void json载体在真实链序下拿到明文body() throws Exception {
        String plaintext = "{\"name\":\"alice\"}";
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/j");
        request.setContentType("application/json");
        request.setContent(("{\"jwe\":\"" + support.seal(plaintext, "/api/j", "POST") + "\"}")
            .getBytes(StandardCharsets.UTF_8));
        AtomicReference<String> seen = new AtomicReference<>();
        runRealChain(request, new MockHttpServletResponse(), (req, resp) -> {
            HttpServletRequest r = (HttpServletRequest) req;
            // 明文长度才是下游（含 Jackson）该看到的长度；原密文长度是误导
            seen.set(body(r) + "/" + r.getContentLength() + "/" + WebContext.current().getCarrier());
        });
        assertThat(seen.get()).isEqualTo(plaintext + "/" + plaintext.length() + "/JSON");
    }

    @Test
    void 响应在真实链序下被回加密且可用请求CEK解开() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/r");
        request.setParameter("jwe", support.seal("a=1", "/api/r", "POST"));
        MockHttpServletResponse response = new MockHttpServletResponse();
        AtomicReference<byte[]> cek = new AtomicReference<>();
        runRealChain(request, response, (req, resp) -> {
            cek.set(copyCek());
            ((HttpServletResponse) resp).setContentType("application/json");
            resp.getWriter().write("{\"ok\":true}");
        });
        String payload = response.getContentAsString();
        assertThat(payload).contains("\"jwe\"");
        assertThat(JweTestSupport.decryptResponse(payload, cek.get()))
            .isEqualTo("{\"ok\":true}".getBytes(StandardCharsets.UTF_8));
        assertThat(JweTestSupport.responseHeaderJson(payload)).contains("\"dir\":\"res\"");
    }

    @Test
    void 链结束后不残留ThreadLocal() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/q");
        request.setParameter("jwe", support.seal("a=1", "/api/q", "GET"));
        runRealChain(request, new MockHttpServletResponse(), (req, resp) -> {
        });
        // 参数过滤器(-11)在链尾 clear()：线程池复用下不得把上一个请求的上下文留给下一个
        assertThat(WebContext.current().isReqEncryptor()).isFalse();
    }

    /** 客户端视角持有自己的 CEK；服务端上下文在请求结束后会被清零，测试必须先复制。 */
    private static byte[] copyCek() {
        byte[] cek = WebContext.current().getJweContext().cek();
        return Arrays.copyOf(cek, cek.length);
    }

    /** 以业务层视角读请求体（请求体过滤器已把它换成明文流）。 */
    private static String body(HttpServletRequest request) throws java.io.IOException {
        java.io.InputStream in = request.getInputStream();
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
        byte[] buffer = new byte[64];
        int read;
        while ((read = in.read(buffer)) > 0) {
            out.write(buffer, 0, read);
        }
        return new String(out.toByteArray(), StandardCharsets.UTF_8);
    }
}
