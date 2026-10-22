package io.github.cuukenn.encryptor.example.boot3;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicLong;

/**
 * 普通下游回显服务（不带 encryptor，符合"网关下游必须是普通应用"的约束）：
 * JDK 自带 {@code com.sun.net.httpserver} 起 127.0.0.1 随机端口服务，让网关侧
 * 加密路径（请求改写 → 转发 → 响应装饰器 → Netty 写出）跑在真实传输上，
 * 对 SCG ordering 的正向断言才有证明力（Mock exchange 验不出过滤器间的真实次序）。
 *
 * <p>/test/hello 的响应契约对齐 javax 线 {@code gateway-example/web} 的
 * TestController（GET → "Hello, name"、POST json → "Hello, body"、POST form →
 * "Hello, name=[1]"），让 {@code front/test.js}（node 前端）断言在两种下游上语义一致。</p>
 *
 * @author changgg
 */
public final class DownstreamEchoServer {
    /** /test/big、/api/big 的固定大响应（响应超限用例共用断言口径）。 */
    public static final String BIG_PAYLOAD = "{\"marker\":\"boot3-big-response\",\"padding\":\"" + "x".repeat(16 * 1024) + "\"}";

    private static volatile HttpServer server;
    private static volatile int port = -1;
    private static final Map<String, AtomicLong> HITS = new ConcurrentHashMap<>();

    private DownstreamEchoServer() {
    }

    /** 幂等启动（多个测试 context / 独立运行共用同一实例/端口）；JVM 退出时停掉（避免野进程）。 */
    public static void start() {
        if (server != null) {
            return;
        }
        synchronized (DownstreamEchoServer.class) {
            if (server != null) {
                return;
            }
            try {
                HttpServer http = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 64);
                http.createContext("/", DownstreamEchoServer::handle);
                http.setExecutor(Executors.newFixedThreadPool(4));
                http.start();
                server = http;
                port = http.getAddress().getPort();
                Runtime.getRuntime().addShutdownHook(new Thread(() -> http.stop(0), "downstream-echo-stop"));
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }
        }
    }

    public static int port() {
        start();
        return port;
    }

    public static String baseUri() {
        return "http://127.0.0.1:" + port();
    }

    /** 某路径被下游真实处理的次数（413/400 断言"没进下游"）。 */
    public static long hits(String path) {
        AtomicLong n = HITS.get(path);
        return n == null ? 0 : n.get();
    }

    private static void handle(HttpExchange exchange) throws IOException {
        String path = exchange.getRequestURI().getPath();
        HITS.computeIfAbsent(path, k -> new AtomicLong()).incrementAndGet();
        byte[] read = exchange.getRequestBody().readAllBytes();
        String body = new String(read, StandardCharsets.UTF_8);
        String query = exchange.getRequestURI().getRawQuery() == null ? "" : exchange.getRequestURI().getRawQuery();
        String contentType = exchange.getRequestHeaders().getFirst("Content-Type");
        String payload;
        if (path.endsWith("/big")) {
            payload = BIG_PAYLOAD;
        } else if (path.equals("/test/hello") && "GET".equals(exchange.getRequestMethod())) {
            // 对齐 gateway-example/web TestController.hello（query 参数版）
            payload = "Hello, " + queryParam(exchange.getRequestURI().getRawQuery(), "name");
        } else if (path.equals("/test/hello") && contentType != null && contentType.contains("json")) {
            // 对齐 TestController.hello（JSON body 版）：回显解析后内容
            payload = "Hello, " + body;
        } else if (path.equals("/test/hello")) {
            // 对齐 TestController.helloForm（form 版）：{k=[v]} 口径
            payload = "Hello, " + formEcho(body);
        } else {
            payload = "{\"path\":\"" + path + "\",\"query\":\"" + query.replace("\"", "\\\"")
                + "\",\"body\":\"" + body.replace("\"", "\\\"").replace("\n", "") + "\"}";
        }
        byte[] out = payload.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type",
            path.equals("/test/hello") ? "text/plain;charset=UTF-8" : "application/json");
        exchange.sendResponseHeaders(200, out.length);
        exchange.getResponseBody().write(out);
        exchange.close();
    }

    private static String queryParam(String rawQuery, String name) {
        if (rawQuery == null || rawQuery.isBlank()) {
            return null;
        }
        for (String pair : rawQuery.split("&")) {
            int eq = pair.indexOf('=');
            if (eq > 0 && name.equals(pair.substring(0, eq))) {
                return URLDecoder.decode(pair.substring(eq + 1), StandardCharsets.UTF_8);
            }
        }
        return null;
    }

    /** 模拟 Spring MultiValueMap 的 toString 口径：name=1 → {name=[1]}。 */
    private static String formEcho(String body) {
        if (body == null || body.isBlank()) {
            return "{}";
        }
        StringBuilder sb = new StringBuilder("{");
        boolean first = true;
        for (String pair : body.split("&")) {
            int eq = pair.indexOf('=');
            if (!first) {
                sb.append(", ");
            }
            first = false;
            if (eq > 0) {
                sb.append(URLDecoder.decode(pair.substring(0, eq), StandardCharsets.UTF_8))
                    .append("=[").append(URLDecoder.decode(pair.substring(eq + 1), StandardCharsets.UTF_8)).append("]");
            } else {
                sb.append(URLDecoder.decode(pair, StandardCharsets.UTF_8)).append("=[]");
            }
        }
        return sb.append('}').toString();
    }
}
