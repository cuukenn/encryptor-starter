package io.github.cuukenn.encryptor.examples.boot3verify;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicLong;

/**
 * 测试直发的下游 echo 服务（不引入 encryptor，符合"网关下游必须是普通应用"的约束）：
 * 用 JDK 自带 {@code com.sun.net.httpserver} 起 127.0.0.1 随机端口服务，
 * 让网关侧的加密路径（NettyRoute → 我们的装饰器 → Netty 写出）跑在真实传输上，
 * 对 SCG ordering 的验证才有断言力（Mock exchange 验不出过滤器间的真实次序）。
 *
 * @author changgg
 */
public final class DownstreamEchoServer {
    /** /api/big 的固定大响应（3 组测试共用断言口径）。 */
    public static final String BIG_PAYLOAD = "{\"marker\":\"boot3-big-response\",\"padding\":\"" + "x".repeat(16 * 1024) + "\"}";

    private static volatile HttpServer server;
    private static volatile int port = -1;
    private static final Map<String, AtomicLong> HITS = new ConcurrentHashMap<>();

    private DownstreamEchoServer() {
    }

    /** 幂等启动（多个测试 context 共用同一实例/端口）。 */
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
                http.createContext("/api", DownstreamEchoServer::handle);
                http.setExecutor(Executors.newFixedThreadPool(4));
                http.start();
                server = http;
                port = http.getAddress().getPort();
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
        String payload;
        if (path.endsWith("/big")) {
            payload = BIG_PAYLOAD;
        } else if (path.endsWith("/echo")) {
            payload = "{\"query\":\"" + query.replace("\"", "\\\"") + "\",\"body\":\"" + body.replace("\"", "\\\"") + "\"}";
        } else {
            payload = "{\"path\":\"" + path + "\"}";
        }
        byte[] out = payload.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        exchange.sendResponseHeaders(200, out.length);
        exchange.getResponseBody().write(out);
        exchange.close();
    }
}
