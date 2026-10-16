package io.github.cuukenn.encryptor.reactive.gateway.converter;

import cn.hutool.json.JSONUtil;
import io.github.cuukenn.encryptor.constant.CoreEncryptorConstant;
import io.github.cuukenn.encryptor.exception.EncryptorException;
import io.github.cuukenn.encryptor.pojo.EncryptorDataWrapper;
import io.github.cuukenn.encryptor.reactive.gateway.kit.GatewayKit;
import org.springframework.cloud.gateway.filter.factory.rewrite.RewriteFunction;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMessage;
import org.springframework.http.MediaType;
import org.springframework.util.MimeType;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Optional;

/**
 * @author changgg
 */
public class DefaultMessageConverter implements MessageReader<String, byte[]>, MessageWriter<String, byte[]> {
    @Override
    public boolean canRead(MediaType mediaType) {
        return false;
    }

    @Override
    public RewriteFunction<String, byte[]> read() {
        return (exchange, input) -> {
            if (input == null) {
                return Mono.empty();
            }
            // RSA/AES 是同步阻塞运算：切到弹性线程池执行，避免占用 Netty event loop（见 open-issues.md P1-13）
            return Mono.fromCallable(() -> {
                EncryptorDataWrapper dataWrapper;
                try {
                    dataWrapper = JSONUtil.toBean(input, EncryptorDataWrapper.class);
                } catch (RuntimeException e) {
                    // 报文不是合法密文结构：算"报文非法"，由过滤器回 4xx
                    throw new EncryptorException("request body is not a valid encrypted payload", e);
                }
                exchange.getAttributes().put(CoreEncryptorConstant.KEY, dataWrapper.getKey());
                return GatewayKit.getEncryptorFacade(exchange).decrypt(dataWrapper);
            }).subscribeOn(Schedulers.boundedElastic());
        };
    }

    @Override
    public boolean canWrite(MediaType mediaType) {
        return false;
    }

    @SuppressWarnings("DuplicatedCode")
    @Override
    public RewriteFunction<String, byte[]> write() {
        return (exchange, input) -> {
            if (input == null) {
                return Mono.empty();
            }
            Charset charset = Optional.of(exchange.getResponse()).map(HttpMessage::getHeaders)
                    .map(HttpHeaders::getContentType)
                    .map(MimeType::getCharset)
                    .orElse(StandardCharsets.UTF_8);
            byte[] raw = input.getBytes(charset);
            // 响应内容类型黑名单在这里判定：响应头只有到"组装响应体"这一刻才可见
            // （过滤器入口处 exchange.getResponse() 还是空的，在那里判定等于永远不生效，见 open-issues.md P1-9）
            if (!GatewayKit.isResEncryptorEnable(exchange)) {
                return Mono.just(raw);
            }
            String key = exchange.getAttribute(CoreEncryptorConstant.KEY);
            if (key == null) {
                // 明文请求（没有协商过 key）：响应无从加密，原样放行。
                // 以前会带着 key=null 去走 RSA，客户端拿到 500。
                return Mono.just(raw);
            }
            // RSA/AES 是同步阻塞运算：切到弹性线程池执行，避免占用 Netty event loop（见 open-issues.md P1-13）
            return Mono.fromCallable(() -> JSONUtil.toJsonStr(GatewayKit.getEncryptorFacade(exchange).encrypt(raw, key)).getBytes(charset))
                    .subscribeOn(Schedulers.boundedElastic());
        };
    }
}
