package io.github.cuukenn.encryptor.reactive.gateway.converter;

import org.springframework.cloud.gateway.filter.factory.rewrite.RewriteFunction;
import org.springframework.http.MediaType;

/**
 * @author changgg
 */
public interface MessageReader<I, O> {
    /**
     * 是否可读
     *
     * @param mediaType 媒体类型
     * @return 结果
     */
    boolean canRead(MediaType mediaType);

    /**
     * 读取策略
     *
     * @return 策略
     */
    RewriteFunction<I, O> read();
}
