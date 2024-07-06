package io.github.cuukenn.encryptor.reactive.gateway.converter;

import org.springframework.cloud.gateway.filter.factory.rewrite.RewriteFunction;
import org.springframework.http.MediaType;

/**
 * @author changgg
 */
public interface MessageWriter<I, O> {
    /**
     * 是否可写
     *
     * @param mediaType 媒体类型
     * @return 结果
     */
    boolean canWrite(MediaType mediaType);

    /**
     * 写策略
     *
     * @return 策略
     */
    RewriteFunction<I, O> write();
}
