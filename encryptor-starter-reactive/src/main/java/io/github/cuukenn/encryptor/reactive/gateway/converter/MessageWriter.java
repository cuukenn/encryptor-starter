package io.github.cuukenn.encryptor.reactive.gateway.converter;

import org.springframework.cloud.gateway.filter.factory.rewrite.RewriteFunction;
import org.springframework.http.MediaType;

/**
 * @author changgg
 */
public interface MessageWriter<I, O> {
    boolean canWrite(MediaType mediaType);

    RewriteFunction<I, O> write();
}
