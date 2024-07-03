package io.github.cuukenn.encryptor.reactive.gateway.converter;

import org.springframework.cloud.gateway.filter.factory.rewrite.RewriteFunction;
import org.springframework.http.MediaType;

/**
 * @author changgg
 */
public interface MessageReader<I, O> {
    boolean canRead(MediaType mediaType);

    RewriteFunction<I, O> read();
}
