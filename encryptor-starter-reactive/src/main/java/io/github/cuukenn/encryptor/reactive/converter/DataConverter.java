package io.github.cuukenn.encryptor.reactive.converter;

import io.github.cuukenn.encryptor.facade.IDataConverter;
import io.github.cuukenn.encryptor.pojo.EncryptorDataWrapper;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;

/**
 * @author changgg
 */
public interface DataConverter extends IDataConverter {
    EncryptorDataWrapper load(ServerHttpRequest request, String data);

    String post(ServerHttpResponse response, EncryptorDataWrapper data);
}
