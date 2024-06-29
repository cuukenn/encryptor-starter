package io.github.cuukenn.encryptor.converter;

import io.github.cuukenn.encryptor.facade.IDataConverter;
import io.github.cuukenn.encryptor.pojo.EncryptorDataWrapper;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * @author changgg
 */
public interface DataConverter extends IDataConverter {
    EncryptorDataWrapper load(HttpServletRequest request, String data);

    void post(HttpServletResponse response, EncryptorDataWrapper data) throws IOException;
}
