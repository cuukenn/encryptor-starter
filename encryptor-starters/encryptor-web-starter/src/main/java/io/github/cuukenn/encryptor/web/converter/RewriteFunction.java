package io.github.cuukenn.encryptor.web.converter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * @author changgg
 */
public interface RewriteFunction<I, R> {
    R apply(HttpServletRequest request, HttpServletResponse response, I input);
}
