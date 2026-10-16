package io.github.cuukenn.encryptor.web.kit;

import cn.hutool.core.thread.ThreadUtil;
import io.github.cuukenn.encryptor.facade.EncryptorFacade;
import io.github.cuukenn.encryptor.kit.StrKit;
import io.github.cuukenn.encryptor.web.config.WebEncryptorConfig;
import org.springframework.http.HttpHeaders;

import javax.servlet.http.HttpServletResponse;
import java.util.Objects;

/**
 * @author changgg
 */
public class WebContext {
    private static final ThreadLocal<WebContext> CONTEXT = ThreadUtil.createThreadLocal(WebContext::new);
    private boolean encryptor;
    private boolean reqEncryptor;
    private boolean resEncryptor;
    private EncryptorFacade encryptorFacade;
    private WebEncryptorConfig config;

    public WebEncryptorConfig getConfig() {
        return config;
    }

    public boolean isReqEncryptor() {
        return reqEncryptor;
    }

    public boolean isEncryptor() {
        return encryptor;
    }

    public void setEncryptor(boolean encryptor) {
        this.encryptor = encryptor;
    }

    public boolean isResEncryptor() {
        return resEncryptor;
    }

    public void setReqEncryptor(boolean reqEncryptor) {
        this.reqEncryptor = reqEncryptor;
    }

    public void setResEncryptor(boolean resEncryptor) {
        this.resEncryptor = resEncryptor;
    }

    public EncryptorFacade getEncryptorFacade() {
        return encryptorFacade;
    }

    public void setEncryptorFacade(EncryptorFacade encryptorFacade) {
        this.encryptorFacade = encryptorFacade;
    }

    public void setConfig(WebEncryptorConfig config) {
        this.config = config;
    }

    public static WebContext current() {
        return CONTEXT.get();
    }

    /**
     * 清理当前线程的上下文。
     *
     * <p><b>必须在请求结束时调用</b>：Servlet 容器会复用线程，ThreadLocal 不清理的话，
     * 上一个请求写入的 {@code encryptorFacade} / {@code config} / 各标志位会泄漏到下一个请求，
     * 按 uri 配不同密钥的场景下可能串号解密。</p>
     */
    public static void clear() {
        CONTEXT.remove();
    }

    public static boolean isResEncryptorEnable(HttpServletResponse response) {
        String contentType = response.getHeader(HttpHeaders.CONTENT_TYPE);
        return current().isReqEncryptor() && !(contentType != null && StrKit.anyMatch(contentType, Objects.requireNonNull(current().getConfig()).getBlackResContentType()));
    }
}
