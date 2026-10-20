package io.github.cuukenn.encryptor.config.base;

/**
 * 旁路开关的纯配置模型（运行期可经 {@code EncryptorRuntime.setBypass} 热改）。
 *
 * @author changgg
 */
public class BypassConfigBase {
    /**
     * 请求方向原样透传：不再要求密文。
     */
    private boolean request;
    /**
     * 响应方向原样透传：不加密。
     */
    private boolean response;

    public boolean isRequest() {
        return request;
    }

    public void setRequest(boolean request) {
        this.request = request;
    }

    public boolean isResponse() {
        return response;
    }

    public void setResponse(boolean response) {
        this.response = response;
    }
}
