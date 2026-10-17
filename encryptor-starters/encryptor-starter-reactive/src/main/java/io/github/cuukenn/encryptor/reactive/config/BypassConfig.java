package io.github.cuukenn.encryptor.reactive.config;

/**
 * 旁路开关（初始值；运行期经 {@code EncryptorRuntime.setBypass} 热改，无需重启）。
 *
 * @author changgg
 */
public class BypassConfig {
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
