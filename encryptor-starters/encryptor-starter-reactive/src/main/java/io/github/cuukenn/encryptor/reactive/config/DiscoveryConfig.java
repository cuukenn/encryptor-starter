package io.github.cuukenn.encryptor.reactive.config;

/**
 * JWKS 只读发现端点配置（客户端按 kid 取公钥，浏览器无法按需重发 ⇒ 没有它就无法平滑轮换）。
 *
 * @author changgg
 */
public class DiscoveryConfig {
    /**
     * 是否暴露发现端点；关闭后路径不存在（放行给业务）。
     */
    private boolean enable = true;
    /**
     * 端点路径。
     */
    private String path = "/.well-known/encryptor-keys";
    /**
     * 响应缓存秒数（Cache-Control: public, max-age=…）。
     */
    private int cacheMaxAgeSeconds = 300;

    public boolean isEnable() {
        return enable;
    }

    public void setEnable(boolean enable) {
        this.enable = enable;
    }

    public String getPath() {
        return path;
    }

    public void setPath(String path) {
        this.path = path;
    }

    public int getCacheMaxAgeSeconds() {
        return cacheMaxAgeSeconds;
    }

    public void setCacheMaxAgeSeconds(int cacheMaxAgeSeconds) {
        this.cacheMaxAgeSeconds = cacheMaxAgeSeconds;
    }
}
