package io.github.cuukenn.encryptor.config.base;

/**
 * JWKS 只读发现端点的纯配置模型（servlet/reactive 两侧共用）。
 *
 * @author changgg
 */
public class DiscoveryConfigBase {
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
