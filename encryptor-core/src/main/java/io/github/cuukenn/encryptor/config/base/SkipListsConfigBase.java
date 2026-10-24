package io.github.cuukenn.encryptor.config.base;

import io.github.cuukenn.encryptor.kit.StrKit;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;

/**
 * skip 名单配置的纯模型与启动期机制（无 Spring 注解）：skip-* 字段 + black-* 旧名 alias
 * 合并 + 正则预编译 + 不可命中条目（大写字符 / 含 {@code ;} 参数段）告警。
 *
 * <p>servlet 与 gateway 两侧的配置类继承本类，各自保留 {@code @ConfigurationProperties}
 * 前缀与模块特有字段，{@code afterPropertiesSet} 里调 {@link #initSkipLists(String)}——
 * skip 口径（alias 语义、precompile、告警）从此单点维护，两侧不再各抄一份。</p>
 *
 * <p>旧名 {@code black-*} 仍可绑定（已弃用，启动 WARN）：Spring Boot 对集合属性是
 * 「就地绑定（clear + 回填）」，新旧名字共用同一个 list 时后绑定的会把先绑定的清掉，
 * 故 alias 单独持有字段、绑定完成后合并去重。</p>
 *
 * @author changgg
 */
public abstract class SkipListsConfigBase {

    private static final Logger LOG = LoggerFactory.getLogger(SkipListsConfigBase.class);

    /**
     * 完全跳过加解密的 uri（整串正则匹配，非通配符；前缀匹配请写 {@code .*}）。
     *
     * <p>旧名 {@code black-uris} 仍可绑定（已弃用）：那个名字与语义相反——命中即<b>跳过</b>，不是拦截。</p>
     */
    private final List<String> skipUris = new ArrayList<>();
    /**
     * 完全跳过加解密的 HTTP 方法（整串正则，匹配输入按规范大写归一）。旧名 {@code black-methods} 仍可绑定（已弃用）。
     */
    private final List<String> skipMethods = new ArrayList<>();
    /**
     * 请求方向跳过的 Content-Type（media-type 段小写后整串正则匹配）。旧名 {@code black-req-content-type} 仍可绑定（已弃用）。
     */
    private final List<String> skipReqContentType = new ArrayList<>();
    /**
     * 响应方向跳过的 Content-Type（media-type 段小写后整串正则匹配，链后 Content-Type 落定判定）。
     * 默认跳过 SSE：流式响应一旦被整段缓冲，事件要等请求结束才下发，超过 max-response-size 还会变 500；
     * 需要加密流式响应时显式清空该名单（代价是客户端要等完整响应）。
     * 旧名 {@code black-res-content-type} 仍可绑定（已弃用）。
     */
    private final List<String> skipResContentType = new ArrayList<>(Collections.singletonList("text/event-stream"));
    /**
     * 旧名 {@code black-*} 的绑定目标（已弃用）：绑定完成后由 {@link #initSkipLists(String)} 并入上面的 skip 名单。
     */
    private final List<String> blackUris = new ArrayList<>();
    private final List<String> blackMethods = new ArrayList<>();
    private final List<String> blackReqContentType = new ArrayList<>();
    private final List<String> blackResContentType = new ArrayList<>();

    public List<String> getSkipUris() {
        return skipUris;
    }

    public void setSkipUris(List<String> skipUris) {
        replace(this.skipUris, skipUris);
    }

    public List<String> getSkipMethods() {
        return skipMethods;
    }

    public void setSkipMethods(List<String> skipMethods) {
        replace(this.skipMethods, skipMethods);
    }

    /** @deprecated 旧名 alias（名字与语义相反：命中即跳过）；请改用 {@link #setSkipUris(List)}。 */
    @Deprecated
    public List<String> getBlackUris() {
        return blackUris;
    }

    /** @deprecated 见 {@link #getBlackUris()}。 */
    @Deprecated
    public void setBlackUris(List<String> blackUris) {
        replace(this.blackUris, blackUris);
    }

    /** @deprecated 旧名 alias；请改用 {@link #setSkipMethods(List)}。 */
    @Deprecated
    public List<String> getBlackMethods() {
        return blackMethods;
    }

    /** @deprecated 见 {@link #getBlackMethods()}。 */
    @Deprecated
    public void setBlackMethods(List<String> blackMethods) {
        replace(this.blackMethods, blackMethods);
    }

    public List<String> getSkipReqContentType() {
        return skipReqContentType;
    }

    public void setSkipReqContentType(List<String> skipReqContentType) {
        replace(this.skipReqContentType, skipReqContentType);
    }

    public List<String> getSkipResContentType() {
        return skipResContentType;
    }

    public void setSkipResContentType(List<String> skipResContentType) {
        replace(this.skipResContentType, skipResContentType);
    }

    /** @deprecated 旧名 alias；请改用 {@link #setSkipReqContentType(List)}。 */
    @Deprecated
    public List<String> getBlackReqContentType() {
        return blackReqContentType;
    }

    /** @deprecated 见 {@link #getBlackReqContentType()}。 */
    @Deprecated
    public void setBlackReqContentType(List<String> blackReqContentType) {
        replace(this.blackReqContentType, blackReqContentType);
    }

    /** @deprecated 旧名 alias；请改用 {@link #setSkipResContentType(List)}。 */
    @Deprecated
    public List<String> getBlackResContentType() {
        return blackResContentType;
    }

    /** @deprecated 见 {@link #getBlackResContentType()}。 */
    @Deprecated
    public void setBlackResContentType(List<String> blackResContentType) {
        replace(this.blackResContentType, blackResContentType);
    }

    /**
     * skip 名单的启动期机制（两侧 afterPropertiesSet 调用，prefix 为各自配置前缀）：
     * 不可命中条目告警 → 旧名 alias 合并 → 全部正则预编译（非法配置直接启动失败）。
     */
    protected void initSkipLists(String prefix) {
        warnUnmatchableCasing(prefix, getSkipReqContentType(), "skip-req-content-type");
        warnUnmatchableCasing(prefix, getSkipResContentType(), "skip-res-content-type");
        warnParameterSuffix(prefix, getSkipReqContentType(), "skip-req-content-type");
        warnParameterSuffix(prefix, getSkipResContentType(), "skip-res-content-type");
        mergeAlias(prefix, "black-uris", skipUris, blackUris);
        mergeAlias(prefix, "black-methods", skipMethods, blackMethods);
        mergeAlias(prefix, "black-req-content-type", skipReqContentType, blackReqContentType);
        mergeAlias(prefix, "black-res-content-type", skipResContentType, blackResContentType);
        StrKit.precompile(prefix + ".skip-uris", skipUris);
        StrKit.precompile(prefix + ".skip-methods", skipMethods);
        StrKit.precompile(prefix + ".skip-req-content-type", skipReqContentType);
        StrKit.precompile(prefix + ".skip-res-content-type", skipResContentType);
    }

    /** 旧名并入生效名单（去重、幂等），并落一次弃用 WARN（迁移提示）。 */
    private static void mergeAlias(String prefix, String oldName, List<String> target, List<String> alias) {
        if (alias == null || alias.isEmpty()) {
            return;
        }
        LOG.warn("配置 {}.{} 已弃用（名字与语义相反：命中即跳过），请改用 {}.{}；本次仍生效",
            prefix, oldName, prefix, oldName.replace("black-", "skip-"));
        for (String value : alias) {
            if (value != null && !target.contains(value)) {
                target.add(value);
            }
        }
    }

    /** 覆盖式写入（与 Spring Boot 对集合属性的就地绑定语义保持一致）。 */
    private static void replace(List<String> target, List<String> values) {
        target.clear();
        if (values != null) {
            target.addAll(values);
        }
    }

    /**
     * content-type 匹配侧会先对实际请求/响应头做小写归一：配置条目含大写字符时永远不命中，
     * 启动期告警让这种静默失效可见（正则不能安全地自动转小写，只能提示）。
     */
    private static void warnUnmatchableCasing(String prefix, List<String> regexes, String name) {
        for (String regex : regexes) {
            if (regex != null && !regex.equals(regex.toLowerCase(Locale.ROOT))) {
                LOG.warn("配置 {}.{} 含大写字符: \"{}\"——请求/响应 content-type 会先小写归一再匹配，该条目永远不会命中",
                    prefix, name, regex);
            }
        }
    }

    /**
     * content-type 匹配侧会先剥掉 {@code ;charset=} 等参数（media-type 段）再整串匹配：
     * 配置条目含 {@code ;} 时永远不命中，启动期告警提示改写为纯 media-type 部分。
     */
    private static void warnParameterSuffix(String prefix, List<String> regexes, String name) {
        for (String regex : regexes) {
            if (regex != null && regex.indexOf(';') >= 0) {
                LOG.warn("配置 {}.{} 含参数段 ';': \"{}\"——请求/响应 content-type 会先剥掉 ; 参数再匹配，"
                    + "该条目永远不会命中（请只写 media-type 部分）", prefix, name, regex);
            }
        }
    }
}
