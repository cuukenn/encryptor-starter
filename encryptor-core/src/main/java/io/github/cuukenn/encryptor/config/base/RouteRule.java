package io.github.cuukenn.encryptor.config.base;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 单条路由加密策略的纯配置模型（per-route policy）。
 *
 * <p><b>为什么现在建模</b>：`crypto-config` 的值是裸 kid 列表（`Map<String, List<String>>`），
 * 将来扩展为 per-route 策略（enc/ttl/require-encrypted…）时 Map 值类型变更属于 Spring 绑定期
 * 硬破坏、alias 机制原理性失效。`routes` 平行键的值类型固定为 {@code Map<String, RouteRule>}，
 * 之后往本类<b>加字段</b>都是增量绑定（Spring 对新增属性零破坏）——键结构现在立住，扩展面就永久打开。</p>
 *
 * <p>当前只实现 {@code kids}（与 {@code crypto-config} 同语义：该 uri 允许的 kid 集合，
 * 空列表 = 不限；同键两侧并集）。预留扩展字段（加字段 = 增量，勿改 Map 值类型）：
 * enc 白名单、ttl 覆写、require-encrypted 覆写。</p>
 *
 * @author changgg
 */
public class RouteRule {

    /**
     * 该路由允许的 kid 集合；空列表 = 不限。与 {@code crypto-config} 同正则命中时取并集。
     */
    private List<String> kids = new ArrayList<>();

    public List<String> getKids() {
        return kids;
    }

    public void setKids(List<String> kids) {
        this.kids = kids;
    }

    /**
     * 路由策略查询单点：在 crypto-config（旧键）与 routes（新键）两个正则空间里找<b>最长命中</b>，
     * 返回其 kids（两键同长命中时取并集）；无任何命中返回 {@code null}（= 不限）。
     *
     * <p>两侧过滤器统一走本方法——"多正则空间合并查找"的口径单点维护，
     * 新旧键的迁移期语义（并集）由这里保证一致。</p>
     *
     * @param uri 已规范化的请求路径（{@code ContextAad.canonicalPath} 口径）
     */
    public static List<String> effectiveKids(Map<String, List<String>> cryptoConfig,
                                             Map<String, RouteRule> routes, String uri) {
        String bestRegex = null;
        List<String> kids = null;
        if (cryptoConfig != null && !cryptoConfig.isEmpty()) {
            bestRegex = io.github.cuukenn.encryptor.kit.StrKit.getBestMatchStr(uri, cryptoConfig.keySet());
            if (bestRegex != null) {
                kids = cryptoConfig.get(bestRegex);
            }
        }
        if (routes != null && !routes.isEmpty()) {
            String routeBest = io.github.cuukenn.encryptor.kit.StrKit.getBestMatchStr(uri, routes.keySet());
            if (routeBest != null) {
                List<String> routeKids = routes.get(routeBest).getKids();
                if (bestRegex == null || routeBest.length() > bestRegex.length()) {
                    bestRegex = routeBest;
                    kids = routeKids;
                } else if (routeBest.length() == bestRegex.length()) {
                    kids = union(kids, routeKids);
                }
            }
        }
        return kids;
    }

    private static List<String> union(List<String> left, List<String> right) {
        if (left == null || left.isEmpty()) {
            return right;
        }
        if (right == null || right.isEmpty()) {
            return left;
        }
        List<String> merged = new ArrayList<>(left);
        for (String kid : right) {
            if (kid != null && !merged.contains(kid)) {
                merged.add(kid);
            }
        }
        return merged;
    }

}
