package io.github.cuukenn.encryptor.kit;

import java.util.Collection;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * 正则匹配工具：{@link Pattern} 预编译缓存。
 *
 * <p>正则来自配置（数量有界），进程内编译一次即可，避免每次请求 {@code Pattern.compile}。
 * 配置变更时调用 {@link #invalidate()} 重新编译。
 *
 * @author changgg
 */
public class StrKit {

    /**
     * 缓存上限：正则应来自配置（数量有界）。{@code matches} 是 public 方法，一旦被业务代码
     * 传入动态 regex，无界缓存会变成内存放大点——超过上限后不再缓存，直接现场编译（变慢但不漏）。
     */
    private static final int MAX_CACHE_SIZE = 256;

    private static final ConcurrentHashMap<String, Pattern> PATTERN_CACHE = new ConcurrentHashMap<>();

    /**
     * 取（缓存的）已编译正则。
     *
     * @param regex 整串匹配的正则
     */
    static Pattern pattern(String regex) {
        if (PATTERN_CACHE.size() >= MAX_CACHE_SIZE) {
            return PATTERN_CACHE.containsKey(regex) ? PATTERN_CACHE.get(regex) : Pattern.compile(regex);
        }
        return PATTERN_CACHE.computeIfAbsent(regex, Pattern::compile);
    }

    /** 清空正则缓存（配置变更后调用）。 */
    public static void invalidate() {
        PATTERN_CACHE.clear();
    }

    /**
     * 启动期预编译并校验（带配置名）：非法正则会带上配置项名称与原始正则，
     * 便于直接定位是哪个配置写错了。
     *
     * @param name    配置项名称（如 {@code crypto-config}）
     * @param regexes 配置里的正则集合，{@code null} 视为空集合
     */
    public static void precompile(String name, Collection<String> regexes) {
        if (regexes == null) {
            return;
        }
        for (String regex : regexes) {
            if (regex == null) {
                throw new IllegalArgumentException(name + " 中的正则不能为 null");
            }
            try {
                pattern(regex);
            } catch (PatternSyntaxException e) {
                throw new IllegalArgumentException(name + " 含非法正则: " + regex
                    + " (" + e.getDescription() + ")", e);
            }
        }
    }

    /**
     * 取 content-type 的 media-type 段（剥掉 {@code ;} 参数，如 {@code text/event-stream;charset=UTF-8}
     * → {@code text/event-stream}）：skip 名单按整串正则匹配，不剥参数的话带参数的真实头
     * （SSE 常见形态）永远匹配不上默认条目。
     */
    public static String mediaType(String contentType) {
        if (contentType == null || contentType.isEmpty()) {
            return contentType;
        }
        int semicolon = contentType.indexOf(';');
        return semicolon < 0 ? contentType : contentType.substring(0, semicolon).trim();
    }

    /**
     * 整串匹配（等价 {@code Pattern.matches}，与旧 {@code ReUtil.isMatch} 语义一致）。
     *
     * @param regex 整串匹配的正则
     * @param input 待匹配文本，{@code null} 返回 {@code false}
     */
    public static boolean matches(String regex, String input) {
        return input != null && pattern(regex).matcher(input).matches();
    }

    /**
     * 任意匹配
     *
     * @param content 内容
     * @param regexes 匹配文本
     * @return 匹配结果
     */
    public static boolean anyMatch(String content, List<String> regexes) {
        if (content == null || regexes == null) {
            return false;
        }
        for (String regex : regexes) {
            if (matches(regex, content)) {
                return true;
            }
        }
        return false;
    }

    /**
     * 获取最佳匹配的字符串。
     *
     * <p><b>契约</b>：命中者中"正则最长"的胜出；长度相同时按 {@code selectable} 的迭代顺序取先者
     * （配置来自 yml 时即声明顺序）。注意匹配是<b>整串</b>匹配（等价
     * {@code Pattern.matches}），需要前缀/包含匹配要自己写 {@code .*}。</p>
     *
     * @param str        字符串
     * @param selectable 可选字符串集
     * @return 结果，无命中时返回 {@code null}
     */
    public static String getBestMatchStr(String str, Collection<String> selectable) {
        if (str == null || selectable == null || selectable.isEmpty()) {
            return null;
        }
        // 最长优先，等长取迭代顺序中的先者（不能换成 TreeSet：比较器对等长 key 返回 0 会静默丢候选）。
        String best = null;
        int bestLength = -1;
        for (String candidate : selectable) {
            if (candidate.length() > bestLength && matches(candidate, str)) {
                best = candidate;
                bestLength = candidate.length();
            }
        }
        return best;
    }
}
