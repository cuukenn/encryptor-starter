package io.github.cuukenn.encryptor.kit;

import java.util.Collection;
import java.util.Comparator;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;

/**
 * 正则匹配工具：{@link Pattern} 预编译缓存。
 *
 * <p>正则来自配置（数量有界），进程内编译一次即可，避免每次请求 {@code Pattern.compile}。
 * 配置变更时调用 {@link #invalidate()} 重新编译。
 *
 * @author changgg
 */
public class StrKit {

    private static final ConcurrentHashMap<String, Pattern> PATTERN_CACHE = new ConcurrentHashMap<>();

    /**
     * 取（缓存的）已编译正则。
     *
     * @param regex 整串匹配的正则
     */
    static Pattern pattern(String regex) {
        return PATTERN_CACHE.computeIfAbsent(regex, Pattern::compile);
    }

    /** 清空正则缓存（配置变更后调用）。 */
    public static void invalidate() {
        PATTERN_CACHE.clear();
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
        return regexes.stream().anyMatch(x -> matches(x, content));
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
        // 用 max 而不是 TreeSet：TreeSet 的比较器对等长 key 返回 0，会把后面的同长候选静默丢掉，
        // 看起来像"随机丢一个"。max 的表达是显式的：最长优先，等长取先遇到的那个。
        return selectable.stream()
                .filter(x -> matches(x, str))
                .max(Comparator.comparingInt(String::length))
                .orElse(null);
    }
}
