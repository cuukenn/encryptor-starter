package io.github.cuukenn.encryptor.kit;

import cn.hutool.core.util.ReUtil;

import java.util.Collection;
import java.util.Comparator;
import java.util.List;

/**
 * @author changgg
 */
public class StrKit {
    /**
     * 任意匹配
     *
     * @param content 内容
     * @param regexes 匹配文本
     * @return 匹配结果
     */
    public static boolean anyMatch(String content, List<String> regexes) {
        return regexes.stream().anyMatch(x -> ReUtil.isMatch(x, content));
    }

    /**
     * 获取最佳匹配的字符串。
     *
     * <p><b>契约</b>：命中者中"正则最长"的胜出；长度相同时按 {@code selectable} 的迭代顺序取先者
     * （配置来自 yml 时即声明顺序）。注意 {@link ReUtil#isMatch} 是<b>整串</b>匹配（等价
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
                .filter(x -> ReUtil.isMatch(x, str))
                .max(Comparator.comparingInt(String::length))
                .orElse(null);
    }
}
