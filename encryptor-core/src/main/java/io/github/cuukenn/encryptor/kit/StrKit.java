package io.github.cuukenn.encryptor.kit;

import cn.hutool.core.util.ReUtil;

import java.util.Collection;
import java.util.List;
import java.util.TreeSet;

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
     * 获取最佳匹配的字符串
     *
     * @param str        字符串
     * @param selectable 可选字符串集
     * @return 结果
     */
    public static String getBestMatchStr(String str, Collection<String> selectable) {
        if (str == null || selectable.isEmpty()) {
            return null;
        }
        TreeSet<String> treeSet = new TreeSet<>((s1, s2) -> s2.length() - s1.length());
        selectable.stream().filter(x -> ReUtil.isMatch(x, str)).forEach(treeSet::add);
        if (treeSet.isEmpty()) {
            return null;
        }
        return treeSet.first();
    }
}
