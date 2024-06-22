package com.github.cuukenn.demo.encrypt.lectotype.core;

/**
 * 摘要算法
 *
 * @author changgg
 */
public interface IDigesterStrategy<I, O> {
    /**
     * 计算数据摘要
     *
     * @param data 数据
     * @return 摘要
     */
    O digest(I data);
}
