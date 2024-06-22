package com.github.cuukenn.demo.encrypt.lectotype.core;

/**
 * @author changgg
 */
public interface IEncoderStrategy<I> {
    String encode(I data);

    I decode(String data);
}
