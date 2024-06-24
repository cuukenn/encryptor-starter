package com.github.cuukenn.demo.encrypt.lectotype.config;

import java.time.Duration;

/**
 * @author changgg
 */
public class NonceCheckerConfig {
    private Duration offsetTime = Duration.ofSeconds(30);
    private Integer inMemoryCacheSize = 1000;

    public Duration getOffsetTime() {
        return offsetTime;
    }

    public void setOffsetTime(Duration offsetTime) {
        this.offsetTime = offsetTime;
    }

    public Integer getInMemoryCacheSize() {
        return inMemoryCacheSize;
    }

    public void setInMemoryCacheSize(Integer inMemoryCacheSize) {
        this.inMemoryCacheSize = inMemoryCacheSize;
    }
}
