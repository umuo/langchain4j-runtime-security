package io.agentsecurity.agent.stream;

import java.util.Properties;

/** 流缓冲、事件数量、活跃流及总时限的配置；启动时验证范围。 */
public record StreamLimits(int maxChars, int maxEvents, int maxActive, int timeoutMillis) {

    public static StreamLimits from(Properties properties) {
        return new StreamLimits(
                read(properties, "stream.max.chars", 100_000, 10_000_000),
                read(properties, "stream.max.events", 2048, 100_000),
                read(properties, "stream.max.active", 64, 1024),
                read(properties, "stream.timeout.millis", 60_000, 3_600_000));
    }

    private static int read(Properties properties, String name, int fallback, int max) {
        int value = Integer.parseInt(properties.getProperty(name, Integer.toString(fallback)));
        if (value < 1 || value > max) {
            throw new IllegalArgumentException("Invalid " + name);
        }
        return value;
    }
}
