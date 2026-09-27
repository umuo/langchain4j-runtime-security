package io.agentsecurity.core;

/** 可替换检测器接口。实现应线程安全、无副作用，并返回固定且不含业务数据的规则标识。 */
@FunctionalInterface
public interface Detector {

    Decision evaluate(SecurityEvent event);
}
