package io.agentsecurity.core.health;

/** 执行池的只读近似快照；计数累计，活动数和队列长度不是跨字段原子值。 */
public record WorkerHealth(
        int active,
        int queued,
        int concurrency,
        int capacity,
        boolean closed,
        boolean failed,
        long timeouts,
        long errors,
        long rejected,
        long interrupted) {}
