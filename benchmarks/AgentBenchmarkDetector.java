import io.agentsecurity.core.Decision;
import io.agentsecurity.core.Detector;
import io.agentsecurity.core.SecurityEvent;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

/** 仅供性能探针使用：验证同一 ClassLoader 下插件只构造一次，并计数实际检查。 */
public final class AgentBenchmarkDetector implements Detector {
    public static final AtomicInteger CONSTRUCTIONS = new AtomicInteger();
    public static final AtomicLong CHECKS = new AtomicLong();

    public AgentBenchmarkDetector() {
        CONSTRUCTIONS.incrementAndGet();
    }

    @Override
    public Decision evaluate(SecurityEvent event) {
        CHECKS.incrementAndGet();
        return Decision.allow();
    }
}
