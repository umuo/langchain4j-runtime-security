package io.agentsecurity.policy.remote;

import io.agentsecurity.core.SecurityEvent;
import java.net.URI;
import java.time.Duration;
import java.util.Objects;
import java.util.Set;

/** 可信宿主配置；端点不能从模型输出或工具参数取得，HTTP 仅允许显式本机测试地址。 */
public record RemoteDetectorSettings(
        URI endpoint,
        Duration timeout,
        int maxConcurrent,
        int maxRequestBytes,
        String policyVersion,
        Set<SecurityEvent.Phase> phases) {
    public RemoteDetectorSettings {
        Objects.requireNonNull(endpoint);
        Objects.requireNonNull(timeout);
        phases = Set.copyOf(phases);
        boolean localHttp =
                "http".equals(endpoint.getScheme())
                        && Set.of("localhost", "127.0.0.1", "[::1]")
                                .contains(endpoint.getHost() == null ? "" : endpoint.getHost());
        if (endpoint.getHost() == null
                || endpoint.getUserInfo() != null
                || endpoint.getQuery() != null
                || endpoint.getFragment() != null
                || endpoint.getPort() == 0
                || endpoint.getPort() > 65535
                || !("https".equals(endpoint.getScheme()) || localHttp)
                || timeout.compareTo(Duration.ofMillis(10)) < 0
                || timeout.compareTo(Duration.ofSeconds(30)) > 0
                || maxConcurrent < 1
                || maxConcurrent > 128
                || maxRequestBytes < 1024
                || maxRequestBytes > 65536
                || policyVersion == null
                || !policyVersion.matches("[a-zA-Z0-9_.-]{1,80}")
                || phases.isEmpty()) {
            throw new IllegalArgumentException("Invalid remote detector settings");
        }
    }
}
