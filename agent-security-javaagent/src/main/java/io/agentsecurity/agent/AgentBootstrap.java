package io.agentsecurity.agent;

import io.agentsecurity.agent.bridge.Bridge;
import io.agentsecurity.agent.bridge.MemoryBridge;
import io.agentsecurity.agent.bridge.RagBridge;
import io.agentsecurity.agent.stream.GuardedStream;
import io.agentsecurity.agent.stream.StreamLimits;
import io.agentsecurity.core.BoundedAuditSink;
import io.agentsecurity.core.Decision;
import io.agentsecurity.core.DetectionLimits;
import io.agentsecurity.core.Detector;
import io.agentsecurity.core.FileAuditSink;
import io.agentsecurity.core.LocalPolicy;
import io.agentsecurity.core.PolicyEngine;
import io.agentsecurity.core.RequiredContextPolicy;
import io.agentsecurity.core.SecurityEvent;
import java.lang.instrument.Instrumentation;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Properties;

/** 加载并校验配置，组装检测链、审计和资源上限；配置错误直接阻止启动。 */
final class AgentBootstrap {

    static void initialize(String arguments, Instrumentation instrumentation) throws Exception {
        for (Class<?> loaded : instrumentation.getAllLoadedClasses()) {
            if (loaded.getName().startsWith("dev.langchain4j.")) {
                throw new IllegalStateException(
                        "LangChain4j already loaded; put the security agent before agents that load it");
            }
        }
        if (arguments == null || arguments.isBlank()) {
            throw new IllegalArgumentException(
                    "Use -javaagent:agent.jar=/absolute/path/policy.properties");
        }
        Properties properties = new Properties();
        try (var reader = Files.newBufferedReader(Path.of(arguments), StandardCharsets.UTF_8)) {
            properties.load(reader);
        }
        StreamLimits streamLimits = StreamLimits.from(properties);
        RagBridge.initialize(properties);
        MemoryBridge.initialize(properties);
        Properties localProperties = new Properties();
        var streamKeys =
                java.util.Set.of(
                        "telemetry.enabled",
                        "stream.max.chars",
                        "stream.max.events",
                        "stream.max.active",
                        "stream.timeout.millis",
                        "detector.timeout.millis",
                        "detector.max.concurrent",
                        "audit.path",
                        "audit.max.bytes",
                        "audit.backups",
                        "audit.force",
                        "audit.timeout.millis",
                        "audit.queue.capacity",
                        "policy.version",
                        "tool.policy.path",
                        "context.required",
                        "rag.max.contents",
                        "rag.max.metadata.entries",
                        "memory.max.messages");
        for (String key : properties.stringPropertyNames()) {
            if (!streamKeys.contains(key)) {
                localProperties.setProperty(key, properties.getProperty(key));
            }
        }
        var detectors = new ArrayList<Detector>();
        String requireContext = properties.getProperty("context.required", "false");
        if (!requireContext.equals("true") && !requireContext.equals("false")) {
            throw new IllegalArgumentException("Invalid context.required");
        }
        if (requireContext.equals("true")) {
            detectors.add(new RequiredContextPolicy());
        }
        LocalPolicy localPolicy = new LocalPolicy(localProperties);
        detectors.add(localPolicy);
        if (properties.containsKey("tool.policy.path")) {
            String file = properties.getProperty("tool.policy.path");
            if (file.isBlank()) {
                throw new IllegalArgumentException("Empty tool.policy.path");
            }
            Path path = Path.of(arguments).toAbsolutePath().getParent().resolve(file).normalize();
            detectors.add(io.agentsecurity.policy.ToolPolicy.fromPath(path, localPolicy));
        }
        var limits =
                new DetectionLimits(
                        java.time.Duration.ofMillis(
                                Long.parseLong(
                                        properties.getProperty("detector.timeout.millis", "500"))),
                        Integer.parseInt(properties.getProperty("detector.max.concurrent", "4")));
        String policyVersion = properties.getProperty("policy.version", "unversioned");
        if (!policyVersion.matches("[a-zA-Z0-9_.-]{1,80}")) {
            throw new IllegalArgumentException("Invalid policy.version");
        }
        String forceValue = properties.getProperty("audit.force", "true");
        if (!forceValue.equals("true") && !forceValue.equals("false")) {
            throw new IllegalArgumentException("Invalid audit.force");
        }
        if (!properties.containsKey("audit.path")
                && java.util.stream.Stream.of("audit.force", "audit.max.bytes", "audit.backups")
                        .anyMatch(properties::containsKey)) {
            throw new IllegalArgumentException("File audit settings require audit.path");
        }
        java.util.function.BiConsumer<SecurityEvent, Decision> auditTarget =
                (event, decision) -> {
                    // Deliberately omit prompt, tool arguments, results and arbitrary user-supplied
                    // names.
                    synchronized (System.err) {
                        System.err.printf(
                                "[agent-security] event=%s run=%s decision=%s phase=%s rule=%s policy=%s invocation=%s parent=%s%n",
                                event.id(),
                                event.context() == null ? "none" : event.context().runId(),
                                decision.allowed() ? "ALLOW" : "DENY",
                                event.phase(),
                                decision.ruleId(),
                                policyVersion,
                                event.context() == null || event.context().invocation() == null
                                        ? "none"
                                        : event.context().invocation().invocationId(),
                                event.context() == null || event.context().invocation() == null
                                        ? "none"
                                        : event.context().invocation().parentInvocationId());
                        if (System.err.checkError()) {
                            throw new IllegalStateException("Audit stderr failed");
                        }
                    }
                };
        if (properties.containsKey("audit.path")) {
            String auditPath = properties.getProperty("audit.path");
            if (auditPath.isBlank()) {
                throw new IllegalArgumentException("Empty audit.path");
            }
            auditTarget =
                    new FileAuditSink(
                            Path.of(auditPath),
                            Long.parseLong(properties.getProperty("audit.max.bytes", "10485760")),
                            Integer.parseInt(properties.getProperty("audit.backups", "5")),
                            Boolean.parseBoolean(forceValue),
                            policyVersion);
        }
        var audit =
                new BoundedAuditSink(
                        auditTarget,
                        java.time.Duration.ofMillis(
                                Long.parseLong(
                                        properties.getProperty("audit.timeout.millis", "1000"))),
                        Integer.parseInt(properties.getProperty("audit.queue.capacity", "128")));
        String telemetryEnabled = properties.getProperty("telemetry.enabled", "false");
        if (!telemetryEnabled.equals("true") && !telemetryEnabled.equals("false")) {
            throw new IllegalArgumentException("Invalid telemetry.enabled");
        }
        var telemetry =
                telemetryEnabled.equals("true")
                        ? io.agentsecurity.core.telemetry.SecurityTelemetry.global()
                        : io.agentsecurity.core.telemetry.SecurityTelemetry.disabled();
        PolicyEngine policyEngine = new PolicyEngine(detectors, audit, limits, telemetry);
        Bridge.initialize(
                policyEngine,
                Integer.parseInt(localProperties.getProperty("max.text.chars", "100000")));
        Runtime.getRuntime()
                .addShutdownHook(
                        new Thread(
                                () -> {
                                    policyEngine.close();
                                    audit.close();
                                },
                                "agent-security-shutdown"));
        GuardedStream.initialize(streamLimits);
    }
}
