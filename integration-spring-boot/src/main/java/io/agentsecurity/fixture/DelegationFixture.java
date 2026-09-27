package io.agentsecurity.fixture;

import dev.langchain4j.agent.tool.Tool;
import dev.langchain4j.agent.tool.ToolExecutionRequest;
import dev.langchain4j.service.tool.DefaultToolExecutor;
import io.agentsecurity.core.*;
import io.agentsecurity.core.delegation.*;
import io.agentsecurity.core.telemetry.SecurityTelemetry;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Set;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;

/** 使用真实 LangChain4j 工具执行器验证子任务委托，而不是仅调用 SDK 模拟检查。 */
final class DelegationFixture {
    private static final AtomicInteger calls = new AtomicInteger();
    private static final AgentGrant FULL =
            AgentGrant.tools(Set.of("read", "write"), Set.of("lookup", "delete"));
    private static final AgentGrant READ = AgentGrant.tools(Set.of("read"), Set.of("lookup"));

    public static final class Tools {
        @Tool
        public String lookup() {
            calls.incrementAndGet();
            return "safe record";
        }

        @Tool
        public String delete() {
            calls.incrementAndGet();
            return "deleted";
        }
    }

    static void run(String scenario) throws Exception {
        boolean blocked = false;
        String reason = "allow";
        var identity =
                SecurityContext.authenticated(
                        "tenant-delegation", "principal-delegation", Set.of("read", "write"));
        try (var journal =
                        new FileAuditSink(
                                Path.of(System.getProperty("delegation.audit.path")),
                                100000,
                                1,
                                false,
                                "delegation-v1");
                var runtime =
                        new AgentRuntime(
                                List.of(
                                        new AgentDefinition("planner", FULL, Set.of("reader")),
                                        new AgentDefinition("reader", READ, Set.of())),
                                AgentRuntimeLimits.defaults(),
                                journal,
                                SecurityTelemetry.global())) {
            if (scenario.equals("delegation-missing")) {
                invoke("lookup");
            } else {
                var root = runtime.startRoot("planner", identity, FULL, Duration.ofMinutes(1));
                root.call(
                        () -> {
                            var child = runtime.delegate("reader", FULL, Duration.ofMinutes(1));
                            if (scenario.equals("delegation-revoked")) {
                                root.revoke();
                                try (var scope = SecurityContexts.open(child.context())) {
                                    invoke("lookup");
                                }
                            } else if (scenario.equals("delegation-spoof")) {
                                var context = child.context();
                                try (var scope =
                                        SecurityContexts.open(
                                                new SecurityContext(
                                                        context.runId(),
                                                        "other-tenant",
                                                        context.principalId(),
                                                        context.permissions(),
                                                        child))) {
                                    invoke("lookup");
                                }
                            } else if (scenario.equals("delegation-async")) {
                                var pool = Executors.newFixedThreadPool(2);
                                try {
                                    var sibling =
                                            runtime.delegate("reader", FULL, Duration.ofMinutes(1));
                                    var a = child.submit(pool, () -> invoke("lookup"));
                                    var b = sibling.submit(pool, () -> invoke("lookup"));
                                    a.get();
                                    b.get();
                                } finally {
                                    pool.shutdownNow();
                                }
                            } else {
                                child.call(
                                        () ->
                                                invoke(
                                                        scenario.equals("delegation-denied")
                                                                ? "delete"
                                                                : "lookup"));
                            }
                            return null;
                        });
            }
        } catch (SecurityBlockedException failure) {
            blocked = true;
            reason = failure.ruleId();
        }
        var telemetryRecords = SecurityTelemetry.global().drain(256);
        var toolRecord =
                telemetryRecords.stream()
                        .filter(record -> record.phase() == SecurityEvent.Phase.TOOL_INPUT)
                        .findFirst()
                        .orElseThrow();
        boolean correlated =
                scenario.equals("delegation-missing")
                        ? toolRecord.invocationId() == null
                        : telemetryRecords.stream()
                                .anyMatch(
                                        record ->
                                                record.phase() == SecurityEvent.Phase.AGENT_DELEGATE
                                                        && record.invocationId()
                                                                .equals(toolRecord.invocationId())
                                                        && record.parentInvocationId()
                                                                .equals(
                                                                        toolRecord
                                                                                .parentInvocationId()));
        if (!correlated || telemetryRecords.toString().contains("principal-delegation")) {
            throw new IllegalStateException("Telemetry correlation or privacy failure");
        }
        var starts =
                telemetryRecords.stream()
                        .filter(
                                record ->
                                        record.phase() == SecurityEvent.Phase.AGENT_START
                                                || record.phase()
                                                        == SecurityEvent.Phase.AGENT_DELEGATE)
                        .map(record -> record.invocationId())
                        .collect(java.util.stream.Collectors.toSet());
        var ends = telemetryRecords.stream().filter(record -> record.endReason() != null).toList();
        if (ends.size() != starts.size()
                || !ends.stream()
                        .map(record -> record.invocationId())
                        .collect(java.util.stream.Collectors.toSet())
                        .equals(starts)
                || ends.stream().anyMatch(record -> record.lifetimeNanos() <= 0)) {
            throw new IllegalStateException("Incomplete lifecycle records");
        }
        System.out.println("TELEMETRY_RESULT correlated=" + correlated + " lifecycleComplete=true");
        System.out.printf(
                "DELEGATION_RESULT scenario=%s blocked=%s toolCalls=%d restored=%s reason=%s%n",
                scenario, blocked, calls.get(), SecurityContexts.current() == null, reason);
    }

    private static String invoke(String tool) throws Exception {
        var executor = new DefaultToolExecutor(new Tools(), Tools.class.getMethod(tool));
        return executor.execute(
                ToolExecutionRequest.builder().name(tool).arguments("{}").build(),
                "fixture-session");
    }
}
