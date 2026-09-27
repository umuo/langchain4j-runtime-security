package io.agentsecurity.fixture;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Properties;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

class DelegationIT {
    @TempDir Path temporary;

    @ParameterizedTest
    @CsvSource({
        "delegation-allowed,false,1,allow",
        "delegation-denied,true,0,agent-tool-denied",
        "delegation-spoof,true,0,agent-context-mismatch",
        "delegation-revoked,true,0,agent-invocation-inactive",
        "delegation-missing,true,0,missing-agent-context",
        "delegation-async,false,2,allow"
    })
    void actualAgentEnforcesDelegatedToolCallsAndAuditsLineage(
            String scenario, boolean blocked, int tools, String reason) throws Exception {
        Path root = Path.of("..").toAbsolutePath().normalize();
        Path policy = temporary.resolve("policy.properties");
        Path decisions = temporary.resolve("decisions.jsonl");
        Path lifecycle = temporary.resolve("lifecycle.jsonl");
        Path log = temporary.resolve("process.log");
        var properties = new Properties();
        properties.setProperty("agent.context.required", "true");
        properties.setProperty("audit.path", decisions.toString());
        try (var writer = Files.newBufferedWriter(policy)) {
            properties.store(writer, "Delegation integration");
        }
        Process process =
                new ProcessBuilder(
                                Path.of(System.getProperty("java.home"), "bin", "java").toString(),
                                "-Ddelegation.audit.path=" + lifecycle,
                                "-javaagent:"
                                        + root.resolve(
                                                "agent-security-javaagent/target/agent-security-javaagent.jar")
                                        + "="
                                        + policy,
                                "-jar",
                                root.resolve("integration-spring-boot/target/boot-fixture.jar")
                                        .toString(),
                                "--scenario=" + scenario,
                                "--spring.main.banner-mode=off",
                                "--logging.level.root=ERROR")
                        .redirectErrorStream(true)
                        .redirectOutput(log.toFile())
                        .start();
        if (!process.waitFor(30, TimeUnit.SECONDS)) {
            process.destroyForcibly();
            fail("Delegation child timed out: " + Files.readString(log));
        }
        String output = Files.readString(log);
        assertEquals(0, process.exitValue(), output);
        assertTrue(
                output.contains(
                        "DELEGATION_RESULT scenario="
                                + scenario
                                + " blocked="
                                + blocked
                                + " toolCalls="
                                + tools
                                + " restored=true reason="
                                + reason),
                output);
        String audit = Files.readString(decisions);
        String links = Files.readString(lifecycle);
        assertTrue(audit.contains("\"schemaVersion\":3"), audit);
        assertFalse(audit.contains("principal-delegation"));
        if (!scenario.equals("delegation-spoof")) {
            assertFalse(audit.contains("tenant-delegation"));
        }
        if (scenario.equals("delegation-missing")) {
            assertEquals("", links);
        } else {
            assertTrue(links.contains("AGENT_START") && links.contains("AGENT_DELEGATE"), links);
            var matcher = Pattern.compile("\"invocationId\":\"([a-f0-9-]+)\"").matcher(links);
            assertTrue(matcher.find());
            String parentId = matcher.group(1);
            assertTrue(audit.contains("\"parentInvocationId\":\"" + parentId + "\""), audit);
            assertTrue(links.contains("AGENT_FINISH") || links.contains("AGENT_REVOKE"), links);
        }
    }
}
