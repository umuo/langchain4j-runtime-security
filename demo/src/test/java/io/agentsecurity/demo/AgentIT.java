package io.agentsecurity.demo;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

/** Every assertion exercises the packaged agent in a new JVM, not direct Advice calls. */
class AgentIT {

    @TempDir Path temporary;

    final Path root = Path.of("..").toAbsolutePath().normalize();

    @ParameterizedTest
    @CsvSource({
        "rag-input,true,true,0,0",
        "rag-output,true,true,1,0",
        "rag-allowed,true,false,1,1",
        "rag-output,false,false,1,1"
    })
    void unmodifiedRagApplicationIsProtectedAtTheRetrievalBoundary(
            String scenario, boolean agent, boolean blocked, int reads, int models)
            throws Exception {
        String output = run(scenario, agent, root.resolve("config/demo.properties"));
        assertTrue(
                output.contains("blocked=" + blocked + " modelCalls=" + models + " toolCalls=0"),
                output);
        assertTrue(output.contains("RETRIEVAL_CALLS=" + reads), output);
        if (agent && scenario.equals("rag-output")) {
            assertTrue(output.contains("decision=DENY phase=RETRIEVAL_OUTPUT"), output);
        }
        assertFalse(output.contains("DEMO_SECRET_123"), output);
    }

    private String run(String scenario, boolean agent, Path config) throws Exception {
        return run(scenario, agent, config, null);
    }

    private String run(String scenario, boolean agent, Path config, Path metadata)
            throws Exception {
        var command = new ArrayList<String>();
        command.add(Path.of(System.getProperty("java.home"), "bin", "java").toString());
        if (agent) {
            command.add(
                    "-javaagent:"
                            + root.resolve(
                                    "agent-security-javaagent/target/agent-security-javaagent.jar")
                            + "="
                            + config);
        }
        if (metadata == null) {
            command.add("-jar");
            command.add(root.resolve("demo/target/agent-security-demo.jar").toString());
        } else {
            command.add("-cp");
            command.add(
                    metadata
                            + java.io.File.pathSeparator
                            + root.resolve("demo/target/agent-security-demo.jar"));
            command.add("io.agentsecurity.demo.Demo");
        }
        command.add(scenario);
        Path log = temporary.resolve("process-" + System.nanoTime() + ".log");
        Process process =
                new ProcessBuilder(command)
                        .redirectErrorStream(true)
                        .redirectOutput(log.toFile())
                        .start();
        if (!process.waitFor(25, TimeUnit.SECONDS)) {
            process.destroyForcibly();
            fail("Child JVM timed out");
        }
        String output = Files.readString(log);
        assertEquals(0, process.exitValue(), output);
        if (agent) {
            assertTrue(output.contains("[agent-security] installed"), output);
            assertTrue(output.contains("instrumented="), output);
        }
        return output;
    }

    @ParameterizedTest
    @CsvSource({
        "1.20.1,allowed,false,2,1",
        "1.20.1,direct-tool,true,0,0",
        "1.21.0,allowed,false,2,1",
        "1.21.0,direct-tool,true,0,0",
        "1.22.0,allowed,true,0,0",
        "1.20.1-SNAPSHOT,allowed,true,0,0"
    })
    void versionAdmissionPreservesThePackagedAgentSecurityBoundary(
            String version, String scenario, boolean blocked, int models, int tools)
            throws Exception {
        // Change metadata only: this tests admission, not compatibility of a different artifact.
        Path metadata = temporary.resolve("metadata");
        Path properties =
                metadata.resolve("META-INF/maven/dev.langchain4j/langchain4j-core/pom.properties");
        Files.createDirectories(properties.getParent());
        Files.writeString(properties, "version=" + version + "\n");
        String output = run(scenario, true, root.resolve("config/demo.properties"), metadata);
        assertTrue(
                output.contains(
                        "blocked=" + blocked + " modelCalls=" + models + " toolCalls=" + tools),
                output);
        if (scenario.equals("direct-tool")) {
            assertTrue(output.contains("rule=denied-tool"), output);
        }
        if (version.equals("1.22.0") || version.endsWith("-SNAPSHOT")) {
            assertTrue(output.contains("unsupported-langchain4j-version"), output);
        }
    }

    @ParameterizedTest
    @CsvSource({
        "input,0,0",
        "output,1,0",
        "tool,1,0",
        "tool-output,1,1",
        "async-input,0,0",
        "async-output,1,0",
        "async-tool,1,0",
        "async-tool-output,1,1",
        "stream-input,0,0",
        "stream-output,1,0",
        "custom-tool,1,0",
        "parallel-tool,1,0",
        "direct-tool,0,0",
        "reactive-input,0,0",
        "reactive-output,1,0",
        "reactive-direct-output,1,0",
        "reactive-custom-output,1,0"
    })
    void deniesBeforeTheProtectedBoundary(String scenario, int models, int tools) throws Exception {
        String output = run(scenario, true, root.resolve("config/demo.properties"));
        assertTrue(
                output.contains("blocked=true modelCalls=" + models + " toolCalls=" + tools),
                output);
        assertFalse(output.contains("OUTPUT=DEMO_SECRET_123"), output);
        assertFalse(output.contains("STREAM="), output);
    }

    @ParameterizedTest
    @CsvSource({
        "allowed,2,1",
        "async-allowed,2,1",
        "stream-allowed,1,0",
        "reactive-allowed,1,0",
        "reactive-no-subscribe,0,0"
    })
    void permitsLegitimateOperations(String scenario, int models, int tools) throws Exception {
        String output = run(scenario, true, root.resolve("config/demo.properties"));
        assertTrue(
                output.contains("blocked=false modelCalls=" + models + " toolCalls=" + tools),
                output);
        assertFalse(output.contains("decision=DENY"), output);
    }

    @Test
    void sameUnmodifiedApplicationExecutesToolWithoutAgent() throws Exception {
        String output = run("tool", false, root.resolve("config/demo.properties"));
        assertTrue(output.contains("blocked=false modelCalls=2 toolCalls=1"), output);
    }

    @Test
    void externalConfigurationChangesPolicyWithoutRecompiling() throws Exception {
        Path config = temporary.resolve("allow.properties");
        Files.writeString(config, "deny.tools=deleteAll\ndeny.text=IGNORE_SECURITY_TEST\n");
        String output = run("tool", true, config);
        assertTrue(output.contains("blocked=false modelCalls=2 toolCalls=1"), output);
    }

    @Test
    void auditDoesNotContainPromptOrResultText() throws Exception {
        String output = run("output", true, root.resolve("config/demo.properties"));
        assertTrue(output.contains("decision=DENY phase=MODEL_OUTPUT rule=denied-text"), output);
        assertFalse(output.contains("DEMO_SECRET_123"), output);
    }

    @ParameterizedTest
    @CsvSource({
        "tool-args-allowed,false,2,1,allow",
        "tool-args-escaped-allowed,false,2,1,allow",
        "tool-args-foreign,true,1,0,tool-argument-policy",
        "tool-args-escaped-foreign,true,1,0,tool-argument-policy",
        "tool-args-range,true,1,0,tool-argument-policy",
        "tool-args-duplicate,true,1,0,invalid-tool-arguments",
        "tool-args-extra,true,1,0,tool-argument-policy",
        "tool-args-type,true,1,0,tool-argument-policy",
        "tool-args-async-foreign,true,1,0,tool-argument-policy",
        "tool-args-direct-foreign,true,0,0,tool-argument-policy"
    })
    void structuredRulesStopSideEffectsBeforeExecution(
            String scenario, boolean denied, int models, int tools, String reason)
            throws Exception {
        Path policy = temporary.resolve("tool-policy.json");
        Files.copy(root.resolve("config/tool-policy-example.json"), policy);
        Path config = temporary.resolve("tool-policy.properties");
        // Resolve relative to the configuration file, not the process cwd.
        Files.writeString(config, "tool.policy.path=tool-policy.json\n");
        String output = run(scenario, true, config);
        assertTrue(
                output.contains(
                        "blocked=" + denied + " modelCalls=" + models + " toolCalls=" + tools),
                output);
        assertTrue(output.contains("rule=" + reason), output);
        assertFalse(output.contains("other-customer"), output);
    }

    @Test
    void agentInspectsDecodedArgumentsWithTheConfiguredContentRules() throws Exception {
        Path config = temporary.resolve("decoded.properties");
        Files.writeString(
                config,
                "tool.policy.path="
                        + root.resolve("config/tool-policy-example.json")
                        + "\ndeny.text=demo-customer\n");
        String output = run("tool-args-escaped-allowed", true, config);
        assertTrue(output.contains("blocked=true modelCalls=1 toolCalls=0"), output);
        assertTrue(output.contains("rule=denied-text"), output);
        assertFalse(output.contains("demo-customer"), output);
    }

    @Test
    void unlistedToolsAreDeniedWithoutAnyBlacklist() throws Exception {
        Path config = temporary.resolve("closed.properties");
        Files.writeString(
                config,
                "tool.policy.path=" + root.resolve("config/tool-policy-example.json") + "\n");
        String output = run("tool", true, config);
        assertTrue(output.contains("blocked=true modelCalls=1 toolCalls=0"), output);
        assertTrue(output.contains("rule=tool-not-allowed"), output);
    }
}
