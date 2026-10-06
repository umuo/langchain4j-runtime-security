package io.agentsecurity.demo;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** 验证真实打包 JAR，覆盖未配置、不限长度和显式错误配置的启动与调用行为。 */
class AgentStartupIT {

    @TempDir Path temporary;

    private final Path root = Path.of("..").toAbsolutePath().normalize();

    private record Result(int exit, String output) {}

    @Test
    void noPolicyPreservesToolAndStreamingBehaviorWithoutLoadingSecurityRuntime() throws Exception {
        for (String scenario : new String[] {"tool", "stream-output"}) {
            Result baseline = run(null, false, scenario, null);
            for (String argument : new String[] {null, "", "   "}) {
                Path classes = temporary.resolve("classes-" + System.nanoTime() + ".log");
                Result unconfigured = run(argument, true, scenario, classes);
                assertEquals(0, unconfigured.exit(), unconfigured.output());
                assertEquals(baseline.output(), unconfigured.output());
                String loaded = Files.readString(classes);
                assertFalse(loaded.contains("io.agentsecurity.agent.AgentBootstrap"), loaded);
                assertFalse(loaded.contains("io.agentsecurity.shaded.bytebuddy."), loaded);
            }
        }
    }

    @Test
    void absentAndBlankLimitsAllowLongModelInputButExplicitLimitBlocksBeforeModel()
            throws Exception {
        for (String policy : new String[] {"", "max.text.chars=\n", "max.text.chars=   \n"}) {
            Path config = temporary.resolve("policy-" + System.nanoTime() + ".properties");
            Files.writeString(config, policy);
            Result result = run(config.toString(), true, null, null);
            assertEquals(0, result.exit(), result.output());
            assertTrue(result.output().contains("PROBE allowed=true calls=1"), result.output());
        }
        Path config = temporary.resolve("limited.properties");
        Files.writeString(config, "max.text.chars=100000\n");
        Result blocked = run(config.toString(), true, null, null);
        assertEquals(0, blocked.exit(), blocked.output());
        assertTrue(blocked.output().contains("PROBE allowed=false calls=0"), blocked.output());
    }

    @Test
    void explicitlyMissingPolicyFailsInsteadOfRunningApplication() throws Exception {
        Result result = run(temporary.resolve("missing.properties").toString(), true, null, null);
        assertNotEquals(0, result.exit(), result.output());
        assertFalse(result.output().contains("PROBE "), result.output());
    }

    @Test
    void packagedConfigurationCheckerUsesExitCodesAndNeverWritesAudit() throws Exception {
        Path config = temporary.resolve("check.properties");
        Path audit = temporary.resolve("uncreated/decisions.jsonl");
        Files.writeString(config, "audit.path=" + audit + "\nmax.text.chars=\n");
        Result valid = check(config.toString());
        assertEquals(0, valid.exit(), valid.output());
        assertFalse(Files.exists(audit.getParent()));
        Files.writeString(config, "deny.tools=deleteAll\ndeny.tools=\n");
        assertEquals(1, check(config.toString()).exit());
        assertEquals(2, check(null).exit());
    }

    private Result check(String policy) throws Exception {
        var command = new ArrayList<String>();
        command.add(Path.of(System.getProperty("java.home"), "bin", "java").toString());
        command.add("-cp");
        command.add(
                root.resolve("agent-security-javaagent/target/agent-security-javaagent.jar")
                        .toString());
        command.add("io.agentsecurity.agent.PolicyCheck");
        if (policy != null) {
            command.add(policy);
        }
        Path log = temporary.resolve("check-" + System.nanoTime() + ".log");
        Process process =
                new ProcessBuilder(command)
                        .redirectErrorStream(true)
                        .redirectOutput(log.toFile())
                        .start();
        if (!process.waitFor(25, TimeUnit.SECONDS)) {
            process.destroyForcibly();
            fail("配置检查子 JVM 超时");
        }
        return new Result(process.exitValue(), Files.readString(log));
    }

    private Result run(String arguments, boolean agent, String scenario, Path classes)
            throws Exception {
        var command = new ArrayList<String>();
        command.add(Path.of(System.getProperty("java.home"), "bin", "java").toString());
        // 错误启动用例避免写入操作系统 core dump。
        command.add("-XX:-CreateCoredumpOnCrash");
        if (classes != null) {
            command.add("-Xlog:class+load=info:file=" + classes);
        }
        if (agent) {
            command.add(
                    "-javaagent:"
                            + root.resolve(
                                    "agent-security-javaagent/target/agent-security-javaagent.jar")
                            + (arguments == null ? "" : "=" + arguments));
        }
        if (scenario != null) {
            command.add("-jar");
            command.add(root.resolve("demo/target/agent-security-demo.jar").toString());
            command.add(scenario);
        } else {
            command.add("-cp");
            command.add(
                    root.resolve("demo/target/test-classes")
                            + java.io.File.pathSeparator
                            + root.resolve("demo/target/agent-security-demo.jar"));
            command.add(AgentStartupProbe.class.getName());
        }
        Path log = temporary.resolve("process-" + System.nanoTime() + ".log");
        Process process =
                new ProcessBuilder(command)
                        .directory(temporary.toFile())
                        .redirectErrorStream(true)
                        .redirectOutput(log.toFile())
                        .start();
        if (!process.waitFor(25, TimeUnit.SECONDS)) {
            process.destroyForcibly();
            fail("子 JVM 超时");
        }
        return new Result(process.exitValue(), Files.readString(log));
    }
}
