package io.agentsecurity.agent;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** 预检查复用启动校验，并证明错误配置不会提前产生审计文件。 */
class AgentConfigurationTest {

    @TempDir Path directory;

    private Path policy(String content) throws Exception {
        Path path = directory.resolve("policy.properties");
        Files.writeString(path, content);
        return path;
    }

    @Test
    void validFileAuditConfigurationDoesNotCreateOutputOrParentDirectory() throws Exception {
        Path audit = directory.resolve("uncreated/decisions.jsonl");
        Path config = policy("audit.path=" + audit + "\nmax.text.chars=\n");
        AgentBootstrap.validateConfiguration(config.toString());
        assertFalse(Files.exists(audit.getParent()));
    }

    @Test
    void duplicateDecodedKeysAreRejectedRatherThanSilentlyOverwritten() throws Exception {
        for (String content :
                new String[] {
                    "deny.tools=deleteAll\ndeny.tools=\n",
                    "deny.tools=deleteAll\ndeny\\.tools=\n",
                    "deny.tools=deleteAll\ndeny.\\\n tools=\n"
                }) {
            Path config = policy(content);
            assertThrows(
                    IllegalArgumentException.class,
                    () -> AgentBootstrap.validateConfiguration(config.toString()));
        }
    }

    @Test
    void unknownKeysAndInvalidValuesFailWithoutWritingAudit() throws Exception {
        Path audit = directory.resolve("uncreated/decisions.jsonl");
        for (String content :
                new String[] {
                    "unknown.key=true\n",
                    "max.text.chars=0\n",
                    "audit.max.bytes=10\n",
                    "audit.timeout.millis=0\n",
                    "audit.queue.capacity=0\n",
                    "telemetry.enabled=invalid\n"
                }) {
            Path config = policy("audit.path=" + audit + "\n" + content);
            assertThrows(
                    IllegalArgumentException.class,
                    () -> AgentBootstrap.validateConfiguration(config.toString()));
            assertFalse(Files.exists(audit.getParent()));
        }
    }

    @Test
    void toolJsonIsResolvedRelativeToConfigurationAndValidated() throws Exception {
        Files.writeString(
                directory.resolve("tools.json"),
                "{\"schemaVersion\":1,\"tools\":{\"lookup\":{\"type\":\"object\",\"properties\":{},\"additionalProperties\":false}}}");
        Path config = policy("tool.policy.path=tools.json\n");
        AgentBootstrap.validateConfiguration(config.toString());
        Files.writeString(directory.resolve("tools.json"), "{}");
        assertThrows(
                IllegalArgumentException.class,
                () -> AgentBootstrap.validateConfiguration(config.toString()));
    }
}
