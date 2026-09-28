package io.agentsecurity.policy.versioning;

import io.agentsecurity.core.Decision;
import io.agentsecurity.core.LocalPolicy;
import io.agentsecurity.core.versioning.PolicyRevision;
import io.agentsecurity.policy.ToolPolicy;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.nio.CharBuffer;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Properties;

/** 编译本地规则和可选工具 JSON，生成内容摘要；失败不触及发布器，不保留调用方可变 Properties。 */
public final class PolicyCompiler {
    private PolicyCompiler() {}

    public static PolicyRevision compile(
            String version, Properties localProperties, String toolPolicyJson) {
        if (localProperties.size() > 32
                || localProperties.stringPropertyNames().size() > 32
                || localProperties.entrySet().stream()
                        .anyMatch(
                                e ->
                                        !(e.getKey() instanceof String)
                                                || !(e.getValue() instanceof String))) {
            throw new IllegalArgumentException("Invalid local policy properties");
        }
        var copy = new Properties();
        int chars = 0;
        for (var key : localProperties.stringPropertyNames()) {
            var value = localProperties.getProperty(key);
            if (key.length() > 128 || value.length() > 8192) {
                throw new IllegalArgumentException("Policy property too large");
            }
            chars += key.length() + value.length();
            copy.setProperty(key, value);
        }
        if (chars > 65536 || (toolPolicyJson != null && toolPolicyJson.length() > 1048576)) {
            throw new IllegalArgumentException("Policy bundle too large");
        }
        var local = new LocalPolicy(copy);
        var tools = toolPolicyJson == null ? null : ToolPolicy.fromJson(toolPolicyJson, local);
        try {
            var bytes = new ByteArrayOutputStream();
            try (var data = new DataOutputStream(bytes)) {
                // 域标识及长度前缀避免拼接歧义；JSON 保留原始空白，语义相同但排版不同可有不同摘要。
                data.writeUTF("agent-security-policy-bundle-v1");
                data.writeInt(copy.size());
                for (String key : copy.stringPropertyNames().stream().sorted().toList()) {
                    write(data, key);
                    write(data, copy.getProperty(key));
                }
                data.writeBoolean(toolPolicyJson != null);
                if (toolPolicyJson != null) {
                    write(data, toolPolicyJson);
                }
            }
            String digest =
                    java.util.HexFormat.of()
                            .formatHex(
                                    MessageDigest.getInstance("SHA-256")
                                            .digest(bytes.toByteArray()));
            return new PolicyRevision(
                    version,
                    digest,
                    event -> {
                        Decision decision = local.evaluate(event);
                        return !decision.allowed() || tools == null
                                ? decision
                                : tools.evaluate(event);
                    });
        } catch (java.io.IOException | java.security.NoSuchAlgorithmException invalid) {
            throw new IllegalArgumentException("Invalid policy bundle encoding");
        }
    }

    private static void write(DataOutputStream data, String text) throws java.io.IOException {
        var encoded =
                StandardCharsets.UTF_8
                        .newEncoder()
                        .onMalformedInput(CodingErrorAction.REPORT)
                        .onUnmappableCharacter(CodingErrorAction.REPORT)
                        .encode(CharBuffer.wrap(text));
        data.writeInt(encoded.remaining());
        byte[] bytes = new byte[encoded.remaining()];
        encoded.get(bytes);
        data.write(bytes);
    }
}
