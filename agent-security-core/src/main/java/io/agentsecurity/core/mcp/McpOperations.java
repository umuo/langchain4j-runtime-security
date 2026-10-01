package io.agentsecurity.core.mcp;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

/** 宿主生成精确 MCP 授权名的公共入口；URI 不做解码或路径归一化，避免扩大授权。 */
public final class McpOperations {
    private McpOperations() {}

    public static String resource(String server, String uri) {
        name(server);
        if (uri == null
                || uri.length() > 1024
                || !uri.matches("[!-~]+")
                || !URI.create(uri).isAbsolute()) {
            throw new IllegalArgumentException("Invalid MCP resource URI");
        }
        try {
            // 哈希仅用于有界且无分隔符歧义的授权名称，不是身份认证或 URI 保密措施。
            byte[] digest =
                    MessageDigest.getInstance("SHA-256")
                            .digest(uri.getBytes(StandardCharsets.US_ASCII));
            return "mcp-resource:" + server + "/" + HexFormat.of().formatHex(digest);
        } catch (NoSuchAlgorithmException error) {
            throw new IllegalStateException("SHA-256 unavailable", error);
        }
    }

    public static String prompt(String server, String prompt) {
        return "mcp-prompt:" + name(server) + "/" + name(prompt);
    }

    public static String discovery(String server, String method) {
        if (!java.util.Set.of(
                        "listTools",
                        "listResources",
                        "listResourceTemplates",
                        "listPrompts",
                        "instructions")
                .contains(method)) {
            throw new IllegalArgumentException("Invalid MCP discovery operation");
        }
        return "mcp-discovery:" + name(server) + "/" + method;
    }

    private static String name(String value) {
        if (value == null || !value.matches("[a-zA-Z0-9_.-]{1,100}")) {
            throw new IllegalArgumentException("Invalid MCP name");
        }
        return value;
    }
}
