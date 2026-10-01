package io.agentsecurity.demo;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.Collections;
import java.util.List;
import java.util.Map;

/** 验收专用 MCP 服务端：相同协议处理器运行于真实 HTTP/SSE 和 stdio。 */
public final class McpProtocolServer {
    private static final ObjectMapper JSON = new ObjectMapper();
    private final Path journal;
    private final String scenario;

    McpProtocolServer(Path journal, String scenario) {
        this.journal = journal;
        this.scenario = scenario;
    }

    public static void main(String[] args) throws Exception {
        var server = new McpProtocolServer(Path.of(args[0]), args[1]);
        try (var reader =
                new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                String reply = server.reply(line);
                if (reply != null) {
                    System.out.println(reply);
                    System.out.flush();
                }
            }
        }
    }

    synchronized String reply(String request) throws Exception {
        JsonNode input = JSON.readTree(request);
        String method = input.path("method").asText();
        if (!input.has("id")) {
            return null;
        }
        Object result;
        if (method.equals("initialize")) {
            result =
                    Map.of(
                            "protocolVersion",
                            "2025-11-25",
                            "capabilities",
                            Map.of("tools", Map.of(), "resources", Map.of(), "prompts", Map.of()),
                            "serverInfo",
                            Map.of("name", "fixture", "version", "1"),
                            "instructions",
                            scenario.equals("output") ? "secret-marker" : "safe");
        } else {
            Files.writeString(
                    journal, method + "\n", StandardOpenOption.CREATE, StandardOpenOption.APPEND);
            String text =
                    scenario.equals("wire")
                            ? "x".repeat(8192)
                            : scenario.equals("output") ? "secret-marker" : "safe";
            result =
                    switch (method) {
                        case "tools/list",
                                "resources/list",
                                "resources/templates/list",
                                "prompts/list" -> {
                            var item = new java.util.LinkedHashMap<String, Object>();
                            item.put("name", "lookup");
                            item.put("description", text);
                            String field;
                            switch (method) {
                                case "tools/list" -> {
                                    field = "tools";
                                    item.put(
                                            "inputSchema",
                                            Map.of(
                                                    "type",
                                                    "object",
                                                    "properties",
                                                    Map.of(
                                                            "query",
                                                            Map.of(
                                                                    "type",
                                                                    "string",
                                                                    "description",
                                                                    scenario.equals("schema")
                                                                            ? "secret-marker"
                                                                            : "safe"))));
                                }
                                case "resources/list" -> {
                                    field = "resources";
                                    item.put("uri", "docs://inventory/item-1");
                                }
                                case "resources/templates/list" -> {
                                    field = "resourceTemplates";
                                    item.put("uriTemplate", "docs://inventory/{id}");
                                }
                                default -> {
                                    field = "prompts";
                                    item.put(
                                            "arguments",
                                            List.of(
                                                    Map.of(
                                                            "name",
                                                            "q",
                                                            "description",
                                                            scenario.equals("schema")
                                                                    ? "secret-marker"
                                                                    : "safe")));
                                }
                            }
                            if (scenario.equals("metadata")) {
                                item.put("_meta", Map.of("hidden", "secret-marker"));
                            }
                            if (scenario.startsWith("paged-")) {
                                if (scenario.equals("paged-bytes")) {
                                    item.put("description", "x".repeat(600));
                                }
                                var page = new java.util.LinkedHashMap<String, Object>();
                                page.put(
                                        field,
                                        scenario.equals("paged-empty") ? List.of() : List.of(item));
                                String cursor = input.path("params").path("cursor").asText("");
                                if (scenario.equals("paged-long-cursor")) {
                                    page.put("nextCursor", "x".repeat(1025));
                                } else if (scenario.equals("paged-cursor")) {
                                    page.put("nextCursor", "repeat");
                                } else if (scenario.equals("paged-pages")
                                        || scenario.equals("paged-empty")) {
                                    page.put(
                                            "nextCursor",
                                            cursor.isEmpty()
                                                    ? "1"
                                                    : Integer.toString(
                                                            Integer.parseInt(cursor) + 1));
                                } else if (cursor.isEmpty()) {
                                    page.put("nextCursor", "1");
                                }
                                yield page;
                            }
                            yield Map.of(
                                    field,
                                    scenario.equals("limit")
                                            ? Collections.nCopies(129, item)
                                            : List.of(item));
                        }
                        case "tools/call" ->
                                Map.of("content", List.of(Map.of("type", "text", "text", text)));
                        case "resources/read" -> {
                            String uri =
                                    scenario.equals("uri")
                                            ? "docs://different"
                                            : input.path("params").path("uri").asText();
                            Object item =
                                    scenario.equals("binary")
                                            ? Map.of("uri", uri, "blob", "c2FmZQ==")
                                            : Map.of(
                                                    "uri",
                                                    uri,
                                                    "text",
                                                    text,
                                                    "mimeType",
                                                    "text/plain");
                            yield Map.of(
                                    "contents",
                                    scenario.equals("limit")
                                            ? Collections.nCopies(129, item)
                                            : List.of(item));
                        }
                        case "prompts/get" -> {
                            Object content =
                                    scenario.equals("binary")
                                            ? Map.of(
                                                    "type",
                                                    "image",
                                                    "data",
                                                    "c2FmZQ==",
                                                    "mimeType",
                                                    "image/png")
                                            : Map.of("type", "text", "text", text);
                            Object message = Map.of("role", "user", "content", content);
                            yield Map.of(
                                    "description",
                                    scenario.equals("description") ? "secret-marker" : "fixture",
                                    "messages",
                                    scenario.equals("limit")
                                            ? Collections.nCopies(129, message)
                                            : List.of(message));
                        }
                        default -> throw new IllegalArgumentException("Unexpected method");
                    };
        }
        return JSON.writeValueAsString(
                Map.of("jsonrpc", "2.0", "id", input.get("id"), "result", result));
    }
}
