package io.agentsecurity.agent;

import io.agentsecurity.core.SecurityBlockedException;
import java.util.*;

/** Inspect the fixed 1.20.0 vocabulary without linking agent classes to application classes. */
final class ReactiveContent {
    private final Object request;
    private final Map<String, StringBuilder> channels = new HashMap<>();
    private final List<Object> tools = new ArrayList<>();
    private int chars;
    private Object response;

    ReactiveContent(Object request) { this.request = request; }

    void add(Object event) {
        if (response != null) throw new SecurityBlockedException("stream-event-order");
        if (event == null) throw new SecurityBlockedException("unsupported-stream-event");
        switch (event.getClass().getName()) {
            case "dev.langchain4j.model.chat.response.PartialResponse" -> append("text", Bridge.call(event, "text"));
            case "dev.langchain4j.model.chat.response.PartialThinking" -> append("thinking", Bridge.call(event, "text"));
            case "dev.langchain4j.model.chat.response.PartialToolCall" -> {
                metadata(Bridge.call(event, "name")); metadata(Bridge.call(event, "id"));
                append("tool-" + Bridge.call(event, "index"), Bridge.call(event, "partialArguments"));
            }
            case "dev.langchain4j.model.chat.response.CompleteToolCall" -> {
                Object tool = Bridge.call(event, "toolExecutionRequest");
                metadata(Bridge.call(tool, "name")); metadata(Bridge.call(tool, "id"));
                append("complete-tool-" + tools.size(), Bridge.call(tool, "arguments"));
                tools.add(tool);
            }
            case "dev.langchain4j.model.chat.response.DefaultRawStreamingEvent" -> {
                Object raw;
                try {
                    Class<?> contract = Class.forName("dev.langchain4j.model.chat.response.RawStreamingEvent", false, event.getClass().getClassLoader());
                    raw = contract.getMethod("rawEvent").invoke(event);
                } catch (ReflectiveOperationException error) { throw new SecurityBlockedException("stream-adapter-error"); }
                metadata(RawStreamControl.inspect(request, raw, StreamRuntime.limits.maxChars() - chars));
            }
            case "dev.langchain4j.model.chat.response.CompleteResponse" -> response = Bridge.call(event, "chatResponse");
            default -> throw new SecurityBlockedException("unsupported-stream-event");
        }
    }

    private String count(Object value) {
        String text = value == null ? "" : value.toString();
        if (text.length() > StreamRuntime.limits.maxChars() - chars) throw new SecurityBlockedException("stream-buffer-limit");
        chars += text.length();
        return text;
    }

    private void append(String channel, Object value) {
        channels.computeIfAbsent(channel, ignored -> new StringBuilder()).append(count(value));
    }
    private void metadata(Object value) { Bridge.checkStreamText(request, count(value)); }

    void validate(long deadline) {
        if (response == null) throw new SecurityBlockedException("missing-stream-response");
        for (StringBuilder channel : channels.values()) {
            checkDeadline(deadline); Bridge.checkStreamText(request, channel.toString());
        }
        for (Object tool : tools) { checkDeadline(deadline); Bridge.before(tool); }
        checkDeadline(deadline); Bridge.after(request, response); checkDeadline(deadline);
    }

    private void checkDeadline(long deadline) {
        if (System.nanoTime() >= deadline) throw new SecurityBlockedException("stream-timeout");
    }
    void clear() { channels.clear(); tools.clear(); response = null; }
}
