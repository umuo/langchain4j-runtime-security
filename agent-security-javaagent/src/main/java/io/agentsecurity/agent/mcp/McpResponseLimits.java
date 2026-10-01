package io.agentsecurity.agent.mcp;

import io.agentsecurity.core.SecurityBlockedException;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Collections;
import java.util.Map;
import java.util.Properties;
import java.util.WeakHashMap;
import java.util.concurrent.atomic.AtomicBoolean;

/** 固定传输的响应容量状态。超限后保持不可用，必须由宿主重建客户端。 */
public final class McpResponseLimits {
    private static volatile int maxBytes = 1_048_576;
    private static final Map<Object, State> STATES =
            Collections.synchronizedMap(new WeakHashMap<>());
    private static final ThreadLocal<State> STDIO = new ThreadLocal<>();

    private McpResponseLimits() {}

    public static void initialize(Properties properties) {
        int value = Integer.parseInt(properties.getProperty("mcp.max.response.bytes", "1048576"));
        if (value < 1024 || value > 16_777_216) {
            throw new IllegalArgumentException("Invalid mcp.max.response.bytes");
        }
        maxBytes = value;
    }

    public static State state(Object transport) {
        synchronized (STATES) {
            return STATES.computeIfAbsent(transport, ignored -> new State(maxBytes));
        }
    }

    public static void bind(Object client, Object transport) {
        STATES.put(client, state(transport));
    }

    public static void check(Object client) {
        State state = STATES.get(client);
        if (state != null) {
            state.check();
        }
    }

    public static State enterStdio(Object transport) {
        State previous = STDIO.get();
        STDIO.set(state(transport));
        return previous;
    }

    public static void exitStdio(State previous) {
        if (previous == null) {
            STDIO.remove();
        } else {
            STDIO.set(previous);
        }
    }

    public static InputStream wrapStdio(InputStream input) {
        State state = STDIO.get();
        return state == null || input instanceof LimitedLineInput
                ? input
                : new LimitedLineInput(input, state);
    }

    public static final class State {
        final int maxBytes;
        private final AtomicBoolean failed = new AtomicBoolean();

        public State(int maxBytes) {
            this.maxBytes = maxBytes;
        }

        public void check() {
            if (failed.get()) {
                throw new SecurityBlockedException("mcp-response-limit");
            }
        }

        SecurityBlockedException reject() {
            failed.set(true);
            return new SecurityBlockedException("mcp-response-limit");
        }
    }

    /** 在 BufferedReader 聚合整行之前计数，CR/LF 都是分隔符；不累积输入正文。 */
    public static final class LimitedLineInput extends FilterInputStream {
        private final State state;
        private int count;

        public LimitedLineInput(InputStream input, State state) {
            super(input);
            this.state = state;
        }

        @Override
        public int read() throws IOException {
            state.check();
            int value = in.read();
            if (value >= 0) {
                inspect(value);
            }
            return value;
        }

        @Override
        public int read(byte[] bytes, int offset, int length) throws IOException {
            java.util.Objects.checkFromIndexSize(offset, length, bytes.length);
            state.check();
            if (length == 0) {
                return 0;
            }
            int size = in.read(bytes, offset, Math.min(length, state.maxBytes - count + 1));
            for (int index = 0; index < size; index++) {
                inspect(bytes[offset + index] & 255);
            }
            return size;
        }

        private void inspect(int value) throws IOException {
            if (value == '\n' || value == '\r') {
                count = 0;
            } else if (++count > state.maxBytes) {
                var denied = state.reject();
                try {
                    in.close();
                } catch (IOException ignored) {
                    /* 保留容量拒绝原因。 */
                }
                throw new IOException("mcp-response-limit", denied);
            }
        }
    }
}
