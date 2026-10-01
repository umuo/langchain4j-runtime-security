package io.agentsecurity.agent.mcp;

import java.io.IOException;
import java.net.*;
import java.net.http.*;
import java.nio.ByteBuffer;
import java.time.Duration;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.*;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;

/** 只包装 MCP 所拥有的 HTTP 客户端，在字符串与 SSE 行缓冲之前限制单次响应总字节数。 */
public final class LimitedMcpHttpClient extends HttpClient {
    private final HttpClient delegate;
    private final McpResponseLimits.State state;

    public LimitedMcpHttpClient(HttpClient delegate, McpResponseLimits.State state) {
        this.delegate = delegate;
        this.state = state;
    }

    @Override
    public Optional<CookieHandler> cookieHandler() {
        return delegate.cookieHandler();
    }

    @Override
    public Optional<Duration> connectTimeout() {
        return delegate.connectTimeout();
    }

    @Override
    public Redirect followRedirects() {
        return delegate.followRedirects();
    }

    @Override
    public Optional<ProxySelector> proxy() {
        return delegate.proxy();
    }

    @Override
    public SSLContext sslContext() {
        return delegate.sslContext();
    }

    @Override
    public SSLParameters sslParameters() {
        return delegate.sslParameters();
    }

    @Override
    public Optional<Authenticator> authenticator() {
        return delegate.authenticator();
    }

    @Override
    public Version version() {
        return delegate.version();
    }

    @Override
    public Optional<Executor> executor() {
        return delegate.executor();
    }

    @Override
    public <T> HttpResponse<T> send(HttpRequest request, HttpResponse.BodyHandler<T> handler)
            throws IOException, InterruptedException {
        state.check();
        return delegate.send(request, limited(handler));
    }

    @Override
    public <T> CompletableFuture<HttpResponse<T>> sendAsync(
            HttpRequest request, HttpResponse.BodyHandler<T> handler) {
        state.check();
        return delegate.sendAsync(request, limited(handler));
    }

    @Override
    public <T> CompletableFuture<HttpResponse<T>> sendAsync(
            HttpRequest request,
            HttpResponse.BodyHandler<T> handler,
            HttpResponse.PushPromiseHandler<T> pushes) {
        // MCP 不使用 HTTP/2 push；不允许推送走未保护的 handler。
        if (pushes != null) {
            return CompletableFuture.failedFuture(
                    new UnsupportedOperationException("MCP push unsupported"));
        }
        return sendAsync(request, handler);
    }

    private <T> HttpResponse.BodyHandler<T> limited(HttpResponse.BodyHandler<T> handler) {
        return info -> new LimitedSubscriber<>(handler.apply(info), state);
    }

    /** 保持 JDK 17 源码兼容，同时将 JDK 21 的关闭调用转交给真正的客户端。 */
    public void close() {
        try {
            HttpClient.class.getMethod("close").invoke(delegate);
        } catch (NoSuchMethodException ignored) {
            // JDK 17 没有显式关闭方法。
        } catch (ReflectiveOperationException error) {
            throw new IllegalStateException("MCP HTTP close failed", error);
        }
    }

    public static final class LimitedSubscriber<T> implements HttpResponse.BodySubscriber<T> {
        private final HttpResponse.BodySubscriber<T> delegate;
        private final McpResponseLimits.State state;
        private Flow.Subscription subscription;
        private long received;
        private boolean done;

        public LimitedSubscriber(
                HttpResponse.BodySubscriber<T> delegate, McpResponseLimits.State state) {
            this.delegate = delegate;
            this.state = state;
        }

        @Override
        public CompletionStage<T> getBody() {
            return delegate.getBody();
        }

        @Override
        public void onSubscribe(Flow.Subscription value) {
            subscription = value;
            delegate.onSubscribe(value);
        }

        @Override
        public void onNext(List<ByteBuffer> buffers) {
            if (done) {
                return;
            }
            for (ByteBuffer buffer : buffers) {
                received += buffer.remaining();
                if (received > state.maxBytes) {
                    done = true;
                    var failure = state.reject();
                    subscription.cancel();
                    delegate.onError(failure);
                    return;
                }
            }
            delegate.onNext(buffers);
        }

        @Override
        public void onError(Throwable error) {
            if (!done) {
                done = true;
                delegate.onError(error);
            }
        }

        @Override
        public void onComplete() {
            if (!done) {
                done = true;
                delegate.onComplete();
            }
        }
    }
}
