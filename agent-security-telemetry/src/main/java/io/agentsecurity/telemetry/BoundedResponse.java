package io.agentsecurity.telemetry;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.Flow;

/** 在接收时限制响应体大小，避免先聚合完整响应再检查。 */
final class BoundedResponse implements HttpResponse.BodySubscriber<byte[]> {
    static final class TooLarge extends IOException {}

    private final CompletableFuture<byte[]> result = new CompletableFuture<>();
    private final ByteArrayOutputStream bytes = new ByteArrayOutputStream();
    private Flow.Subscription subscription;

    @Override
    public CompletionStage<byte[]> getBody() {
        return result;
    }

    @Override
    public void onSubscribe(Flow.Subscription subscription) {
        this.subscription = subscription;
        subscription.request(1);
    }

    @Override
    public void onNext(List<ByteBuffer> buffers) {
        for (var buffer : buffers) {
            if (buffer.remaining() > 16384 - bytes.size()) {
                subscription.cancel();
                result.completeExceptionally(new TooLarge());
                return;
            }
            byte[] piece = new byte[buffer.remaining()];
            buffer.get(piece);
            bytes.writeBytes(piece);
        }
        subscription.request(1);
    }

    @Override
    public void onError(Throwable error) {
        result.completeExceptionally(error);
    }

    @Override
    public void onComplete() {
        result.complete(bytes.toByteArray());
    }
}
