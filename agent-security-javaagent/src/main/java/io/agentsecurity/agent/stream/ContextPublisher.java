package io.agentsecurity.agent.stream;

import io.agentsecurity.agent.bridge.Bridge;
import io.agentsecurity.core.SecurityBlockedException;
import io.agentsecurity.core.SecurityContext;
import io.agentsecurity.core.SecurityContexts;
import java.util.Objects;
import java.util.concurrent.Flow;

/** 为订阅和流回调恢复创建时的身份快照；空身份也必须传播，避免借用工作线程的其他请求身份。 */
public final class ContextPublisher implements Flow.Publisher<Object> {

    private final Flow.Publisher<?> source;

    private final SecurityContext origin;

    public ContextPublisher(Flow.Publisher<?> source, SecurityContext origin) {
        this.source = source;
        this.origin = origin;
    }

    @Override
    public void subscribe(Flow.Subscriber<? super Object> downstream) {
        Objects.requireNonNull(downstream);
        SecurityContext active = SecurityContexts.current();
        if (origin != null && active != null && !origin.equals(active)) {
            Bridge.failedPublisher(new SecurityBlockedException("security-context-mismatch"))
                    .subscribe(downstream);
            return;
        }
        // Even an absent origin is a snapshot; never borrow a worker's unrelated ambient identity.
        SecurityContext captured = origin;
        try (var scope = SecurityContexts.restore(captured)) {
            source.subscribe(
                    new Flow.Subscriber<Object>() {

                        @Override
                        public void onSubscribe(Flow.Subscription subscription) {
                            try (var ignored = SecurityContexts.restore(captured)) {
                                downstream.onSubscribe(
                                        new Flow.Subscription() {

                                            @Override
                                            public void request(long count) {
                                                try (var ignored =
                                                        SecurityContexts.restore(captured)) {
                                                    subscription.request(count);
                                                }
                                            }

                                            @Override
                                            public void cancel() {
                                                try (var ignored =
                                                        SecurityContexts.restore(captured)) {
                                                    subscription.cancel();
                                                }
                                            }
                                        });
                            }
                        }

                        @Override
                        public void onNext(Object item) {
                            try (var ignored = SecurityContexts.restore(captured)) {
                                downstream.onNext(item);
                            }
                        }

                        @Override
                        public void onError(Throwable error) {
                            try (var ignored = SecurityContexts.restore(captured)) {
                                downstream.onError(error);
                            }
                        }

                        @Override
                        public void onComplete() {
                            try (var ignored = SecurityContexts.restore(captured)) {
                                downstream.onComplete();
                            }
                        }
                    });
        }
    }
}
