/*
 * Copyright by the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.bitcoinj.utils;

import org.bitcoinj.base.internal.FutureUtils;

import java.util.concurrent.CompletableFuture;

/**
 * A {@link CompletableFuture} that is also a {@link com.google.common.util.concurrent.ListenableFuture} for migration
 * from <b>Guava</b> {@code ListenableFuture} to {@link CompletableFuture}. This allows clients of <b>bitcoinj</b> to change the type
 * of variables receiving {@code Future}s from bitcoinj methods. You must switch from Guava's
 * {@link com.google.common.util.concurrent.ListenableFuture} (and related types) to Java 8's {@link CompletableFuture}.
 * Release 0.18 of bitcoinj will <b>remove</b> this class,
 * and the type of returned futures from bitcoinj, will be changed to {@link CompletableFuture}.
 * <p>
 * <b>WARNING: This class should be considered Deprecated for Removal, as it will be removed in Release 0.18.</b> See above for details.
 */
public class ListenableCompletableFuture<V> extends CompletableFuture<V> implements ListenableCompletionStage<V> {
    /**
     * Returns a new {@link CompletableFuture} that is already completed with
     * the given value.
     *
     * @param value the value
     * @param <T> the type of the value
     * @return the completed CompletableFuture
     * @deprecated Use {@link CompletableFuture#completedFuture(Object)}
     */
    @Deprecated
    public static <T> ListenableCompletableFuture<T> completedFuture(T value) {
        ListenableCompletableFuture<T> future = new ListenableCompletableFuture<>();
        future.complete(value);
        return future;
    }

    /**
     * Returns a new {@link ListenableCompletableFuture} that is already completed exceptionally
     * with the given throwable.
     *
     * @param throwable the exceptions
     * @param <T> the type of the expected value
     * @return the completed CompletableFuture
     * @deprecated Use {@code new CompletableFuture() + CompletableFuture.completeExceptionally()} or if JDK 9+ use {@code CompletableFuture.failedFuture()}
     */
    @Deprecated
    public static <T> ListenableCompletableFuture<T> failedFuture(Throwable throwable) {
        return ListenableCompletableFuture.of(FutureUtils.failedFuture(throwable));
    }

    /**
     * Converts a generic {@link CompletableFuture} to a {@code ListenableCompletableFuture}. If the passed
     * in future is already a {@code ListenableCompletableFuture} no conversion is performed.
     * @param future A CompletableFuture that may need to be converted
     * @param <T> the type of the futures return value
     * @return A ListenableCompletableFuture
     * @deprecated Don't convert to {@link ListenableCompletableFuture}, use {@link CompletableFuture} directly.
     */
    @Deprecated
    public static <T> ListenableCompletableFuture<T> of(CompletableFuture<T> future) {
        ListenableCompletableFuture<T> listenable;
        if (future instanceof ListenableCompletableFuture) {
            listenable = (ListenableCompletableFuture<T>) future;
        } else {
            listenable = new ListenableCompletableFuture<>();
            future.whenComplete((value, ex) -> {
                // We can't test for a not-null T `value`, because of the CompletableFuture<Void> case,
                // so we test for a null Throwable `ex` instead.
                if (ex == null) {
                    listenable.complete(value);
                } else {
                    listenable.completeExceptionally(ex);
                }
            });
        }
        return listenable;
    }
}
