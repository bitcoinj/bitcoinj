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

import java.util.concurrent.CompletableFuture;

/**
 * A {@link CompletableFuture} that is also a {@link com.google.common.util.concurrent.ListenableFuture} for migration
 * from Guava {@code ListenableFuture} to {@link CompletableFuture}.
 */
public class ListenableCompletableFuture<V> extends CompletableFuture<V> implements ListenableCompletionStage<V> {

    /**
     * Returns a new {@link CompletableFuture} that is already completed with
     * the given value.
     * <p>
     * When the migration to {@link CompletableFuture} is finished use of this method
     * can be replaced with {@link CompletableFuture#completedFuture(Object)}.
     *
     * @param value the value
     * @param <T> the type of the value
     * @return the completed CompletableFuture
     */
    public static <T> ListenableCompletableFuture<T> completedFuture(T value) {
        ListenableCompletableFuture<T> future = new ListenableCompletableFuture<>();
        future.complete(value);
        return future;
    }

    /**
     * Returns a new {@link CompletableFuture} that is already completed exceptionally
     * the given throwable.
     * <p>
     * When the migration to {@link CompletableFuture} is finished we'll probably move this
     * method to FutureUtils as the {@code failedFuture()} is not available until Java 9.
     *
     * @param throwable the exceptions
     * @param <T> the type of the expected value
     * @return the completed CompletableFuture
     */
    public static <T> ListenableCompletableFuture<T> failedFuture(Throwable throwable) {
        ListenableCompletableFuture<T> future = new ListenableCompletableFuture<>();
        future.completeExceptionally(throwable);
        return future;
    }

    /**
     * Converts a generic {@link CompletableFuture} to a {@code ListenableCompletableFuture}. If the passed
     * in future is already a {@code ListenableCompletableFuture} no conversion is performed.
     * <p>
     * When the migration to {@link CompletableFuture} is finished usages of this method
     * can simply be removed as the conversion will no longer be required.
     * @param future A CompletableFuture that may need to be converted
     * @param <T> the type of the futures return value
     * @return A ListenableCompletableFuture
     */
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
