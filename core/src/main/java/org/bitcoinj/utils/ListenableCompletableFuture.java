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
import java.util.concurrent.Executor;
import java.util.function.Supplier;

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
            future.whenComplete((val, ex) -> {
                // We can't test for a null val, because of the CompletableFuture<Void> special case.
                if (ex == null) {
                    listenable.complete(val);
                } else {
                    listenable.completeExceptionally(ex);
                }
            });
        }
        return listenable;
    }

    public static <T> ListenableCompletableFuture<T> supplyAsync(ThrowingSupplier<T> throwingSupplier, Executor executor) {
        ListenableCompletableFuture<T> future = new ListenableCompletableFuture<>();
        executor.execute(() -> {
            try {
                T result = throwingSupplier.getThrows();
                future.complete(result);
            } catch (Exception e) {
                future.completeExceptionally(e);
            }
        });
        return future;
    }

    /**
     * Subinterface of {@link Supplier} for Lambdas which throw exceptions.
     * Can be used for two purposes:
     * 1. To cast a lambda that throws an exception to a {@link Supplier} and
     * automatically wrapping any exceptions with {@link RuntimeException}.
     * 2. As a {@code FunctionalInterface} where a lambda that throws exceptions is
     * expected or allowed.
     *
     * @param <T>
     */
    @FunctionalInterface
    public interface ThrowingSupplier<T> extends Supplier<T> {

        /**
         * Gets a result wrapping checked Exceptions with {@link RuntimeException}
         * @return a result
         */
        @Override
        default T get() {
            try {
                return getThrows();
            } catch (final Exception e) {
                throw new RuntimeException(e);
            }
        }

        /**
         * Gets a result.
         *
         * @return a result
         * @throws Exception Any checked Exception
         */
        T getThrows() throws Exception;
    }
}
