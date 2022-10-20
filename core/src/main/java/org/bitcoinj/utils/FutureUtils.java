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

import java.util.Arrays;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.function.IntFunction;
import java.util.function.Supplier;
import java.util.stream.Collectors;

/**
 * Utilities for {@link CompletableFuture}.
 * <p>
 * Note: When the <b>bitcoinj</b> migration to {@code CompletableFuture} is finished this class will
 * either be removed or its remaining methods changed to use generic {@code CompletableFuture}s.
 */
public class FutureUtils {
    /**
     * Note: When the migration to {@code CompletableFuture} is complete this routine will
     * either be removed or changed to return a generic {@code CompletableFuture}.
     * @param stages A list of {@code CompletionStage}s all returning the same type
     * @param <T> the result type
     * @return A ListenableCompletableFuture that returns a list of result type
     */
    public static <T> ListenableCompletableFuture<List<T>> allAsList(
            List<? extends CompletionStage<? extends T>> stages) {
        return ListenableCompletableFuture.of(FutureUtils.allAsCFList(stages));
    }

    /**
     * Note: When the migration to {@code CompletableFuture} is complete this routine will
     * either be removed or changed to return a generic {@code CompletableFuture}.
     * @param stages A list of {@code CompletionStage}s all returning the same type
     * @param <T> the result type
     * @return A ListenableCompletableFuture that returns a list of result type
     */
    public static <T> ListenableCompletableFuture<List<T>> successfulAsList(
            List<? extends CompletionStage<? extends T>> stages) {
        return ListenableCompletableFuture.of(FutureUtils.successfulAsCFList(stages));
    }

    /**
     * Subinterface of {@link Supplier} for Lambdas which throw exceptions.
     * Can be used for two purposes:
     * 1. To cast a lambda that throws an exception to a {@link Supplier} and
     * automatically wrapping any exceptions with {@link RuntimeException}.
     * 2. As a {@code FunctionalInterface} where a lambda that throws exceptions is
     * expected or allowed.
     *
     * @param <T> the supplied type
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

    /**
     * Thank you Apache-licensed Spotify https://github.com/spotify/completable-futures
     * @param stages A list of {@code CompletionStage}s all returning the same type
     * @param <T> the result type
     * @return  A generic CompletableFuture that returns a list of result type
     */
    private static <T> CompletableFuture<List<T>> allAsCFList(
            List<? extends CompletionStage<? extends T>> stages) {
        // Convert List to Array
        final CompletableFuture<? extends T>[] all = listToArray(stages);

        // Use allOf on the Array
        final CompletableFuture<Void> allOf = CompletableFuture.allOf(all);

        // If any of the components fails, fail the whole thing
        stages.forEach(stage -> stage.whenComplete((r, throwable) -> {
            if (throwable != null) {
                allOf.completeExceptionally(throwable);
            }
        }));

        // Transform allOf from Void to List<T>
        return transformToListResult(allOf, all);
    }

    private static <T> CompletableFuture<List<T>> successfulAsCFList(
            List<? extends CompletionStage<? extends T>> stages) {
        // Convert List to Array
        final CompletableFuture<? extends T>[] all = listToArray2(stages);

        // Use allOf on the Array
        final CompletableFuture<Void> allOf = CompletableFuture.allOf(all);

        // Transform allOf from Void to List<T>
        return transformToListResult(allOf, all);
    }

    private static <T> CompletableFuture<? extends T>[] listToArray( List<? extends CompletionStage<? extends T>> stages) {
        // Convert List to Array
        final CompletableFuture<? extends T>[] all = stages.stream()
                .map(CompletionStage::toCompletableFuture)
                .toArray(genericArray(CompletableFuture[]::new));
        return all;
    }

    private static <T> CompletableFuture<? extends T>[] listToArray2( List<? extends CompletionStage<? extends T>> stages) {
        // Convert List to Array
        final CompletableFuture<? extends T>[] all = stages.stream()
                .map(s -> s.exceptionally(throwable -> null).toCompletableFuture())
                .toArray(genericArray(CompletableFuture[]::new));
        return all;
    }

    private static <T> CompletableFuture<List<T>>  transformToListResult(CompletableFuture<Void> allOf, CompletableFuture<? extends T>[] all) {
        return allOf.thenApply(ignored -> Arrays.stream(all)
                .map(CompletableFuture::join)
                .collect(Collectors.toList()));
    }

    /**
     * Function used to create/cast generic array to expected type. Using this function prevents us from
     * needing a {@code @SuppressWarnings("unchecked")} in the calling code.
     * @param arrayCreator Array constructor lambda taking an integer size parameter and returning array of type T
     * @param <T> The erased type
     * @param <R> The desired type
     * @return Array constructor lambda taking an integer size parameter and returning array of type R
     */
    @SuppressWarnings("unchecked")
    static <T, R extends T> IntFunction<R[]> genericArray(IntFunction<T[]> arrayCreator) {
        return size -> (R[]) arrayCreator.apply(size);
    }
}
