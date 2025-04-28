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
package org.bitcoinj.base.internal;

import java.util.Arrays;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.function.Function;
import java.util.function.IntFunction;
import java.util.stream.Collectors;

/**
 * Utilities for {@link CompletableFuture}.
 */
public class FutureUtils {
    /**
     * Create a single {@link CompletableFuture} that completes with a {@code List} of {@link T}
     * from a {@code List} of {@code CompletableFuture} that each completes with a {@link T}. If any
     * of the input futures fails, the consolidated future will also fail.
     * @param stages A list of {@code CompletionStage}s all returning the same type
     * @param <T> the result type
     * @return A CompletableFuture that returns a list of result type
     */
    public static <T> CompletableFuture<List<T>> allAsList(
            List<? extends CompletionStage<? extends T>> stages) {
        // Convert List to Array
        final CompletableFuture<? extends T>[] all = listToArray(stages);

        // Create a single future that completes when all futures in the array complete
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

    /**
     * Create a single {@link CompletableFuture} that completes with a {@code List} of {@link T}
     * from a {@code List} of {@code CompletableFuture} that each completes with a {@link T}. For each
     * input future that fails a corresponding {@code null} result will be present in the returned list.
     * @param stages A list of {@code CompletionStage}s all returning the same type
     * @param <T> the result type
     * @return A CompletableFuture that returns a list of result type
     */
    public static <T> CompletableFuture<List<T>> successfulAsList(
            List<? extends CompletionStage<? extends T>> stages) {
        // Convert List to Array and map exceptions to null results
        final CompletableFuture<? extends T>[] all = listToArray2(stages);

        // Create a single future that completes when all futures in the array complete
        final CompletableFuture<Void> allOf = CompletableFuture.allOf(all);

        // Transform allOf from Void to List<T>
        return transformToListResult(allOf, all);
    }

    /**
     * Can be replaced with {@code CompletableFuture.failedFuture(Throwable)} in Java 9+.
     * @param t Exception that is causing the failure
     * @return a failed future containing the specified exception
     * @param <T> the future's return type
     */
    public static <T> CompletableFuture<T> failedFuture(Throwable t) {
        CompletableFuture<T> future = new CompletableFuture<>();
        future.completeExceptionally(t);
        return future;
    }

    // Convert a list of CompletionStage to an array of CompletableFuture
    private static <T> CompletableFuture<? extends T>[] listToArray( List<? extends CompletionStage<? extends T>> stages) {
        return listToArrayWithMapping(stages, CompletionStage::toCompletableFuture);
    }

    // Convert a list of CompletionStage to an array of CompletableFuture also mapping exceptions to null results
    private static <T> CompletableFuture<? extends T>[] listToArray2( List<? extends CompletionStage<? extends T>> stages) {
        return listToArrayWithMapping(stages, stage -> stage.exceptionally(throwable -> null).toCompletableFuture());
    }

    // Convert a list of CompletionStage to an array of CompletableFuture using a mapping function to transform each CompletionStage
    private static <T> CompletableFuture<? extends T>[] listToArrayWithMapping(List<? extends CompletionStage<? extends T>> stages, Function<CompletionStage<? extends T>, CompletableFuture<? extends T>> mapper) {
        return stages.stream()
                .map(mapper::apply)
                .toArray(genericArray(CompletableFuture[]::new));
    }

    // Transform a CompletableFuture returning Void to a CompletableFuture returning all results from an array of CompletableFuture
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
