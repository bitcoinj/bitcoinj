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

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;

/**
 * Utilities for {@link CompletableFuture}.
 * <p>
 * Note: When the <b>bitcoinj</b> migration to {@code CompletableFuture} is finished this class will
 * either be removed or its remaining methods changed to use generic {@code CompletableFuture}s.
 */
public class FutureUtils {

    /**
     * Thank you Apache-licensed Spotify https://github.com/spotify/completable-futures
     * @param stages A list of {@code CompletionStage}s all returning the same type
     * @param <T> the result type
     * @return  A generic CompletableFuture that returns a list of result type
     */
    private static <T> CompletableFuture<List<T>> allAsCFList(
            List<? extends CompletionStage<? extends T>> stages) {
        @SuppressWarnings("unchecked") // generic array creation
        final CompletableFuture<? extends T>[] all = new CompletableFuture[stages.size()];
        for (int i = 0; i < stages.size(); i++) {
            all[i] = stages.get(i).toCompletableFuture();
        }

        CompletableFuture<Void> allOf = CompletableFuture.allOf(all);

        for (CompletableFuture<? extends T> completableFuture : all) {
            completableFuture.exceptionally(throwable -> {
                if (!allOf.isDone()) {
                    allOf.completeExceptionally(throwable);
                }
                return null; // intentionally unused
            });
        }

        return allOf
                .thenApply(ignored -> {
                    final List<T> result = new ArrayList<>(all.length);
                    for (CompletableFuture<? extends T> completableFuture : all) {
                        result.add(completableFuture.join());
                    }
                    return result;
                });
    }

    /**
     * Note: When the migration to {@code CompletableFuture} is complete this routine will
     * either be removed or changed to return a generic {@code CompletableFuture}.
     * @param stages A list of {@code CompletionStage}s all returning the same type
     * @param <T> the result type
     * @return  A ListenableCompletableFuture that returns a list of result type
     */
    public static <T> ListenableCompletableFuture<List<T>> allAsList(
            List<? extends CompletionStage<? extends T>> stages) {
        return ListenableCompletableFuture.of(FutureUtils.allAsCFList(stages));
    }
}
