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
}
