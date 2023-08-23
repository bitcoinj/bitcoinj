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

import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.Executor;

/**
* A simple wrapper around a listener and an executor, with some utility methods.
*/
public class ListenerRegistration<T> {
    public final T listener;
    public final Executor executor;

    public ListenerRegistration(T listener, Executor executor) {
        this.listener = Objects.requireNonNull(listener);
        this.executor = Objects.requireNonNull(executor);
    }

    /**
     * Remove wrapped listener
     * @param listener listener to remove
     * @param list list to remove it from
     * @return true if the listener was removed, else false.
     * @param <T>
     */
    public static <T> boolean removeFromList(T listener, List<? extends ListenerRegistration<T>> list) {
        Objects.requireNonNull(listener);

        // Find matching ListenerRegistration (if any)
        Optional<? extends ListenerRegistration<T>> optRegistration = list.stream()
                .filter(r -> r.listener == listener)
                .findFirst();
        // If ListenerRegistration found, call list::remove
        Optional<Boolean> optBool = optRegistration.map(list::remove);
        // Return result of list::remove or false
        return optBool.orElse(false);
    }
}
