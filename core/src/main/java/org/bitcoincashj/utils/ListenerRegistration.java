/*
 * Copyright 2013 Google Inc.
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

package org.bitcoincashj.utils;

import java.util.List;
import java.util.concurrent.Executor;

import static com.google.common.base.Preconditions.checkNotNull;

/**
* A simple wrapper around a listener and an executor, with some utility methods.
*/
public class ListenerRegistration<T> {
    public final T listener;
    public final Executor executor;

    public ListenerRegistration(T listener, Executor executor) {
        this.listener = checkNotNull(listener);
        this.executor = checkNotNull(executor);
    }

    /** Returns true if the listener was removed, else false. */
    public static <T> boolean removeFromList(T listener, List<? extends ListenerRegistration<T>> list) {
        checkNotNull(listener);

        ListenerRegistration<T> item = null;
        for (ListenerRegistration<T> registration : list) {
            if (registration.listener == listener) {
                item = registration;
                break;
            }
        }
        return item != null && list.remove(item);
    }
}
