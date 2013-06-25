/**
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

package com.google.bitcoin.utils;

import java.util.List;
import java.util.concurrent.Executor;

/**
* A simple wrapper around a listener and an executor, with some utility methods.
*/
public class ListenerRegistration<T> {
    public T listener;
    public Executor executor;

    public ListenerRegistration(T listener, Executor executor) {
        this.listener = listener;
        this.executor = executor;
    }

    public static <T> boolean removeFromList(T listener, List<ListenerRegistration<T>> list) {
        ListenerRegistration<T> item = null;
        for (ListenerRegistration<T> registration : list) {
            if (registration.listener == listener) {
                item = registration;
                break;
            }
        }
        if (item != null) {
            list.remove(item);
            return true;
        } else {
            return false;
        }
    }
}
