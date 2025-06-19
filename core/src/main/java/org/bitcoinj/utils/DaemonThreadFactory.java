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

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadFactory;

/** Thread factory whose threads are marked as daemon and won't prevent process exit. */
public class DaemonThreadFactory implements ThreadFactory {
    @Nullable private final String name;

    public DaemonThreadFactory(@Nullable String name) {
        this.name = name;
    }

    public DaemonThreadFactory() {
        this(null);
    }

    @Override
    public Thread newThread(@NonNull Runnable runnable) {
        Thread thread = Executors.defaultThreadFactory().newThread(runnable);
        thread.setDaemon(true);
        if (name != null)
            thread.setName(name);
        return thread;
    }
}
