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

import com.google.common.base.*;
import org.bitcoinj.core.*;
import org.slf4j.*;

import java.util.concurrent.*;

/**
 * A {@link ThreadFactory} that propagates a {@link Context} from the creating
 * thread into the new thread. This factory creates daemon threads.
 */
public class ContextPropagatingThreadFactory implements ThreadFactory {
    private static final Logger log = LoggerFactory.getLogger(ContextPropagatingThreadFactory.class);
    private final String name;
    private final int priority;

    public ContextPropagatingThreadFactory(String name, int priority) {
        this.name = name;
        this.priority = priority;
    }

    public ContextPropagatingThreadFactory(String name) {
        this(name, Thread.NORM_PRIORITY);
    }

    @Override
    public Thread newThread(final Runnable r) {
        final Context context = Context.get();
        Thread thread = new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    Context.propagate(context);
                    r.run();
                } catch (Exception e) {
                    log.error("Exception in thread", e);
                    Throwables.propagate(e);
                }
            }
        }, name);
        thread.setPriority(priority);
        thread.setDaemon(true);
        Thread.UncaughtExceptionHandler handler = Threading.uncaughtExceptionHandler;
        if (handler != null)
            thread.setUncaughtExceptionHandler(handler);
        return thread;
    }
}
