package org.bitcoinj.utils;

import org.bitcoinj.core.*;

import java.util.concurrent.*;

import static com.google.common.base.Preconditions.checkNotNull;

/**
 * A {@link java.util.concurrent.ThreadFactory} that propagates a {@link org.bitcoinj.core.Context} from the creating
 * thread into the new thread. This factory creates daemon threads.
 */
public class ContextPropagatingThreadFactory implements ThreadFactory {
    private final String name;

    public ContextPropagatingThreadFactory(String name) {
        this.name = checkNotNull(name);
    }

    @Override
    public Thread newThread(final Runnable r) {
        final Context context = Context.get();
        Thread thread = new Thread(new Runnable() {
            @Override
            public void run() {
                Context.propagate(context);
                r.run();
            }
        }, name);
        thread.setDaemon(true);
        return thread;
    }
}
