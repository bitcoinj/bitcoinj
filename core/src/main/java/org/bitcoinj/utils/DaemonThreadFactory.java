package org.bitcoinj.utils;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
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
    public Thread newThread(@Nonnull Runnable runnable) {
        Thread thread = Executors.defaultThreadFactory().newThread(runnable);
        thread.setDaemon(true);
        if (name != null)
            thread.setName(name);
        return thread;
    }
}
