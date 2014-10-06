package org.bitcoinj.utils;

import javax.annotation.Nonnull;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadFactory;

/** Thread factory whose threads are marked as daemon and won't prevent process exit. */
public class DaemonThreadFactory implements ThreadFactory {

    @Override
    public Thread newThread(@Nonnull Runnable runnable) {
        Thread thread = Executors.defaultThreadFactory().newThread(runnable);
        thread.setDaemon(true);
        return thread;
    }
}
