/**
 * Copyright 2013 Google Inc.
 * Copyright 2014 Andreas Schildbach
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

package org.bitcoinj.wallet;

import org.bitcoinj.core.*;
import org.bitcoinj.utils.*;
import org.slf4j.*;

import javax.annotation.*;
import java.io.*;
import java.util.Date;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;

import static com.google.common.base.Preconditions.*;

/**
 * A class that handles atomic and optionally delayed writing of the wallet file to disk. In future: backups too.
 * It can be useful to delay writing of a wallet file to disk on slow devices where disk and serialization overhead
 * can come to dominate the chain processing speed, i.e. on Android phones. By coalescing writes and doing serialization
 * and disk IO on a background thread performance can be improved.
 */
public class WalletFiles {
    private static final Logger log = LoggerFactory.getLogger(WalletFiles.class);

    private final Wallet wallet;
    private final ScheduledThreadPoolExecutor executor;
    private final File file;
    private final AtomicBoolean savePending;
    private final long delay;
    private final TimeUnit delayTimeUnit;
    private final Callable<Void> saver;

    private volatile Listener vListener;

    /**
     * Implementors can do pre/post treatment of the wallet file. Useful for adjusting permissions and other things.
     */
    public interface Listener {
        /**
         * Called on the auto-save thread when a new temporary file is created but before the wallet data is saved
         * to it. If you want to do something here like adjust permissions, go ahead and do so.
         */
        void onBeforeAutoSave(File tempFile);

        /**
         * Called on the auto-save thread after the newly created temporary file has been filled with data and renamed.
         */
        void onAfterAutoSave(File newlySavedFile);
    }

    public WalletFiles(final Wallet wallet, File file, long delay, TimeUnit delayTimeUnit) {
        // An executor that starts up threads when needed and shuts them down later.
        this.executor = new ScheduledThreadPoolExecutor(1, new ContextPropagatingThreadFactory("Wallet autosave thread", Thread.MIN_PRIORITY));
        this.executor.setKeepAliveTime(5, TimeUnit.SECONDS);
        this.executor.allowCoreThreadTimeOut(true);
        this.executor.setExecuteExistingDelayedTasksAfterShutdownPolicy(false);
        this.wallet = checkNotNull(wallet);
        // File must only be accessed from the auto-save executor from now on, to avoid simultaneous access.
        this.file = checkNotNull(file);
        this.savePending = new AtomicBoolean();
        this.delay = delay;
        this.delayTimeUnit = checkNotNull(delayTimeUnit);

        this.saver = new Callable<Void>() {
            @Override public Void call() throws Exception {
                // Runs in an auto save thread.
                if (!savePending.getAndSet(false)) {
                    // Some other scheduled request already beat us to it.
                    return null;
                }
                Date lastBlockSeenTime = wallet.getLastBlockSeenTime();
                log.info("Background saving wallet; last seen block is height {}, date {}, hash {}",
                        wallet.getLastBlockSeenHeight(),
                        lastBlockSeenTime != null ? Utils.dateTimeFormat(lastBlockSeenTime) : "unknown",
                        wallet.getLastBlockSeenHash());
                saveNowInternal();
                return null;
            }
        };
    }

    /**
     * The given listener will be called on the autosave thread before and after the wallet is saved to disk.
     */
    public void setListener(@Nonnull Listener listener) {
        this.vListener = checkNotNull(listener);
    }

    /** Actually write the wallet file to disk, using an atomic rename when possible. Runs on the current thread. */
    public void saveNow() throws IOException {
        // Can be called by any thread. However the wallet is locked whilst saving, so we can have two saves in flight
        // but they will serialize (using different temp files).
        Date lastBlockSeenTime = wallet.getLastBlockSeenTime();
        log.info("Saving wallet; last seen block is height {}, date {}, hash {}", wallet.getLastBlockSeenHeight(),
                lastBlockSeenTime != null ? Utils.dateTimeFormat(lastBlockSeenTime) : "unknown",
                wallet.getLastBlockSeenHash());
        saveNowInternal();
    }

    private void saveNowInternal() throws IOException {
        long now = System.currentTimeMillis();
        File directory = file.getAbsoluteFile().getParentFile();
        File temp = File.createTempFile("wallet", null, directory);
        final Listener listener = vListener;
        if (listener != null)
            listener.onBeforeAutoSave(temp);
        wallet.saveToFile(temp, file);
        if (listener != null)
            listener.onAfterAutoSave(file);
        log.info("Save completed in {}msec", System.currentTimeMillis() - now);
    }

    /** Queues up a save in the background. Useful for not very important wallet changes. */
    public void saveLater() {
        if (savePending.getAndSet(true))
            return;   // Already pending.
        executor.schedule(saver, delay, delayTimeUnit);
    }

    /** Shut down auto-saving. */
    public void shutdownAndWait() {
        executor.shutdown();
        try {
            executor.awaitTermination(Long.MAX_VALUE, TimeUnit.DAYS); // forever
        } catch (InterruptedException x) {
            throw new RuntimeException(x);
        }
    }
}
