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

import com.google.common.util.concurrent.Callables;
import com.google.common.util.concurrent.CycleDetectingLockFactory;
import com.google.common.util.concurrent.Futures;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.lang.ref.WeakReference;
import java.util.concurrent.*;
import java.util.concurrent.locks.ReentrantLock;

import static com.google.common.base.Preconditions.checkState;

/**
 * Various threading related utilities. Provides a wrapper around explicit lock creation that lets you control whether
 * bitcoinj performs cycle detection or not. Cycle detection is useful to detect bugs but comes with a small cost.
 * Also provides a worker thread that is designed for event listeners to be dispatched on.
 */
public class Threading {
    /**
     * An executor with one thread that is intended for running event listeners on. This ensures all event listener code
     * runs without any locks being held. It's intended for the API user to run things on. Callbacks registered by
     * bitcoinj internally shouldn't normally run here, although currently there are a few exceptions.
     */
    public static final ExecutorService USER_THREAD;

    /**
     * A dummy executor that just invokes the runnable immediately. Use this over
     * {@link com.google.common.util.concurrent.MoreExecutors#sameThreadExecutor()} because the latter creates a new
     * object each time in order to implement the more complex {@link ExecutorService} interface, which is overkill
     * for our needs.
     */
    public static final Executor SAME_THREAD;

    // For safety reasons keep track of the thread we use to run user-provided event listeners to avoid deadlock.
    private static volatile WeakReference<Thread> vUserThread;

    /**
     * Put a dummy task into the queue and wait for it to be run. Because it's single threaded, this means all
     * tasks submitted before this point are now completed. Usually you won't want to use this method - it's a
     * convenience primarily used in unit testing. If you want to wait for an event to be called the right thing
     * to do is usually to create a {@link com.google.common.util.concurrent.SettableFuture} and then call set
     * on it. You can then either block on that future, compose it, add listeners to it and so on.
     */
    public static void waitForUserCode() {
        // If this assert fires it means you have a bug in your code - you can't call this method inside your own
        // event handlers because it would never return. If you aren't calling this method explicitly, then that
        // means there's a bug in bitcoinj.
        if (vUserThread != null) {
            checkState(vUserThread.get() != null && vUserThread.get() != Thread.currentThread(),
                    "waitForUserCode() run on user code thread would deadlock.");
        }
        Futures.getUnchecked(USER_THREAD.submit(Callables.returning(null)));
    }

    /**
     * An exception handler that will be invoked for any exceptions that occur in the user thread, and
     * any unhandled exceptions that are caught whilst the framework is processing network traffic or doing other
     * background tasks. The purpose of this is to allow you to report back unanticipated crashes from your users
     * to a central collection center for analysis and debugging. You should configure this <b>before</b> any
     * bitcoinj library code is run, setting it after you started network traffic and other forms of processing
     * may result in the change not taking effect.
     */
    @Nullable
    public static volatile Thread.UncaughtExceptionHandler uncaughtExceptionHandler;

    /////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    static {
        // Default policy goes here. If you want to change this, use one of the static methods before
        // instantiating any bitcoinj objects. The policy change will take effect only on new objects
        // from that point onwards.
        throwOnLockCycles();

        USER_THREAD = Executors.newSingleThreadExecutor(new ThreadFactory() {
            @Nonnull @Override public Thread newThread(@Nonnull Runnable runnable) {
                Thread t = new Thread(runnable);
                t.setName("bitcoinj user thread");
                t.setDaemon(true);
                t.setUncaughtExceptionHandler(uncaughtExceptionHandler);
                vUserThread = new WeakReference<Thread>(t);
                return t;
            }
        });
        SAME_THREAD = new Executor() {
            @Override
            public void execute(@Nonnull Runnable runnable) {
                runnable.run();
            }
        };
    }

    private static CycleDetectingLockFactory.Policy policy;
    public static CycleDetectingLockFactory factory;

    public static ReentrantLock lock(String name) {
        return factory.newReentrantLock(name);
    }

    public static void warnOnLockCycles() {
        setPolicy(CycleDetectingLockFactory.Policies.WARN);
    }

    public static void throwOnLockCycles() {
        setPolicy(CycleDetectingLockFactory.Policies.THROW);
    }

    public static void ignoreLockCycles() {
        setPolicy(CycleDetectingLockFactory.Policies.DISABLED);
    }

    public static void setPolicy(CycleDetectingLockFactory.Policy policy) {
        Threading.policy = policy;
        factory = CycleDetectingLockFactory.newInstance(policy);
    }

    public static CycleDetectingLockFactory.Policy getPolicy() {
        return policy;
    }
}
