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

package org.bitcoinj.net;

import java.util.Timer;
import java.util.TimerTask;

/**
 * <p>A base class which provides basic support for socket timeouts. It is used instead of integrating timeouts into the
 * NIO select thread both for simplicity and to keep code shared between NIO and blocking sockets as much as possible.
 * </p>
 */
public abstract class AbstractTimeoutHandler {
    // TimerTask and timeout value which are added to a timer to kill the connection on timeout
    private TimerTask timeoutTask;
    private long timeoutMillis = 0;
    private boolean timeoutEnabled = true;

    // A timer which manages expiring channels as their timeouts occur (if configured).
    private static final Timer timeoutTimer = new Timer("AbstractTimeoutHandler timeouts", true);

    /**
     * <p>Enables or disables the timeout entirely. This may be useful if you want to store the timeout value but wish
     * to temporarily disable/enable timeouts.</p>
     *
     * <p>The default is for timeoutEnabled to be true but timeoutMillis to be set to 0 (ie disabled).</p>
     *
     * <p>This call will reset the current progress towards the timeout.</p>
     */
    public synchronized void setTimeoutEnabled(boolean timeoutEnabled) {
        this.timeoutEnabled = timeoutEnabled;
        resetTimeout();
    }

    /**
     * <p>Sets the receive timeout to the given number of milliseconds, automatically killing the connection if no
     * messages are received for this long</p>
     *
     * <p>A timeout of 0 is interpreted as no timeout.</p>
     *
     * <p>The default is for timeoutEnabled to be true but timeoutMillis to be set to 0 (ie disabled).</p>
     *
     * <p>This call will reset the current progress towards the timeout.</p>
     */
    public synchronized void setSocketTimeout(int timeoutMillis) {
        this.timeoutMillis = timeoutMillis;
        resetTimeout();
    }

    /**
     * Resets the current progress towards timeout to 0.
     */
    protected synchronized void resetTimeout() {
        if (timeoutTask != null)
            timeoutTask.cancel();
        if (timeoutMillis == 0 || !timeoutEnabled)
            return;
        timeoutTask = new TimerTask() {
            @Override
            public void run() {
                timeoutOccurred();
            }
        };
        timeoutTimer.schedule(timeoutTask, timeoutMillis);
    }

    protected abstract void timeoutOccurred();
}
