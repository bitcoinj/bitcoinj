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

package org.bitcoinj.net;

import java.time.Duration;
import java.util.Timer;
import java.util.TimerTask;

/**
 * Component that implements the timeout capability of {@link TimeoutHandler}.
 */
public class SocketTimeoutTask implements TimeoutHandler {
    // TimerTask and timeout value which are added to a timer to kill the connection on timeout
    private final Runnable actualTask;
    private TimerTask timeoutTask;
    private Duration timeout = Duration.ZERO;
    private boolean timeoutEnabled = true;

    // A timer which manages expiring channels as their timeouts occur (if configured).
    private static final Timer timeoutTimer = new Timer("AbstractTimeoutHandler timeouts", true);

    public SocketTimeoutTask(Runnable actualTask) {
        this.actualTask = actualTask;
    }

    /**
     * <p>Enables or disables the timeout entirely. This may be useful if you want to store the timeout value but wish
     * to temporarily disable/enable timeouts.</p>
     *
     * <p>The default is for timeoutEnabled to be true but timeout to be set to {@link Duration#ZERO} (ie disabled).</p>
     *
     * <p>This call will reset the current progress towards the timeout.</p>
     */
    @Override
    public synchronized final void setTimeoutEnabled(boolean timeoutEnabled) {
        this.timeoutEnabled = timeoutEnabled;
        resetTimeout();
    }

    /**
     * <p>Sets the receive timeout, automatically killing the connection if no
     * messages are received for this long</p>
     *
     * <p>A timeout of {@link Duration#ZERO} is interpreted as no timeout.</p>
     *
     * <p>The default is for timeoutEnabled to be true but timeout to be set to {@link Duration#ZERO} (ie disabled).</p>
     *
     * <p>This call will reset the current progress towards the timeout.</p>
     */
    @Override
    public synchronized final void setSocketTimeout(Duration timeout) {
        this.timeout = timeout;
        resetTimeout();
    }

    /**
     * Resets the current progress towards timeout to 0.
     * @deprecated This will be made private once {@link AbstractTimeoutHandler} is removed.
     */
    @Deprecated
    synchronized void resetTimeout() {
        if (timeoutTask != null)
            timeoutTask.cancel();
        if (timeout.isZero() || !timeoutEnabled)
            return;
        // TimerTasks are not reusable, so we create a new one each time
        timeoutTask = timerTask(actualTask);
        timeoutTimer.schedule(timeoutTask, timeout.toMillis());
    }

    // Create TimerTask from Runnable
    private static TimerTask timerTask(Runnable r) {
        return new TimerTask() {

            @Override
            public void run() {
                r.run();
            }
        };
    }
}
