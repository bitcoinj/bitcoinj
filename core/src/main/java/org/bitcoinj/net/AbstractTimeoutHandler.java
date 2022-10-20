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

/**
 * A base class which provides basic support for socket timeouts. It is used instead of integrating timeouts into the
 * NIO select thread both for simplicity and to keep code shared between NIO and blocking sockets as much as possible.
 * <p>
 * @deprecated Don't extend this class, implement {@link TimeoutHandler} using {@link SocketTimeoutTask} instead
 */
@Deprecated
public abstract class AbstractTimeoutHandler implements TimeoutHandler {
    private final SocketTimeoutTask timeoutTask;

    public AbstractTimeoutHandler() {
        timeoutTask = new SocketTimeoutTask(this::timeoutOccurred);
    }

    /**
     * <p>Enables or disables the timeout entirely. This may be useful if you want to store the timeout value but wish
     * to temporarily disable/enable timeouts.</p>
     *
     * <p>The default is for timeoutEnabled to be true but timeoutMillis to be set to 0 (ie disabled).</p>
     *
     * <p>This call will reset the current progress towards the timeout.</p>
     */
    @Override
    public synchronized final void setTimeoutEnabled(boolean timeoutEnabled) {
        timeoutTask.setTimeoutEnabled(timeoutEnabled);
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
    @Override
    public synchronized final void setSocketTimeout(int timeoutMillis) {
        timeoutTask.setSocketTimeout(timeoutMillis);
    }

    /**
     * Resets the current progress towards timeout to 0.
     */
    protected synchronized void resetTimeout() {
        timeoutTask.resetTimeout();
    }

    protected abstract void timeoutOccurred();
}
