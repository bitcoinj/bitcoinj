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

package org.bitcoinj.utils;

import org.bitcoinj.core.Utils;
import com.google.common.primitives.Longs;

import static com.google.common.base.Preconditions.checkArgument;

/**
 * <p>Tracks successes and failures and calculates a time to retry the operation.</p>
 *
 * <p>The retries are exponentially backed off, up to a maximum interval.  On success the back off interval is reset.</p>
 */
public class ExponentialBackoff implements Comparable<ExponentialBackoff> {
    public static final int DEFAULT_INITIAL_MILLIS = 100;
    public static final float DEFAULT_MULTIPLIER = 1.1f;
    public static final int DEFAULT_MAXIMUM_MILLIS = 30 * 1000;

    private float backoff;
    private long retryTime;
    private final Params params;

    /**
     * Parameters to configure a particular kind of exponential backoff.
     */
    public static class Params {
        private final float initial;
        private final float multiplier;
        private final float maximum;

        /**
         * @param initialMillis the initial interval to wait, in milliseconds
         * @param multiplier the multiplier to apply on each failure
         * @param maximumMillis the maximum interval to wait, in milliseconds
         */
        public Params(long initialMillis, float multiplier, long maximumMillis) {
            checkArgument(multiplier > 1.0f, "multiplier must be greater than 1.0");
            checkArgument(maximumMillis >= initialMillis, "maximum must not be less than initial");

            this.initial = initialMillis;
            this.multiplier = multiplier;
            this.maximum = maximumMillis;
        }

        /**
         * Construct params with default values.
         */
        public Params() {
            initial = DEFAULT_INITIAL_MILLIS;
            multiplier = DEFAULT_MULTIPLIER;
            maximum = DEFAULT_MAXIMUM_MILLIS;
        }
    }

    public ExponentialBackoff(Params params) {
        this.params = params;
        trackSuccess();
    }

    /** Track a success - reset back off interval to the initial value */
    public final void trackSuccess() {
        backoff = params.initial;
        retryTime = Utils.currentTimeMillis();
    }

    /** Track a failure - multiply the back off interval by the multiplier */
    public void trackFailure() {
        retryTime = Utils.currentTimeMillis() + (long)backoff;
        backoff = Math.min(backoff * params.multiplier, params.maximum);
    }

    /** Get the next time to retry, in milliseconds since the epoch */
    public long getRetryTime() {
        return retryTime;
    }

    @Override
    public int compareTo(ExponentialBackoff other) {
        // note that in this implementation compareTo() is not consistent with equals()
        return Longs.compare(retryTime, other.retryTime);
    }

    @Override
    public String toString() {
        return "ExponentialBackoff retry=" + retryTime + " backoff=" + backoff;
    }
}
