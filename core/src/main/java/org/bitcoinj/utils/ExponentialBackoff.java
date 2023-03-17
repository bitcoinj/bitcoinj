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

import org.bitcoinj.base.internal.TimeUtils;

import java.time.Duration;
import java.time.Instant;

import static org.bitcoinj.base.internal.Preconditions.checkArgument;

/**
 * <p>Tracks successes and failures and calculates a time to retry the operation.</p>
 *
 * <p>The retries are exponentially backed off, up to a maximum interval.  On success the back off interval is reset.</p>
 */
public class ExponentialBackoff implements Comparable<ExponentialBackoff> {
    public static final Duration DEFAULT_INITIAL_INTERVAL = Duration.ofMillis(100);
    public static final float DEFAULT_MULTIPLIER = 1.1f;
    public static final Duration DEFAULT_MAXIMUM_INTERVAL = Duration.ofSeconds(30);

    private Duration backoff;
    private Instant retryTime;
    private final Params params;

    /**
     * Parameters to configure a particular kind of exponential backoff.
     */
    public static class Params {
        private final Duration initialInterval;
        private final float multiplier;
        private final Duration maximumInterval;

        /**
         * @param initialInterval the initial interval to wait
         * @param multiplier the multiplier to apply on each failure
         * @param maximumInterval the maximum interval to wait
         */
        public Params(Duration initialInterval, float multiplier, Duration maximumInterval) {
            checkArgument(multiplier > 1.0f, () ->
                    "multiplier must be greater than 1.0: " + multiplier);
            checkArgument(maximumInterval.compareTo(initialInterval) >= 0, () ->
                    "maximum must not be less than initial: " + maximumInterval);

            this.initialInterval = initialInterval;
            this.multiplier = multiplier;
            this.maximumInterval = maximumInterval;
        }

        /**
         * Construct params with default values.
         */
        public Params() {
            initialInterval = DEFAULT_INITIAL_INTERVAL;
            multiplier = DEFAULT_MULTIPLIER;
            maximumInterval = DEFAULT_MAXIMUM_INTERVAL;
        }
    }

    public ExponentialBackoff(Params params) {
        this.params = params;
        trackSuccess();
    }

    /** Track a success - reset back off interval to the initial value */
    public final void trackSuccess() {
        backoff = params.initialInterval;
        retryTime = TimeUtils.currentTime();
    }

    /** Track a failure - multiply the back off interval by the multiplier */
    public void trackFailure() {
        retryTime = TimeUtils.currentTime().plus(backoff);
        backoff = Duration.ofMillis((long) (backoff.toMillis() * params.multiplier));
        if (backoff.compareTo(params.maximumInterval) > 0)
            backoff = params.maximumInterval;
    }

    /** Get the next time to retry */
    public Instant retryTime() {
        return retryTime;
    }

    /**
     * Get the next time to retry, in milliseconds since the epoch
     * @deprecated use {@link #retryTime()}
     **/
    @Deprecated
    public long getRetryTime() {
        return retryTime.toEpochMilli();
    }

    @Override
    public int compareTo(ExponentialBackoff other) {
        // note that in this implementation compareTo() is not consistent with equals()
        return retryTime.compareTo(other.retryTime);
    }

    @Override
    public String toString() {
        return "ExponentialBackoff retry=" + retryTime + " backoff=" + backoff.toMillis() + " ms";
    }
}
