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

package com.google.bitcoin.core;

import javax.annotation.Nullable;
import java.math.BigInteger;

import static com.google.common.base.Preconditions.checkNotNull;

/**
 * Thrown to indicate that you don't have enough money available to perform the requested operation.
 */
public class InsufficientMoneyException extends Exception {
    /** Contains the number of satoshis that would have been required to complete the operation. */
    @Nullable
    public final BigInteger missing;

    protected InsufficientMoneyException() {
        this.missing = null;
    }

    public InsufficientMoneyException(BigInteger missing) {
        this(missing, "Insufficient money,  missing " + missing + " satoshis");
    }

    public InsufficientMoneyException(BigInteger missing, String message) {
        super(message);
        this.missing = checkNotNull(missing);
    }

    /**
     * Thrown when we were trying to empty the wallet, and the total amount of money we were trying to empty after
     * being reduced for the fee was smaller than the min payment. Note that the missing field will be null in this
     * case.
     */
    public static class CouldNotAdjustDownwards extends InsufficientMoneyException {
        public CouldNotAdjustDownwards() {
            super();
        }
    }
}
