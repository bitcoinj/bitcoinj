/*
 * Copyright 2011 Google Inc.
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

package org.bitcoincashj.core;

@SuppressWarnings("serial")
public class VerificationException extends RuntimeException {
    public VerificationException(String msg) {
        super(msg);
    }

    public VerificationException(Exception e) {
        super(e);
    }

    public VerificationException(String msg, Throwable t) {
        super(msg, t);
    }

    public static class EmptyInputsOrOutputs extends VerificationException {
        public EmptyInputsOrOutputs() {
            super("Transaction had no inputs or no outputs.");
        }
    }

    public static class LargerThanMaxBlockSize extends VerificationException {
        public LargerThanMaxBlockSize() {
            super("Transaction larger than MAX_BLOCK_SIZE");
        }
    }

    public static class DuplicatedOutPoint extends VerificationException {
        public DuplicatedOutPoint() {
            super("Duplicated outpoint");
        }
    }

    public static class NegativeValueOutput extends VerificationException {
        public NegativeValueOutput() {
            super("Transaction output negative");
        }
    }

    public static class ExcessiveValue extends VerificationException {
        public ExcessiveValue() {
            super("Total transaction output value greater than possible");
        }
    }


    public static class CoinbaseScriptSizeOutOfRange extends VerificationException {
        public CoinbaseScriptSizeOutOfRange() {
            super("Coinbase script size out of range");
        }
    }


    public static class BlockVersionOutOfDate extends VerificationException {
        public BlockVersionOutOfDate(final long version) {
            super("Block version #"
                + version + " is outdated.");
        }
    }

    public static class UnexpectedCoinbaseInput extends VerificationException {
        public UnexpectedCoinbaseInput() {
            super("Coinbase input as input in non-coinbase transaction");
        }
    }

    public static class CoinbaseHeightMismatch extends VerificationException {
        public CoinbaseHeightMismatch(final String message) {
            super(message);
        }
    }
}
