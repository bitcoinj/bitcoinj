/*
 * Copyright 2013 Ken Sedgwick
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

package com.google.bitcoin.crypto;

/**
 * Exceptions thrown by the MnemonicCode module.
 */
@SuppressWarnings("serial")
public class MnemonicException extends Exception {
    public MnemonicException(String msg) {
        super(msg);
    }
    public MnemonicException(Exception ex) {
        super(ex);
    }
    public MnemonicException(String msg, Exception ex) {
        super(msg, ex);
    }

    /**
     * Thrown when an argument to MnemonicCode is the wrong length.
     */
    public static class MnemonicLengthException extends MnemonicException {
        public MnemonicLengthException(String msg) {
            super(msg);
        }
        public MnemonicLengthException(Exception ex) {
            super(ex);
        }
        public MnemonicLengthException(String msg, Exception ex) {
            super(msg, ex);
        }
    }

    /**
     * Thrown when a list of MnemonicCode words fails the checksum check.
     */
    public static class MnemonicChecksumException extends MnemonicException {
        public MnemonicChecksumException(String msg) {
            super(msg);
        }
        public MnemonicChecksumException(Exception ex) {
            super(ex);
        }
        public MnemonicChecksumException(String msg, Exception ex) {
            super(msg, ex);
        }
    }

    /**
     * Thrown when a word is encountered which is not in the MnemonicCode's word list.
     */
    public static class MnemonicWordException extends MnemonicException {
        /** Contains the word that was not found in the word list. */
        public String badWord;

        public MnemonicWordException(String msg, String badWord) {
            super(msg);
            this.badWord = badWord;
        }
        public MnemonicWordException(String badWord, Exception ex) {
            super(ex);
            this.badWord = badWord;
        }
        public MnemonicWordException(String msg, String badWord, Exception ex) {
            super(msg, ex);
            this.badWord = badWord;
        }
        public String getBadWord() {
            return badWord;
        }
    }
}
