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
 * Thrown when a word is encountered which is not in the MnemonicCode's word list.
 */
@SuppressWarnings("serial")
public class MnemonicWordException extends Exception {
    /** Contains the word that was not found in the word list. */
    public String badWord;

    public MnemonicWordException(String msg, String badWord) {
        super(msg);
        this.badWord = badWord;
    }

    public MnemonicWordException(String badWord, Exception e) {
        super(e);
        this.badWord = badWord;
    }

    public MnemonicWordException(String msg, String badWord, Exception e) {
        super(msg, e);
        this.badWord = badWord;
    }

    public String getBadWord() {
        return badWord;
    }
}
