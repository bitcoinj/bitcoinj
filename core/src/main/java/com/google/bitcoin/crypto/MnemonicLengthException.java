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
 * Thrown when an argument to MnemonicCode is the wrong length.
 */
@SuppressWarnings("serial")
public class MnemonicLengthException extends Exception {
    public MnemonicLengthException(String msg) {
        super(msg);
    }

    public MnemonicLengthException(Exception e) {
        super(e);
    }

    public MnemonicLengthException(String msg, Exception e) {
        super(msg, e);
    }
}
