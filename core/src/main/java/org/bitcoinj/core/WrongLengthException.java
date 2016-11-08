/*
 * Copyright 2017 the bitcoinj authors
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

package org.bitcoinj.core;

/**
 * This exception is thrown by the Address class when you try and decode an address with a version code that requires
 * a different length of hash.
 */
public class WrongLengthException extends AddressFormatException {
    public int length;

    public WrongLengthException(int length) {
        super("Length of address incorrect: " + length);
    }
}
