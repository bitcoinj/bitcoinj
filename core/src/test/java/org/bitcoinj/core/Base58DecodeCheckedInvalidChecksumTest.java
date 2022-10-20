/*
 * Copyright 2011 Google Inc.
 * Copyright 2014 Andreas Schildbach
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

import org.bitcoinj.base.Base58;
import org.bitcoinj.base.exceptions.AddressFormatException;
import org.junit.Test;

public class Base58DecodeCheckedInvalidChecksumTest {

    @Test(expected = AddressFormatException.InvalidChecksum.class)
    public void testDecodeChecked_invalidChecksum() {
        Base58.decodeChecked("4stwEBjT6FYyVW");
    }
}
