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

import org.bitcoinj.base.internal.ByteUtils;
import org.bitcoinj.base.internal.InternalUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;

/**
 * A collection of various utility methods that are helpful for working with the Bitcoin protocol.
 * To enable debug logging from the library, run with -Dbitcoinj.logging=true on your command line.
 */
public class Utils {

    /**
     * Max initial size of variable length arrays and ArrayLists that could be attacked.
     * Avoids this attack: Attacker sends a msg indicating it will contain a huge number (e.g. 2 billion) elements (e.g. transaction inputs) and
     * forces bitcoinj to try to allocate a huge piece of the memory resulting in OutOfMemoryError.
    */
    public static final int MAX_INITIAL_ARRAY_LENGTH = 20;

    private static final Logger log = LoggerFactory.getLogger(Utils.class);

    public static String toString(List<byte[]> stack) {
        List<String> parts = new ArrayList<>(stack.size());
        for (byte[] push : stack)
            parts.add('[' + ByteUtils.formatHex(push) + ']');
        return InternalUtils.SPACE_JOINER.join(parts);
    }
}
