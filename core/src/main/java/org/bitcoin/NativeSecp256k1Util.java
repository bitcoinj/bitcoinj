/*
 * Copyright 2014-2016 the libsecp256k1 contributors
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

package org.bitcoin;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Assertion utilities for {@link NativeSecp256k1}
 * @deprecated See https://github.com/bitcoinj/bitcoinj/issues/2267
 */
@Deprecated
public class NativeSecp256k1Util {

    private static final Logger log = LoggerFactory.getLogger(NativeSecp256k1Util.class);

    /**
     * Compare two integers and throw {@link AssertFailException} if not equal
     *
     * @param val first int
     * @param val2 second int
     * @param message failure error message
     * @throws AssertFailException when ints are not equal
     */
    public static void assertEquals(int val, int val2, String message) throws AssertFailException {
        if (val != val2)
            throw new AssertFailException("FAIL: " + message);
    }

    /**
     * Compare two booleans and throw {@link AssertFailException} if not equal
     *
     * @param val first boolean
     * @param val2 second boolean
     * @param message failure error message
     * @throws AssertFailException when booleans are not equal
     */
    public static void assertEquals(boolean val, boolean val2, String message) throws AssertFailException {
        if (val != val2)
            throw new AssertFailException("FAIL: " + message);
        else
            log.debug("PASS: " + message);
    }

    /**
     * Compare two Strings and throw {@link AssertFailException} if not equal
     *
     * @param val first String
     * @param val2 second String
     * @param message failure error message
     * @throws AssertFailException when Strings are not equal
     */
    public static void assertEquals(String val, String val2, String message) throws AssertFailException {
        if (!val.equals(val2))
            throw new AssertFailException("FAIL: " + message);
        else
            log.debug("PASS: " + message);
    }

    /**
     * Assertion failure exception
     */
    public static class AssertFailException extends Exception {
        /**
         * @param message The failure message
         */
        public AssertFailException(String message) {
            super(message);
        }
    }
}
