/*
 * Copyright 2019 Tim Strasser
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

import org.junit.Test;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Locale;

public class BtcFixedFormatThrowsIllegalStateExceptionTest {

    @Test(expected = IllegalStateException.class)
    public void testScaleThrowsIllegalStateException() {
        BtcFixedFormat btcFixedFormat = new BtcFixedFormat(Locale.getDefault(), BtcFormat.MILLICOIN_SCALE, 2,
                new ArrayList<Integer>());
        btcFixedFormat.scale(new BigInteger("2000"), 0);
    }
}
