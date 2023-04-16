/*
 * Copyright by the original author or authors.
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

import junitparams.JUnitParamsRunner;
import junitparams.Parameters;
import org.bitcoinj.base.Coin;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

import static org.junit.Assert.assertEquals;

/**
 * Test FeeFilterMessage
 */
@RunWith(JUnitParamsRunner.class)
public class FeeFilterMessageTest {
    @Test
    @Parameters(method = "validFeeRates")
    public void roundTripValid(Coin feeRate) {
        byte[] buf = ByteBuffer.allocate(Long.BYTES).order(ByteOrder.LITTLE_ENDIAN).putLong(feeRate.getValue()).array();
        FeeFilterMessage ffm = FeeFilterMessage.read(ByteBuffer.wrap(buf));
        assertEquals(feeRate, ffm.feeRate());

        byte[] serialized = ffm.serialize();
        FeeFilterMessage ffm2 = FeeFilterMessage.read(ByteBuffer.wrap(serialized));
        assertEquals(feeRate, ffm2.feeRate());
    }

    @Test(expected = ProtocolException.class)
    @Parameters(method = "invalidFeeRates")
    public void invalid(Coin feeRate) {
        byte[] buf = ByteBuffer.allocate(Long.BYTES).order(ByteOrder.LITTLE_ENDIAN).putLong(feeRate.getValue()).array();
        FeeFilterMessage ffm = FeeFilterMessage.read(ByteBuffer.wrap(buf));
    }

    private Coin[] validFeeRates() {
        return new Coin[] { Coin.ZERO, Coin.SATOSHI, Coin.FIFTY_COINS, Coin.valueOf(Long.MAX_VALUE) };
    }

    private Coin[] invalidFeeRates() {
        return new Coin[] { Coin.NEGATIVE_SATOSHI, Coin.valueOf(Integer.MIN_VALUE), Coin.valueOf(Long.MIN_VALUE) };
    }
}
