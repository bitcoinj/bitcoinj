/*
 * Copyright by the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.bitcoinj.wallet;

import org.bitcoinj.base.Address;
import org.bitcoinj.base.BitcoinNetwork;
import org.bitcoinj.base.Coin;
import org.bitcoinj.base.ScriptType;
import org.bitcoinj.crypto.AesKey;
import org.bitcoinj.crypto.ECKey;
import org.junit.Test;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class SendRequestTest {

    private static Address randomAddress() {
        return ECKey.random().toAddress(ScriptType.P2PKH, BitcoinNetwork.TESTNET);
    }

    @Test
    public void testToString() {
        SendRequest req = SendRequest.to(randomAddress(), Coin.SATOSHI);

        String s = req.toString();
        // Sanity: a few of the user-settable fields should always show up so
        // toString() remains useful for debugging.
        assertTrue(s.contains("emptyWallet"));
        assertTrue(s.contains("feePerKb"));
        assertTrue(s.contains("ensureMinRequiredFee"));
        assertTrue(s.contains("signInputs"));
    }

    @Test
    public void testToString_omitsAesKeyWhenUnset() {
        // omitNullValues() should drop the aesKey entry entirely when no key is set.
        SendRequest req = SendRequest.to(randomAddress(), Coin.SATOSHI);

        String s = req.toString();
        assertFalse(s.contains("aesKey"));
    }

    @Test
    public void testToString_doesNotLeakAesKeyBytes() {
        // Build a distinctive raw key so we can search for it in toString output.
        byte[] keyBytes = new byte[]{
            (byte) 0xCA, (byte) 0xFE, (byte) 0xBA, (byte) 0xBE,
            (byte) 0xDE, (byte) 0xAD, (byte) 0xBE, (byte) 0xEF,
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
            0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        };
        SendRequest req = SendRequest.to(randomAddress(), Coin.SATOSHI);
        req.aesKey = new AesKey(keyBytes);

        String s = req.toString();

        // The presence marker must be there...
        assertTrue("toString() should mark that an aesKey is set", s.contains("aesKey=set"));

        // ...but the actual bytes must not, in any common representation. This is the
        // regression test for the explicit "careful to not leak the key" guard in
        // SendRequest.toString().
        assertFalse("Security Fail: toString() leaked the aesKey hex bytes!",
                s.toLowerCase().contains("cafebabedeadbeef"));
        assertFalse("Security Fail: toString() leaked the aesKey as an int array!",
                s.contains("-54, -2, -70, -66"));
        assertFalse("Security Fail: toString() leaked the aesKey as an unsigned array!",
                s.contains("202, 254, 186, 190"));
    }
}
