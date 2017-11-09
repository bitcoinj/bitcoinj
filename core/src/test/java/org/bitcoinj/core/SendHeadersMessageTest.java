/*
 * Copyright 2017 Anton Kumaigorodski
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

import org.bitcoinj.params.RegTestParams;
import org.junit.Test;

import java.nio.ByteBuffer;

import static org.bitcoinj.core.Utils.HEX;
import static org.junit.Assert.assertTrue;

public class SendHeadersMessageTest {
    @Test
    public void decodeAndEncode() throws Exception {
        byte[] message = HEX
                .decode("00000000fabfb5da73656e646865616465727300000000005df6e0e2fabfb5da70696e670000000000000000080000009a"
                        + "65b9cc9840c9729e4502b200000000000000000000000000000d000000000000000000000000000000000000000000000000007ad82"
                        + "872c28ac782102f5361746f7368693a302e31342e312fe41d000001fabfb5da76657261636b000000000000000000005df6e0e2fabf"
                        + "b5da616c65727400000000000000a80000001bf9aaea60010000000000000000000000ffffff7f00000000ffffff7ffeffff7f01fff"
                        + "fff7f00000000ffffff7f00ffffff7f002f555247454e543a20416c657274206b657920636f6d70726f6d697365642c207570677261"
                        + "6465207265717569726564004630440220653febd6410f470f6bae11cad19c48413becb1ac2c17f908fd0fd53bdc3abd5202206d0e9"
                        + "c96fe88d4a0f01ed9dedae2b6f9e00da94cad0fecaae66ecf689bf71b50000000000000000000000000000000000000000000000000");

        ByteBuffer buffer = ByteBuffer.wrap(message);
        RegTestParams params = org.bitcoinj.params.RegTestParams.get();
        BitcoinSerializer serializer = new BitcoinSerializer(params, false);
        assertTrue(serializer.deserialize(buffer) instanceof org.bitcoinj.core.SendHeadersMessage);
    }
}
