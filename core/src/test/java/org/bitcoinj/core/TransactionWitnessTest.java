/*
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

import org.bitcoinj.base.utils.ByteUtils;
import org.bitcoinj.crypto.TransactionSignature;
import org.bitcoinj.script.Script;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Test;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

public class TransactionWitnessTest {

    @Test
    public void testToString() {
        TransactionWitness w1 = new TransactionWitness(0);
        assertEquals("", w1.toString());

        TransactionWitness w2 = new TransactionWitness(2);
        assertEquals("", w2.toString());

        TransactionWitness w3 = new TransactionWitness(3);
        w3.setPush(0, ByteUtils.HEX.decode("123aaa"));
        w3.setPush(1, ByteUtils.HEX.decode("123bbb"));
        w3.setPush(3, ByteUtils.HEX.decode("123ccc"));
        assertEquals("123aaa 123bbb EMPTY 123ccc", w3.toString());
    }

    @Test
    public void testRedeemP2WSH() throws SignatureDecodeException {
        ECKey.ECDSASignature ecdsaSignature1 = TransactionSignature.decodeFromDER(Hex.decode("3045022100c3d84f7bf41c7eda3b23bbbccebde842a451c1a0aca39df706a3ff2fe78b1e0a02206e2e3c23559798b02302ad6fa5ddbbe87af5cc7d3b9f86b88588253770ab9f79"));
        TransactionSignature signature1 = new TransactionSignature(ecdsaSignature1, Transaction.SigHash.ALL, false);
        ECKey.ECDSASignature ecdsaSignature2 = TransactionSignature.decodeFromDER(Hex.decode("3045022100fcfe4a58f2878047ef7c5889fc52a3816ad2dd218807daa3c3eafd4841ffac4d022073454df7e212742f0fee20416b418a2c1340a33eebed5583d19a61088b112832"));
        TransactionSignature signature2 = new TransactionSignature(ecdsaSignature2, Transaction.SigHash.ALL, false);

        Script witnessScript = new Script(Hex.decode("522102bb65b325a986c5b15bd75e0d81cf149219597617a70995efedec6309b4600fa02103c54f073f5db9f68915019801435058c9232cb72c6528a2ca15af48eb74ca8b9a52ae"));

        TransactionWitness witness = TransactionWitness.redeemP2WSH(witnessScript, signature1, signature2);
        assertEquals(4, witness.getPushCount());
        assertArrayEquals(new byte[]{}, witness.getPush(0));
        assertArrayEquals(signature1.encodeToBitcoin(), witness.getPush(1));
        assertArrayEquals(signature2.encodeToBitcoin(), witness.getPush(2));
        assertArrayEquals(witnessScript.getProgram(), witness.getPush(3));
    }
}
