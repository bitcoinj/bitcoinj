/*
 * Copyright 2019 Giannis L. Jegutanis
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

import com.fasterxml.jackson.databind.ObjectMapper;
import org.bitcoinj.base.Coin;
import org.bitcoinj.base.Sha256Hash;
import org.bitcoinj.crypto.DumpedPrivateKey;
import org.bitcoinj.crypto.ECKey;
import org.bitcoinj.params.UnitTestParams;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.junit.BeforeClass;
import org.junit.Ignore;
import org.junit.Test;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

import static org.junit.Assert.*;

public class PartiallySignedTransactionTest {
    private static PsbtTestVectors tv;

    @BeforeClass
    public static void readTestVectors() throws IOException {
        tv = new ObjectMapper().readValue(
                PartiallySignedTransactionTest.class.getResource("rpc_psbt.json"),
                PsbtTestVectors.class
        );
    }

    @Test(expected = ProtocolException.class)
    public void testPsbtMagic() {
        PartiallySignedTransaction.read(ByteBuffer.wrap(new byte[]{'f', 'a', 'k', 'e', (byte) 0xff}));
    }

    @Test
    public void testPSBTInvalidVectors() {
        for (String psbtInvalid : tv.invalid) {
            try {
                PartiallySignedTransaction.fromBase64(psbtInvalid);
                fail(psbtInvalid);
            } catch (ProtocolException e) {
                /* expected */
            }
        }
    }

    @Test
    public void testPSBTValidVectors() {
        for (String psbtValid : tv.valid) {
            byte[] psbtBytes = Base64.decode(psbtValid);
            PartiallySignedTransaction psbt = PartiallySignedTransaction.read(ByteBuffer.wrap(psbtBytes));
            assertEquals(psbtBytes.length, psbt.messageSize());
            assertPsbtEquals(psbtValid, psbt);
        }
    }

    @Test
    public void testPSBTCreator() {
        final byte[] EMPTY_ARRAY = new byte[0];
        for (PsbtTestVectors.Creator creator : tv.creator) {
            Transaction rawTx = new Transaction();
            rawTx.setVersion(2); // Test uses a version 2 transaction
            for (PsbtTestVectors.Creator.Input input : creator.inputs) {
                Sha256Hash txHash = Sha256Hash.wrap(input.txid);
                TransactionOutPoint outpoint = TransactionOutPoint.of(txHash, input.vout);
                TransactionInput txIn = new TransactionInput(rawTx, EMPTY_ARRAY, outpoint);
                rawTx.addInput(txIn);
            }

            for (PsbtTestVectors.Creator.Output output : creator.outputs) {
                byte[] scriptBytes = Hex.decode(output.script);
                Coin value = Coin.valueOf(output.value);
                TransactionOutput txOut = new TransactionOutput(rawTx, value, scriptBytes);
                rawTx.addOutput(txOut);
            }

            PartiallySignedTransaction psbt = new PartiallySignedTransaction(rawTx);
            assertPsbtEquals(creator.result, psbt);
        }
    }

    @Test
    public void psbtCombinerTest() throws PartiallySignedTransaction.PsbtException {
        for (PsbtTestVectors.Combiner combiner : tv.combiner) {
            List<PartiallySignedTransaction> psbts = new ArrayList<>(combiner.combine.size());
            for (String combine : combiner.combine) {
                // Add PSBT tx to container
                psbts.add(PartiallySignedTransaction.fromBase64(combine));
            }
            PartiallySignedTransaction combined = PartiallySignedTransaction.combine(psbts);
            assertPsbtEquals(combiner.result, combined);
            // Also check that the original PSBTs are not changed
            for (PartiallySignedTransaction psbt : psbts) {
                assertNotEquals(combiner.result, psbt.toBase64());
            }
        }
    }

    @Ignore
    @Test
    // TODO implement signing and enable this test
    public void testPSBTSigner() {
        for (PsbtTestVectors.Signer signer : tv.signer) {
            PartiallySignedTransaction psbt = PartiallySignedTransaction.fromBase64(signer.psbt);
            List<ECKey> keys = new ArrayList<>(signer.privkeys.size());
            for (String privkey : signer.privkeys) {
                keys.add(DumpedPrivateKey.fromBase58(UnitTestParams.get().network, privkey).getKey());
            }
            // TODO implement signing
            assertPsbtEquals(signer.result, psbt);
        }
    }

    @Ignore
    @Test
    // TODO implement PSBT finalizer and enable this test
    public void psbtFinalizerTest() {
        for (PsbtTestVectors.Finalizer finalizer : tv.finalizer) {
            PartiallySignedTransaction psbt = PartiallySignedTransaction.fromBase64(finalizer.finalize);
            // TODO implement psbt.makeFinal()
            assertPsbtEquals(finalizer.result, psbt);
        }
    }

    @Test
    public void psbtExtractorTest() {
        for (PsbtTestVectors.Extractor extractor : tv.extractor) {
            PartiallySignedTransaction psbt = PartiallySignedTransaction.fromBase64(extractor.extract);
            Transaction tx = psbt.extract();
            assertNotNull(tx);
            assertEquals(extractor.result, Hex.toHexString(tx.serialize()));
        }
    }

    /**
     * Compare a PSBT to its Base64 representation but print failed assert in Hex for easier debugging
     */
    private void assertPsbtEquals(String expectedPsbt, PartiallySignedTransaction psbt) {
        byte[] psbtBytes = psbt.write(ByteBuffer.allocate(psbt.messageSize())).array();
        if (!expectedPsbt.equals(Base64.toBase64String(psbtBytes))) {
            String result = Hex.toHexString(psbtBytes);
            String expected = Hex.toHexString(Base64.decode(expectedPsbt));
            assertEquals(expected, result);
        }
    }

    /**
     * A class to easily parse the rpc_psbt.json taken from the Bitcoin Core project
     */
    static class PsbtTestVectors {
        public ArrayList<String> invalid;
        public ArrayList<String> valid;
        public ArrayList<Creator> creator;
        public ArrayList<Signer> signer;
        public ArrayList<Combiner> combiner;
        public ArrayList<Finalizer> finalizer;
        public ArrayList<Extractor> extractor;

        static class Creator {
            static class Input {
                public String txid;
                public int vout;
            }
            static class Output {
                public String script;
                public long value;
            }

            public ArrayList<Input> inputs;
            public ArrayList<Output> outputs;
            public String result;
        }

        static class Signer {
            public ArrayList<String> privkeys;
            public String psbt;
            public String result;
        }

        static class Combiner {
            public ArrayList<String> combine;
            public String result;
        }

        static class Finalizer {
            public String finalize;
            public String result;
        }

        static class Extractor {
            public String extract;
            public String result;
        }
    }
}
