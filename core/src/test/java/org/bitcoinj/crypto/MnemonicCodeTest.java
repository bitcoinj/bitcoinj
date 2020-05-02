/*
 * Copyright 2013 Ken Sedgwick
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

package org.bitcoinj.crypto;

import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import static org.bitcoinj.core.Utils.HEX;
import static org.bitcoinj.core.Utils.WHITESPACE_SPLITTER;
import static org.junit.Assert.assertEquals;

/**
 * Test the various guard clauses of {@link MnemonicCode}.
 *
 * See {@link MnemonicCodeVectorsTest} test vectors.
 */
public class MnemonicCodeTest {

    private MnemonicCode mc;

    @Before
    public void setup() throws IOException {
        mc = new MnemonicCode();
    }

    @Test(expected = MnemonicException.MnemonicLengthException.class)
    public void testBadEntropyLength() throws Exception {
        byte[] entropy = HEX.decode("7f7f7f7f7f7f7f7f7f7f7f7f7f7f");
        mc.toMnemonic(entropy);
    }

    @Test(expected = MnemonicException.MnemonicLengthException.class)
    public void testBadLength() throws Exception {
        List<String> words = WHITESPACE_SPLITTER.splitToList("risk tiger venture dinner age assume float denial penalty hello");
        mc.check(words);
    }

    @Test(expected = MnemonicException.MnemonicWordException.class)
    public void testBadWord() throws Exception {
        List<String> words = WHITESPACE_SPLITTER.splitToList("risk tiger venture dinner xyzzy assume float denial penalty hello game wing");
        mc.check(words);
    }

    @Test(expected = MnemonicException.MnemonicChecksumException.class)
    public void testBadChecksum() throws Exception {
        List<String> words = WHITESPACE_SPLITTER.splitToList("bless cloud wheel regular tiny venue bird web grief security dignity zoo");
        mc.check(words);
    }

    @Test(expected = MnemonicException.MnemonicLengthException.class)
    public void testEmptyMnemonic() throws Exception {
        List<String> words = new ArrayList<>();
        mc.check(words);
    }

    @Test(expected = MnemonicException.MnemonicLengthException.class)
    public void testEmptyEntropy() throws Exception {
        byte[] entropy = {};
        mc.toMnemonic(entropy);
    }

    @Test(expected = NullPointerException.class)
    public void testNullPassphrase() {
        List<String> code = WHITESPACE_SPLITTER.splitToList("legal winner thank year wave sausage worth useful legal winner thank yellow");
        MnemonicCode.toSeed(code, null);
    }

    /**
     * Test data from: https://iancoleman.io/bip39/#english
     */
    @Test
    public void testWithPassphraseSpecialChars() {
        List<String> code = WHITESPACE_SPLITTER.splitToList(
                "smart deer exclude episode famous inside post inmate rocket analyst soccer mammal");
        final byte[] seed = MnemonicCode.toSeed(code, "BananoweŻycie");

        assertEquals(
                "2e9c82dde1ed6e8ce61bb9403b570ff5021843638d589100796b40b513b7f82fa0306037321e13a237fb04016daaa94b4c2c6e23453a2f500e3b6fa1e0ee7c99",
                HEX.encode(seed));
    }
}
