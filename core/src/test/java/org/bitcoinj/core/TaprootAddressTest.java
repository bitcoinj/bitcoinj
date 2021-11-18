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

import org.bitcoinj.params.MainNetParams;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Test;
import java.io.*;
import static org.junit.Assert.*;

/*
Some test vectors taken from
https://github.com/bitcoin/bips/blob/master/bip-0341/wallet-test-vectors.json
 */

public class TaprootAddressTest {
    private static final MainNetParams MAINNET = MainNetParams.get();

    @Test
    public void pubkey_with_null_script_tree() throws IOException {
        ECKey key = ECKey.fromPublicOnly(Hex.decode("02d6889cb081036e0faefa3a35157ad71086b123b2b144b649798b494c300a961d"));
        byte[] witnessProgram = key.getTweakedPublicKey(null);
        SegwitAddress segwitAddress = SegwitAddress.fromProgram(MAINNET, 1, witnessProgram);
        assertEquals("bc1p2wsldez5mud2yam29q22wgfh9439spgduvct83k3pm50fcxa5dps59h4z5", segwitAddress.toBech32());
    }

    @Test
    public void pubkey_with_script_tree() throws IOException {
        ECKey key = ECKey.fromPublicOnly(Hex.decode("02187791b6f712a8ea41c8ecdd0ee77fab3e85263b37e1ec18a3651926b3a6cf27"));
        byte[] merkleRoot = Hex.decode("5b75adecf53548f3ec6ad7d78383bf84cc57b55a3127c72b9a2481752dd88b21");
        byte[] witnessProgram = key.getTweakedPublicKey(merkleRoot);
        SegwitAddress segwitAddress = SegwitAddress.fromProgram(MAINNET, 1, witnessProgram);
        assertEquals("bc1pz37fc4cn9ah8anwm4xqqhvxygjf9rjf2resrw8h8w4tmvcs0863sa2e586", segwitAddress.toBech32());
    }

    @Test
    public void pubkey_with_script_tree_2() throws IOException {
        ECKey key = ECKey.fromPublicOnly(Hex.decode("0293478e9488f956df2396be2ce6c5cced75f900dfa18e7dabd2428aae78451820"));
        byte[] merkleRoot = Hex.decode("c525714a7f49c28aedbbba78c005931a81c234b2f6c99a73e4d06082adc8bf2b");
        byte[] witnessProgram = key.getTweakedPublicKey(merkleRoot);
        SegwitAddress segwitAddress = SegwitAddress.fromProgram(MAINNET, 1, witnessProgram);
        assertEquals("bc1punvppl2stp38f7kwv2u2spltjuvuaayuqsthe34hd2dyy5w4g58qqfuag5", segwitAddress.toBech32());
    }

    @Test
    public void pubkey_with_script_tree_3() throws IOException {
        ECKey key = ECKey.fromPublicOnly(Hex.decode("03f9f400803e683727b14f463836e1e78e1c64417638aa066919291a225f0e8dd8"));
        byte[] merkleRoot = Hex.decode("ab179431c28d3b68fb798957faf5497d69c883c6fb1e1cd9f81483d87bac90cc");
        byte[] witnessProgram = key.getTweakedPublicKey(merkleRoot);
        SegwitAddress segwitAddress = SegwitAddress.fromProgram(MAINNET, 1, witnessProgram);
        assertEquals("bc1pwl3s54fzmk0cjnpl3w9af39je7pv5ldg504x5guk2hpecpg2kgsqaqstjq", segwitAddress.toBech32());
    }

    @Test
    public void pubkey_with_complex_script_tree() throws IOException {
        ECKey key = ECKey.fromPublicOnly(Hex.decode("0255adf4e8967fbd2e29f20ac896e60c3b0f1d5b0efa9d34941b5958c7b0a0312d"));
        byte[] merkleRoot = Hex.decode("2f6b2c5397b6d68ca18e09a3f05161668ffe93a988582d55c6f07bd5b3329def");
        byte[] witnessProgram = key.getTweakedPublicKey(merkleRoot);
        SegwitAddress segwitAddress = SegwitAddress.fromProgram(MAINNET, 1, witnessProgram);
        assertEquals("bc1pw5tf7sqp4f50zka7629jrr036znzew70zxyvvej3zrpf8jg8hqcssyuewe", segwitAddress.toBech32());
    }

    @Test
    public void prvkey_with_script_tree() throws IOException {
        ECKey key = ECKey.fromPrivate(Hex.decode("77863416be0d0665e517e1c375fd6f75839544eca553675ef7fdf4949518ebaa"));
        byte[] merkleRoot = Hex.decode("ab179431c28d3b68fb798957faf5497d69c883c6fb1e1cd9f81483d87bac90cc");
        byte[] tweakedPrivateKey = key.getTweakedPrivateKey(merkleRoot);
        ECKey tweakedKey = ECKey.fromPrivate(tweakedPrivateKey);
        String tweakedPubKey = Hex.toHexString(tweakedKey.getPubKey()).substring(2);
        byte[] witnessProgram = Hex.decode(tweakedPubKey);
        SegwitAddress segwitAddress = SegwitAddress.fromProgram(MAINNET, 1, witnessProgram);
        assertEquals("bc1pwl3s54fzmk0cjnpl3w9af39je7pv5ldg504x5guk2hpecpg2kgsqaqstjq", segwitAddress.toBech32());
    }
}
