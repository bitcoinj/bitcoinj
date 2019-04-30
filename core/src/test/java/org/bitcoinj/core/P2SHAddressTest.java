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
import org.bitcoinj.params.TestNet3Params;
import org.bitcoinj.script.Script;
import org.bitcoinj.script.ScriptBuilder;
import org.bitcoinj.script.ScriptPattern;
import org.junit.Test;

import java.util.Arrays;
import java.util.List;

import static org.bitcoinj.core.Utils.HEX;
import static org.junit.Assert.*;

public class P2SHAddressTest {
    private static final NetworkParameters TESTNET = TestNet3Params.get();
    private static final NetworkParameters MAINNET = MainNetParams.get();

    @Test
    public void creation() {
        // Test that we can construct P2SH addresses
        P2SHAddress mainNetP2SHAddress = P2SHAddress.fromBase58(MainNetParams.get(), "35b9vsyH1KoFT5a5KtrKusaCcPLkiSo1tU");
        assertEquals(mainNetP2SHAddress.getVersion(), MAINNET.p2shHeader);
        P2SHAddress testNetP2SHAddress = P2SHAddress.fromBase58(TestNet3Params.get(), "2MuVSxtfivPKJe93EC1Tb9UhJtGhsoWEHCe");
        assertEquals(testNetP2SHAddress.getVersion(), TESTNET.p2shHeader);

        // Test that we can determine what network a P2SH address belongs to
        NetworkParameters mainNetParams = P2SHAddress.getParametersFromAddress("35b9vsyH1KoFT5a5KtrKusaCcPLkiSo1tU");
        assertEquals(MAINNET.getId(), mainNetParams.getId());
        NetworkParameters testNetParams = P2SHAddress.getParametersFromAddress("2MuVSxtfivPKJe93EC1Tb9UhJtGhsoWEHCe");
        assertEquals(TESTNET.getId(), testNetParams.getId());

        // Test that we can convert them from hashes
        byte[] hex = HEX.decode("2ac4b0b501117cc8119c5797b519538d4942e90e");
        P2SHAddress a = P2SHAddress.fromScriptHash(MAINNET, hex);
        assertEquals("35b9vsyH1KoFT5a5KtrKusaCcPLkiSo1tU", a.toString());
        P2SHAddress b = P2SHAddress.fromScriptHash(TESTNET, HEX.decode("18a0e827269b5211eb51a4af1b2fa69333efa722"));
        assertEquals("2MuVSxtfivPKJe93EC1Tb9UhJtGhsoWEHCe", b.toString());
        P2SHAddress c = P2SHAddress.fromScriptHash(MAINNET,
                ScriptPattern.extractHashFromP2SH(ScriptBuilder.createP2SHOutputScript(hex)));
        assertEquals("35b9vsyH1KoFT5a5KtrKusaCcPLkiSo1tU", c.toString());
    }

    @Test
    public void creationFromKeys() {
        // import some keys from this example: https://gist.github.com/gavinandresen/3966071
        ECKey key1 = DumpedPrivateKey.fromBase58(MAINNET, "5JaTXbAUmfPYZFRwrYaALK48fN6sFJp4rHqq2QSXs8ucfpE4yQU").getKey();
        key1 = ECKey.fromPrivate(key1.getPrivKeyBytes());
        ECKey key2 = DumpedPrivateKey.fromBase58(MAINNET, "5Jb7fCeh1Wtm4yBBg3q3XbT6B525i17kVhy3vMC9AqfR6FH2qGk").getKey();
        key2 = ECKey.fromPrivate(key2.getPrivKeyBytes());
        ECKey key3 = DumpedPrivateKey.fromBase58(MAINNET, "5JFjmGo5Fww9p8gvx48qBYDJNAzR9pmH5S389axMtDyPT8ddqmw").getKey();
        key3 = ECKey.fromPrivate(key3.getPrivKeyBytes());

        List<ECKey> keys = Arrays.asList(key1, key2, key3);
        Script p2shScript = ScriptBuilder.createP2SHOutputScript(2, keys);
        P2SHAddress address = P2SHAddress.fromScriptHash(MAINNET,
                ScriptPattern.extractHashFromP2SH(p2shScript));
        assertEquals("3N25saC4dT24RphDAwLtD8LUN4E2gZPJke", address.toString());
    }

    @Test
    public void errorPaths() {
        // Check what happens if we try and decode garbage.
        try {
            P2SHAddress.fromBase58(TESTNET, "this is not a valid address!");
            fail();
        } catch (AddressFormatException.WrongNetwork | AddressFormatException.WrongAddressType e) {
            fail();
        } catch (AddressFormatException e) {
            // Success.
        }


        // Check the empty case.
        try {
            P2SHAddress.fromBase58(TESTNET, "");
            fail();
        } catch (AddressFormatException.WrongNetwork | AddressFormatException.WrongAddressType e) {
            fail();
        } catch (AddressFormatException e) {
            // Success.
        }

        // Check the case of a mismatched network.
        try {
            P2SHAddress.fromBase58(TESTNET, "35b9vsyH1KoFT5a5KtrKusaCcPLkiSo1tU");
            fail();
        } catch (AddressFormatException.WrongNetwork e) {
            // Success.
        } catch (AddressFormatException e) {
            fail();
        }

        // Check the case of decoding a P2PKH address
        try {
            P2SHAddress.fromBase58(TESTNET, "n4eA2nbYqErp7H6jebchxAN59DmNpksexv");
            fail();
        } catch (AddressFormatException.WrongAddressType e) {
            // Success.
        } catch (AddressFormatException e) {
            fail();
        }
    }

    @Test
    public void cloning() throws Exception {
        P2SHAddress a = P2SHAddress.fromScriptHash(TESTNET, HEX.decode("18a0e827269b5211eb51a4af1b2fa69333efa722"));
        P2SHAddress b = a.clone();

        assertEquals(a, b);
        assertNotSame(a, b);
    }

    @Test
    public void roundtripBase58() {
        String base58 = "3N25saC4dT24RphDAwLtD8LUN4E2gZPJke";
        assertEquals(base58, P2SHAddress.fromBase58(null, base58).toBase58());
    }

    @Test
    public void comparisonCloneEqualTo() throws Exception {
        String base58 = "3N25saC4dT24RphDAwLtD8LUN4E2gZPJke";
        LegacyAddress a = LegacyAddress.fromBase58(MAINNET, base58);
        LegacyAddress b = a.clone();

        int result = a.compareTo(b);
        assertEquals(0, result);
    }
}
