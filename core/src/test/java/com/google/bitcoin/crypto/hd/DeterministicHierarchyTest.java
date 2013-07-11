/**
 * Copyright 2013 Matija Mazi.
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

package com.google.bitcoin.crypto.hd;

import com.google.bitcoin.crypto.hd.wallet.DeterministicKeyGenerator;
import org.junit.Test;

import java.security.SecureRandom;

import static org.junit.Assert.assertEquals;

public class DeterministicHierarchyTest {

    /**
     * Test creating a sequence of derived keys using the internal and external chain.
     */
    @Test
    public void testHierarchy() throws Exception {
        ExtendedHierarchicKey m = HDKeyDerivation.createMasterPrivateKey(new SecureRandom().generateSeed(32));

        for (int iWallet = 0; iWallet < 3; iWallet++) {
            ExtendedHierarchicKey walletRootKey = HDKeyDerivation.deriveChildKey(m, iWallet);
            DeterministicKeyGenerator hdWalletKeyGen = new DeterministicKeyGenerator(walletRootKey);
            assertEquals(walletRootKey.getChildNumber().getChildNumber(), iWallet);

            assertEquals(0L, hdWalletKeyGen.nextInternal().getChildNumber().getChildNumber());
            assertEquals(1L, hdWalletKeyGen.nextInternal().getChildNumber().getChildNumber());
            assertEquals(2L, hdWalletKeyGen.nextInternal().getChildNumber().getChildNumber());

            assertEquals(0L, hdWalletKeyGen.nextExternal().getChildNumber().getChildNumber());
            assertEquals(1L, hdWalletKeyGen.nextExternal().getChildNumber().getChildNumber());
            assertEquals(2L, hdWalletKeyGen.nextExternal().getChildNumber().getChildNumber());

            assertEquals(3L, hdWalletKeyGen.nextInternal().getChildNumber().getChildNumber());

            assertEquals(3L, hdWalletKeyGen.nextExternal().getChildNumber().getChildNumber());
        }
    }
}
