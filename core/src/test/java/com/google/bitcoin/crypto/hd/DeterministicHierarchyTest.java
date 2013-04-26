package com.google.bitcoin.crypto.hd;

import com.google.bitcoin.crypto.hd.wallet.DeterministicKeyGenerator;
import org.junit.Assert;
import org.junit.Test;

import java.security.SecureRandom;

/**
 * @author Matija Mazi <br/>
 */
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
            Assert.assertEquals(walletRootKey.getChildNumber().getChildNumber(), iWallet);

            Assert.assertEquals(0L, hdWalletKeyGen.nextInternal().getChildNumber().getChildNumber());
            Assert.assertEquals(1L, hdWalletKeyGen.nextInternal().getChildNumber().getChildNumber());
            Assert.assertEquals(2L, hdWalletKeyGen.nextInternal().getChildNumber().getChildNumber());

            Assert.assertEquals(0L, hdWalletKeyGen.nextExternal().getChildNumber().getChildNumber());
            Assert.assertEquals(1L, hdWalletKeyGen.nextExternal().getChildNumber().getChildNumber());
            Assert.assertEquals(2L, hdWalletKeyGen.nextExternal().getChildNumber().getChildNumber());

            Assert.assertEquals(3L, hdWalletKeyGen.nextInternal().getChildNumber().getChildNumber());

            Assert.assertEquals(3L, hdWalletKeyGen.nextExternal().getChildNumber().getChildNumber());
        }
    }
}
