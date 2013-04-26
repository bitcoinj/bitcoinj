package com.google.bitcoin.crypto.hd;

import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.spongycastle.util.encoders.Hex;

/**
 * @author Matija Mazi <br/>
 *
 * This test is adapted from Armory's BIP 32 tests.
 */
public class ChildKeyDerivationTest {
    private static final Logger log = LoggerFactory.getLogger(ChildKeyDerivationTest.class);

    private static final int HDW_CHAIN_EXTERNAL = 0;
    private static final int HDW_CHAIN_INTERNAL = 1;

    @Test
    public void testChildKeyDerivation() throws Exception {
        String ckdTestVectors[] = {
                // test case 1:
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "04" +  "6a04ab98d9e4774ad806e302dddeb63b" +
                        "ea16b5cb5f223ee77478e861bb583eb3" +
                        "36b6fbcb60b5b3d4f1551ac45e5ffc49" +
                        "36466e7d98f6c7c0ec736539f74691a6",
                "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",

                // test case 2:
                "be05d9ded0a73f81b814c93792f753b35c575fe446760005d44e0be13ba8935a",
                "02" +  "b530da16bbff1428c33020e87fc9e699" +
                        "cc9c753a63b8678ce647b7457397acef",
                "7012bc411228495f25d666d55fdce3f10a93908b5f9b9b7baa6e7573603a7bda"
        };

        for(int i = 0; i < 1; i++) {
            byte[] priv  = Hex.decode(ckdTestVectors[3 * i]);
            byte[] pub   = Hex.decode(ckdTestVectors[3 * i + 1]);
            byte[] chain = Hex.decode(ckdTestVectors[3 * i + 2]); // chain code

            //////////////////////////////////////////////////////////////////////////
            // Start with an extended PRIVATE key
            ExtendedHierarchicKey ekprv = HDKeyDerivation.createMasterPrivKeyFromBytes(priv, chain);

            // Create two accounts
            ExtendedHierarchicKey ekprv_0 = HDKeyDerivation.deriveChildKey(ekprv, 0);
            ExtendedHierarchicKey ekprv_1 = HDKeyDerivation.deriveChildKey(ekprv, 1);

            // Create internal and external chain on Account 0
            ExtendedHierarchicKey ekprv_0_EX = HDKeyDerivation.deriveChildKey(ekprv_0, HDW_CHAIN_EXTERNAL);
            ExtendedHierarchicKey ekprv_0_IN = HDKeyDerivation.deriveChildKey(ekprv_0, HDW_CHAIN_INTERNAL);

            // Create three addresses on external chain
            ExtendedHierarchicKey ekprv_0_EX_0 = HDKeyDerivation.deriveChildKey(ekprv_0_EX, 0);
            ExtendedHierarchicKey ekprv_0_EX_1 = HDKeyDerivation.deriveChildKey(ekprv_0_EX, 1);
            ExtendedHierarchicKey ekprv_0_EX_2 = HDKeyDerivation.deriveChildKey(ekprv_0_EX, 2);

            // Create three addresses on internal chain
            ExtendedHierarchicKey ekprv_0_IN_0 = HDKeyDerivation.deriveChildKey(ekprv_0_IN, 0);
            ExtendedHierarchicKey ekprv_0_IN_1 = HDKeyDerivation.deriveChildKey(ekprv_0_IN, 1);
            ExtendedHierarchicKey ekprv_0_IN_2 = HDKeyDerivation.deriveChildKey(ekprv_0_IN, 2);

            // Now add a few more addresses with very large indices
            ExtendedHierarchicKey ekprv_1_IN = HDKeyDerivation.deriveChildKey(ekprv_1, HDW_CHAIN_INTERNAL);
            ExtendedHierarchicKey ekprv_1_IN_4095 = HDKeyDerivation.deriveChildKey(ekprv_1_IN, 4095);
//            ExtendedHierarchicKey ekprv_1_IN_4bil = HDKeyDerivation.deriveChildKey(ekprv_1_IN, 4294967295L);

            //////////////////////////////////////////////////////////////////////////
            // Repeat the above with PUBLIC key
            ExtendedHierarchicKey ekpub = HDKeyDerivation.createMasterPubKeyFromBytes(HDUtils.toCompressed(pub), chain);

            // Create two accounts
            ExtendedHierarchicKey ekpub_0 = HDKeyDerivation.deriveChildKey(ekpub, 0);
            ExtendedHierarchicKey ekpub_1 = HDKeyDerivation.deriveChildKey(ekpub, 1);

            // Create internal and external chain on Account 0
            ExtendedHierarchicKey ekpub_0_EX = HDKeyDerivation.deriveChildKey(ekpub_0, HDW_CHAIN_EXTERNAL);
            ExtendedHierarchicKey ekpub_0_IN = HDKeyDerivation.deriveChildKey(ekpub_0, HDW_CHAIN_INTERNAL);

            // Create three addresses on external chain
            ExtendedHierarchicKey ekpub_0_EX_0 = HDKeyDerivation.deriveChildKey(ekpub_0_EX, 0);
            ExtendedHierarchicKey ekpub_0_EX_1 = HDKeyDerivation.deriveChildKey(ekpub_0_EX, 1);
            ExtendedHierarchicKey ekpub_0_EX_2 = HDKeyDerivation.deriveChildKey(ekpub_0_EX, 2);

            // Create three addresses on internal chain
            ExtendedHierarchicKey ekpub_0_IN_0 = HDKeyDerivation.deriveChildKey(ekpub_0_IN, 0);
            ExtendedHierarchicKey ekpub_0_IN_1 = HDKeyDerivation.deriveChildKey(ekpub_0_IN, 1);
            ExtendedHierarchicKey ekpub_0_IN_2 = HDKeyDerivation.deriveChildKey(ekpub_0_IN, 2);

            // Now add a few more addresses with very large indices
            ExtendedHierarchicKey ekpub_1_IN = HDKeyDerivation.deriveChildKey(ekpub_1, HDW_CHAIN_INTERNAL);
            ExtendedHierarchicKey ekpub_1_IN_4095 = HDKeyDerivation.deriveChildKey(ekpub_1_IN, 4095);
//            ExtendedHierarchicKey ekpub_1_IN_4bil = HDKeyDerivation.deriveChildKey(ekpub_1_IN, 4294967295L);

            checkKeyMatch(ekprv, ekpub);
            checkKeyMatch(ekprv_0, ekpub_0);
            checkKeyMatch(ekprv_1, ekpub_1);
            checkKeyMatch(ekprv_0_IN, ekpub_0_IN);
            checkKeyMatch(ekprv_0_IN_0, ekpub_0_IN_0);
            checkKeyMatch(ekprv_0_IN_1, ekpub_0_IN_1);
            checkKeyMatch(ekprv_0_IN_2, ekpub_0_IN_2);
            checkKeyMatch(ekprv_0_EX_0, ekpub_0_EX_0);
            checkKeyMatch(ekprv_0_EX_1, ekpub_0_EX_1);
            checkKeyMatch(ekprv_0_EX_2, ekpub_0_EX_2);
            checkKeyMatch(ekprv_1_IN, ekpub_1_IN);
            checkKeyMatch(ekprv_1_IN_4095, ekpub_1_IN_4095);
//            checkKeyMatch(ekprv_1_IN_4bil, ekpub_1_IN_4bil);
        }
    }

    private void checkKeyMatch(ExtendedHierarchicKey ekprv, ExtendedHierarchicKey ekpub) {
        String fromPriv = hexEncodePub(ekprv.getPubOnly());
        String fromParentPublic = hexEncodePub(ekpub);
        log.info((fromPriv.equals(fromParentPublic) ? "OK: " : "***FAILED*** : ") + fromPriv + ", " + fromParentPublic);
    }

    /*
     * Commented out; these are old sipa's test vectors and the BIP32 derivation algorithm has been changed since.
     */
/*
    @Test
    public void testChildKeyDerivationSecond() throws Exception {

        // Using the test vectors created by sipa, starting with only a 16-byte seed
        byte[] seed = Hex.decode("ff000000000000000000000000000000");

        // We only need to compare public keys at each step, because any errors in 
        // those would cascade and cause everything else to be incorrect.
        // Remember BIP 32 says all steps must use compressed public keys.
        byte[] sipaPubKeyAnswers[] = {
                Hex.decode("02b530da16bbff1428c33020e87fc9e699cc9c753a63b8678ce647b7457397acef"),
                Hex.decode("032ad2472db0e9b1706c816a93dc55c72ef2ff339818718b676a563e063afa3f38"),
                Hex.decode("02655643c6fba3edf1139d59261590e5b358cbf19a063c88448f01558dd4fbf2c7"),
                Hex.decode("02a3b9ce007bbcfa0b9ec81779d07413256e72e516d14468a2e21172663376c233"),
                Hex.decode("03737b8811cda598ed635621997305e7a84e41c99990b69b88dfb021e74625247a"),
                Hex.decode("03bc1a550813b185e61d82a0823636e539dd86adbf591e9d3f91e32a579506c050"),
                Hex.decode("03f8d3b8825607daaca137909d9a74c8bb5d667bb06b9be519c2b171f47e6322d2"),
                Hex.decode("0322dd499c356165d7cbc6072be77354041b7ff6c7c256130189f829968275cfdc"),
                Hex.decode("0288e3cd9838a0d4c09d469befa2ff7fa0bbd2829a24bd8e1b3d3e6a64fe0f5380"),
                Hex.decode("0262001d6694e0c02a3fdc95e1e0ca3a2687233bd15145415cc6a4daf4b57c595e"),
                Hex.decode("02ea90cfbbeacc9bcd695449a4406fd886b3757774160e3de0d7fb7d9297ff5f1a"),
                Hex.decode("026199b74e5d514b0f520c40fc9f3eb9cba965bfa64aa70c435e9db6c7bb5ecd21"),
                Hex.decode("02415b0da16af9b210ba5c998b9d07553c33e1c570a34d174728c2211f5a894bf9"),
                Hex.decode("0330cb9a20e013cf203a79fc2c15c588019bb1016193f82ddefd28c05552b36503"),
                Hex.decode("02d8a3f07e15e34f6a14187907f49e5634080b7de946eb1f27f7979abf2fd54e72"),
                Hex.decode("032af575cb4fa722febb29ea3a7d8c9efd9dc410fcf86153c91b57c484c1d20313"),
                Hex.decode("031d55c55998f29a15fe38b0d466347df7519092ef8bc48193395167ff28cf99af")
        };

        // Master Key comes from HMAC_SHA512 using "Bitcoin seed" as the "key"
        ExtendedHierarchicKey computedPrivEK = HDKeyDerivation.createMasterPrivateKey(seed);
        ExtendedHierarchicKey computedPubEK = computedPrivEK.getPubOnly();

        log.info("********************************************************************************");
        log.info("Testing key chaining");
        for (int i = 0; i <= 16; i++) {
            log.info("*** {} ****************************************************************************", i);
            ExtendedHierarchicKey pubKey = computedPrivEK.getPubOnly();
            int childNumber = (1 << i) - 1;
            debug(computedPrivEK, computedPubEK, childNumber);
            Assert.assertArrayEquals(pubKey.getPubKeyBytes(), sipaPubKeyAnswers[i]);
            Assert.assertArrayEquals(computedPubEK.getPubKeyBytes(), sipaPubKeyAnswers[i]);
            log.info("OK.", childNumber);
            computedPrivEK = HDKeyDerivation.deriveChildKey(computedPrivEK, childNumber);
            computedPubEK = HDKeyDerivation.deriveChildKey(computedPubEK, childNumber);
        }
    }

    private void debug(ExtendedHierarchicKey computedPrivEK, ExtendedHierarchicKey computedPubEK, long childNumber) {
        log.info("Index:          {}", childNumber);
        log.info("Pr path:        {}", computedPrivEK.getPath());
        log.info("Pr Key:         {}", hexEncode(computedPrivEK.getPrivKeyBytes()));
        log.info("Pr Identifier:  {}", hexEncode(computedPrivEK.getIdentifier()));
        log.info("Pr Chain Code:  {}", hexEncode(computedPrivEK.getChainCode()));
        log.info("Pb Key:       {}", hexEncode(computedPubEK.getPubKeyBytes()));
        log.info("Pb path:        {}", computedPubEK.getPath());
        log.info("Pb Identifier:  {}", hexEncode(computedPubEK.getIdentifier()));
        log.info("Pb Fingerprint: {}", hexEncode(computedPubEK.getFingerprint()));
        log.info("Pb Chain Code:  {}", hexEncode(computedPubEK.getChainCode()));
    }

    private String hexEncodePriv(ExtendedHierarchicKey privKey) {
        return hexEncode(privKey.getPrivKeyBytes());
    }
*/

    private String hexEncodePub(ExtendedHierarchicKey pubKey) {
        return hexEncode(pubKey.getPubKeyBytes());
    }

    private String hexEncode(byte[] bytes) {
        return new String(Hex.encode(bytes));
    }
}
