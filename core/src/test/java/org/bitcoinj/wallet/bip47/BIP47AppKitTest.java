
/* Copyright (c) 2017 Stash
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.bitcoinj.wallet.bip47;

import com.google.common.collect.Lists;
import org.bitcoinj.core.*;
import org.bitcoinj.core.bip47.BIP47Channel;
import org.bitcoinj.crypto.MnemonicCode;
import org.bitcoinj.kits.BIP47AppKit;
import org.bitcoinj.params.MainNetParams;
import org.bitcoinj.params.TestNet3Params;
import org.bitcoinj.testing.TestWithBIP47AppKit;
import org.bitcoinj.utils.BIP47Util;
import org.bitcoinj.wallet.*;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.security.SecureRandom;
import java.security.Security;
import java.util.List;

import static org.apache.commons.lang3.StringUtils.join;
import static org.bitcoinj.core.Utils.WHITESPACE_SPLITTER;
import static org.bitcoinj.core.Utils.HEX;
import static org.junit.Assert.*;

import org.bitcoinj.crypto.MnemonicCodeTest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class BIP47AppKitTest extends TestWithBIP47AppKit {
    private static final Logger log = LoggerFactory.getLogger(org.bitcoinj.wallet.WalletTest.class);

    //  - test vectors
    private final String ALICE_BIP39_MNEMONIC = "response seminar brave tip suit recall often sound stick owner lottery motion";
    private final String ALICE_BIP39_RAW_ENTROPY = "b7b8706d714d9166e66e7ed5b3c61048";
    private final String ALICE_BIP32_SEED = "64dca76abc9c6f0cf3d212d248c380c4622c8f93b2c425ec6a5567fd5db57e10d3e6f94a2f6af4ac2edb8998072aad92098db73558c323777abf5bd1082d970a";
    private final String ALICE_PAYMENT_CODE_V1 = "PM8TJTLJbPRGxSbc8EJi42Wrr6QbNSaSSVJ5Y3E4pbCYiTHUskHg13935Ubb7q8tx9GVbh2UuRnBc3WSyJHhUrw8KhprKnn9eDznYGieTzFcwQRya4GA";
    private final String ALICE_NOTIFICATION_ADDRESS = "1JDdmqFLhpzcUwPeinhJbUPw4Co3aWLyzW";

    private final String BOB_BIP39_MNEMONIC = "reward upper indicate eight swift arch injury crystal super wrestle already dentist";
    private final String BOB_BIP39_RAW_ENTROPY = "b8bde1cba37dbc161d09aad9bfc81c9d";
    private final String BOB_BIP32_SEED = "87eaaac5a539ab028df44d9110defbef3797ddb805ca309f61a69ff96dbaa7ab5b24038cf029edec5235d933110f0aea8aeecf939ed14fc20730bba71e4b1110";
    private final String BOB_PAYMENT_CODE_V1 = "PM8TJS2JxQ5ztXUpBBRnpTbcUXbUHy2T1abfrb3KkAAtMEGNbey4oumH7Hc578WgQJhPjBxteQ5GHHToTYHE3A1w6p7tU6KSoFmWBVbFGjKPisZDbP97";
    private final String BOB_NOTIFICATION_ADDRESS = "1ChvUUvht2hUQufHBXF8NgLhW8SwE2ecGV";

    private final String SHARED_SECRET_0 = "f5bb84706ee366052471e6139e6a9a969d586e5fe6471a9b96c3d8caefe86fef";
    private final String SHARED_SECRET_1 = "adfb9b18ee1c4460852806a8780802096d67a8c1766222598dc801076beb0b4d";
    private final String SHARED_SECRET_2 = "79e860c3eb885723bb5a1d54e5cecb7df5dc33b1d56802906762622fa3c18ee5";
    private final String SHARED_SECRET_3 = "d8339a01189872988ed4bd5954518485edebf52762bf698b75800ac38e32816d";
    private final String SHARED_SECRET_4  = "14c687bc1a01eb31e867e529fee73dd7540c51b9ff98f763adf1fc2f43f98e83";
    private final String SHARED_SECRET_5  = "725a8e3e4f74a50ee901af6444fb035cb8841e0f022da2201b65bc138c6066a2";
    private final String SHARED_SECRET_6  = "521bf140ed6fb5f1493a5164aafbd36d8a9e67696e7feb306611634f53aa9d1f";
    private final String SHARED_SECRET_7  = "5f5ecc738095a6fb1ea47acda4996f1206d3b30448f233ef6ed27baf77e81e46";
    private final String SHARED_SECRET_8  = "1e794128ac4c9837d7c3696bbc169a8ace40567dc262974206fcf581d56defb4";
    private final String SHARED_SECRET_9  = "fe36c27c62c99605d6cd7b63bf8d9fe85d753592b14744efca8be20a4d767c37";

    //  - keypairs M'/47'/0'/0'/0' .. M'/47'/0'/0'/2147483647'\

    //  - parameters to generate keys in ECDH.
    private String ALICE_;


    private final String CHANNEL_NTX = "010000000186f411ab1c8e70ae8a0795ab7a6757aea6e4d5ae1826fc7b8f00c597d500609c010000"
            + "006b483045022100ac8c6dbc482c79e86c18928a8b364923c774bfdbd852059f6b3778f2319b59a7022029d7cc5724e2f41ab1fcf"
            + "c0ba5a0d4f57ca76f72f19530ba97c860c70a6bf0a801210272d83d8a1fa323feab1c085157a0791b46eba34afb8bfbfaeb3a3fcc3"
            + "f2c9ad8ffffffff0210270000000000001976a9148066a8e7ee82e5c5b9b7dc1765038340dc5420a988ac1027000000000000536a4"
            + "c50010002063e4eb95e62791b06c50e1a3a942e1ecaaa9afbbeb324d16ae6821e091611fa96c0cf048f607fe51a0327f5e252897931"
            + "1c78cb2de0d682c61e1180fc3d543b0000000000000000000000000000000000";

    private final String CARLOS_BIP39_MNEMONIC = "fetch genuine seek want smile sea orient elbow basic where arrange display mask country walnut shuffle usage airport juice price grant scan wild alone";
    private final String CARLOS_PAYMENT_CODE = "PM8TJaWSfZYLLuJnXctJ8npNYrUr5UCeT6KGmayJ4ENDSqj7VZr7uyX9exCo5JA8mFLkeXPaHoCBKuMDpYFs3tdxP2UxNiHSsZtb1KkKSVQyiwFhdLTZ";

    private final Address OTHER_ADDRESS = LegacyAddress.fromKey(UNITTEST, new ECKey());


    //  - blockchains to test
    public static final String[] SUPPORTED_COINS = { "BCH", "BTC", "tBCH", "tBTC" };

    // -

    static {
        // Adds a new provider, at a specified position
        Security.insertProviderAt(new org.bouncycastle.jce.provider.BouncyCastleProvider(), 2);
        Security.addProvider(new BouncyCastleProvider());
    }
    private BIP47AppKit createWallet(String coinName, NetworkParameters params, File workingDir, String mnemonic) throws Exception {
        DeterministicSeed seed = null;
        if (mnemonic != null)
            seed = new DeterministicSeed(mnemonic, null, "", Utils.currentTimeSeconds());
        return new BIP47AppKit(coinName, params, workingDir, seed);
    };

    static void deleteFolder(String dirname){
        File dir = new File(dirname);
        if (!dir.exists())
            return;
        String[] entries = dir.list();
        for(String s: entries){
            File currentFile = new File(dir.getPath(),s);
            if (currentFile.isDirectory())
                deleteFolder((currentFile.getAbsolutePath()));
            else
                currentFile.delete();
        }
        dir.delete();
    }

    @Test
    public void aliceWalletTest() throws Exception {
        deleteFolder("target/test/output/aliceWalletTest");
        File workingDir = new File("target/test/output/aliceWalletTest");

        //  - test bip 39
        MnemonicCode mc = new MnemonicCode();
        List<String> code = mc.toMnemonic(HEX.decode(ALICE_BIP39_RAW_ENTROPY));
        byte[] seed = MnemonicCode.toSeed(code,"");
	List<String> words = Lists.newArrayList(WHITESPACE_SPLITTER.split(ALICE_BIP39_MNEMONIC));
        byte[] entropy = mc.toEntropy(words);

        assertEquals(ALICE_BIP39_RAW_ENTROPY, HEX.encode(entropy));
        assertEquals(ALICE_BIP39_MNEMONIC, join(code, " "));
        assertEquals(ALICE_BIP32_SEED, HEX.encode(seed));

        //  - test bip 47
        BIP47AppKit w = createWallet("BTC", MainNetParams.get(),workingDir,ALICE_BIP39_MNEMONIC);
        byte[] BTC_PUBKEY = w.getAccount(0).getPaymentCode().getPubKey();
        assertEquals(ALICE_PAYMENT_CODE_V1, w.getPaymentCode());
        assertEquals(ALICE_NOTIFICATION_ADDRESS, w.getAccount(0).getNotificationAddress().toString());

        w = createWallet("tBTC", TestNet3Params.get(),workingDir,ALICE_BIP39_MNEMONIC);
        byte[] tBTC_PUBKEY = w.getAccount(0).getPaymentCode().getPubKey();
        assertEquals(HEX.encode(tBTC_PUBKEY), HEX.encode(BTC_PUBKEY));
        assertEquals(ALICE_PAYMENT_CODE_V1, w.getPaymentCode());

        deleteFolder("target/test/output/aliceWalletTest");
    }

    @Test
    public void bobWalletTest() throws Exception {
        deleteFolder("target/test/output/bobWalletTest");

        //  - test bip 39
        MnemonicCode mc = new MnemonicCode();
        List<String> code = mc.toMnemonic(HEX.decode(BOB_BIP39_RAW_ENTROPY));
        byte[] seed = MnemonicCode.toSeed(code,"");
	List<String> words = Lists.newArrayList(WHITESPACE_SPLITTER.split(BOB_BIP39_MNEMONIC));
	byte[] entropy = mc.toEntropy(words);
        
        assertEquals(BOB_BIP39_RAW_ENTROPY, HEX.encode(entropy));
        assertEquals(BOB_BIP39_MNEMONIC, join(code, " "));
        assertEquals(BOB_BIP32_SEED, HEX.encode(seed));

        File workingDir = new File("target/test/output/bobWalletTest");

        BIP47AppKit w = createWallet("BTC", MainNetParams.get(), workingDir, BOB_BIP39_MNEMONIC);
        assertEquals(w.getMnemonicCode(), BOB_BIP39_MNEMONIC);

        assertEquals(BOB_PAYMENT_CODE_V1, w.getPaymentCode());

        w = createWallet("tBTC", TestNet3Params.get(),workingDir,BOB_BIP39_MNEMONIC);
        assertEquals(BOB_PAYMENT_CODE_V1, w.getPaymentCode());

        deleteFolder("target/test/output/bobWalletTest");
    }

    @Test
    public void notificationTransactionTest() throws Exception {
        super.setUp();
        // folders for alice and bob wallets
        String aliceDir = "target/test/output/notificationTransactionTest/alice";
        String bobDir = "target/test/output/notificationTransactionTest/bob";

        deleteFolder(aliceDir);deleteFolder(bobDir);

        BIP47AppKit Alice = createWallet("BTC", MainNetParams.get(), new File(aliceDir), ALICE_BIP39_MNEMONIC);
        BIP47AppKit Bob = createWallet("BTC", MainNetParams.get(), new File(bobDir), BOB_BIP39_MNEMONIC);

        // Alice sends a payment to Bob, she saves Bob's payment code.

        setWallet(Alice);
        assertTrue(Alice.getCoinsReceivedEventListener() != null);
        assertTrue(Alice.getAccount(0) != null);

        // both have issued 1 receive address
        assertEquals(1, Alice.getExternalAddressCount());
        assertEquals(1, Bob.getExternalAddressCount());
        assertEquals(0, Bob.getvWallet().getImportedKeys().size());

        sendMoneyToWallet(Alice.getvWallet(), AbstractBlockChain.NewBlockType.BEST_CHAIN, Coin.COIN, Alice.getCurrentAddress());

        SendRequest ntxRequest = Alice.makeNotificationTransaction(Bob.getPaymentCode());

        // Bob receives a NTX with Alice's payment code. Bob's wallet generates keys for Alice to use.
        Bob.savePaymentCode(Alice.getAccount(0).getPaymentCode()); // bob saves alice
        BIP47Channel channel = Bob.getBip47MetaForPaymentCode(Alice.getPaymentCode());
        assertEquals(10, channel.getIncomingAddresses().size()); // bob's # of incoming addresses
        assertEquals(10, Bob.getvWallet().getImportedKeys().size());

        //  - addresses used by Alice for sending to Bob
        assertEquals("141fi7TY3h936vRUKh1qfUZr8rSBuYbVBK", channel.getIncomingAddresses().get(0).getAddress());
        assertEquals("12u3Uued2fuko2nY4SoSFGCoGLCBUGPkk6", channel.getIncomingAddresses().get(1).getAddress());
        assertEquals("1FsBVhT5dQutGwaPePTYMe5qvYqqjxyftc", channel.getIncomingAddresses().get(2).getAddress());
        assertEquals("1CZAmrbKL6fJ7wUxb99aETwXhcGeG3CpeA", channel.getIncomingAddresses().get(3).getAddress());
        assertEquals("1KQvRShk6NqPfpr4Ehd53XUhpemBXtJPTL", channel.getIncomingAddresses().get(4).getAddress());
        assertEquals("1KsLV2F47JAe6f8RtwzfqhjVa8mZEnTM7t", channel.getIncomingAddresses().get(5).getAddress());
        assertEquals("1DdK9TknVwvBrJe7urqFmaxEtGF2TMWxzD", channel.getIncomingAddresses().get(6).getAddress());
        assertEquals("16DpovNuhQJH7JUSZQFLBQgQYS4QB9Wy8e", channel.getIncomingAddresses().get(7).getAddress());
        assertEquals("17qK2RPGZMDcci2BLQ6Ry2PDGJErrNojT5", channel.getIncomingAddresses().get(8).getAddress());
        assertEquals("1GxfdfP286uE24qLZ9YRP3EWk2urqXgC4s", channel.getIncomingAddresses().get(9).getAddress());

        assertEquals(SHARED_SECRET_0, HEX.encode(BIP47Util.getReceiveAddress(Bob, ALICE_PAYMENT_CODE_V1, 0).getSharedSecret().ECDHSecretAsBytes()));
        assertEquals(SHARED_SECRET_1, HEX.encode(BIP47Util.getReceiveAddress(Bob, ALICE_PAYMENT_CODE_V1, 1).getSharedSecret().ECDHSecretAsBytes()));
        assertEquals(SHARED_SECRET_2, HEX.encode(BIP47Util.getReceiveAddress(Bob, ALICE_PAYMENT_CODE_V1, 2).getSharedSecret().ECDHSecretAsBytes()));
        assertEquals(SHARED_SECRET_3, HEX.encode(BIP47Util.getReceiveAddress(Bob, ALICE_PAYMENT_CODE_V1, 3).getSharedSecret().ECDHSecretAsBytes()));
        assertEquals(SHARED_SECRET_4, HEX.encode(BIP47Util.getReceiveAddress(Bob, ALICE_PAYMENT_CODE_V1, 4).getSharedSecret().ECDHSecretAsBytes()));
        assertEquals(SHARED_SECRET_5, HEX.encode(BIP47Util.getReceiveAddress(Bob, ALICE_PAYMENT_CODE_V1, 5).getSharedSecret().ECDHSecretAsBytes()));
        assertEquals(SHARED_SECRET_6, HEX.encode(BIP47Util.getReceiveAddress(Bob, ALICE_PAYMENT_CODE_V1, 6).getSharedSecret().ECDHSecretAsBytes()));
        assertEquals(SHARED_SECRET_7, HEX.encode(BIP47Util.getReceiveAddress(Bob, ALICE_PAYMENT_CODE_V1, 7).getSharedSecret().ECDHSecretAsBytes()));
        assertEquals(SHARED_SECRET_8, HEX.encode(BIP47Util.getReceiveAddress(Bob, ALICE_PAYMENT_CODE_V1, 8).getSharedSecret().ECDHSecretAsBytes()));
        assertEquals(SHARED_SECRET_9, HEX.encode(BIP47Util.getReceiveAddress(Bob, ALICE_PAYMENT_CODE_V1, 9).getSharedSecret().ECDHSecretAsBytes()));

        deleteFolder(aliceDir);deleteFolder(bobDir);
    }

    @Test
    public void testPeerGroupStart() throws Exception{
        deleteFolder("target/test/output/testPeerGroupStart");
        File workingDir = new File("target/test/output/testPeerGroupStart");
        BIP47AppKit w = new BIP47AppKit("tBTC", TestNet3Params.get(), workingDir, null);
        assertFalse(w.isStarted());
        assertFalse(w.isStarted());
        w.startBlockchainDownload();
        assertTrue(w.isStarted());
        w.startBlockchainDownload();
        assertTrue(w.isStarted());
        w.stop();
        assertFalse(w.isStarted());
        w.startBlockchainDownload();
        assertTrue(w.isStarted());
        deleteFolder("target/test/output/testPeerGroupStart");
    }

    @Test
    public void testIsValidAddress() throws Exception {
        deleteFolder("target/test/output/testIsValidAddress");
        File workingDir = new File("target/test/output/testIsValidAddress");

	BIP47AppKit btc = new BIP47AppKit("BTC", MainNetParams.get(), workingDir, null);
        BIP47AppKit tbtc = new BIP47AppKit("tBTC", TestNet3Params.get(), workingDir, null);

        assertFalse(tbtc.isValidAddress(null));
        assertFalse(tbtc.isValidAddress(""));

        // bip47 or bch should work by default as fallbacks
        assertTrue(tbtc.isValidAddress(ALICE_PAYMENT_CODE_V1));
        assertFalse(tbtc.isValidAddress("bitcoincash:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a"));

        // BTC shouldn't work on a tBTC wallet
        assertTrue(tbtc.isValidAddress("2NBMEXqk5SMdHsEeATAByw7DqZ8jjLwf1MY")); // tBTC
        assertFalse(tbtc.isValidAddress("3CMXDwnQfyGmTkw5U58f2ffoVYroMBWrJe")); //BTC

        // BTC should work
        assertTrue(btc.isValidAddress("3CMXDwnQfyGmTkw5U58f2ffoVYroMBWrJe"));
        deleteFolder("target/test/output/testIsValidAddress");
    }

    /* Test that a wallet restored from seed is persistent */
    @Test
    public void testMnemonicWordsPersistence() throws Exception{
        // create a fresh new wallet
        deleteFolder("target/test/output/testMnemonicWordsPersistence");
        File workingDir = new File("target/test/output/testMnemonicWordsPersistence");

        DeterministicSeed davesSeed = new DeterministicSeed(new SecureRandom(), 256, "", System.currentTimeMillis() / 1000);
        assertFalse(workingDir.exists()); //delete previous wallets created by this test
        //create Dave's wallet and save it
        BIP47AppKit Dave = new BIP47AppKit("BTC", MainNetParams.get(), workingDir, davesSeed);
        String davesMnemonic = Dave.getMnemonicCode();
        String davesPaymentCode = Dave.getPaymentCode();
        assertTrue(workingDir.exists());
        Dave.stop();
        Dave.closeBlockStore();
        // the same directory/coin will have the same seed as saved before.
        BIP47AppKit DaveReload = new BIP47AppKit("BTC", MainNetParams.get(), workingDir, null);
        assertEquals(DaveReload.getMnemonicCode(), davesMnemonic);
        assertEquals(DaveReload.getPaymentCode(), davesPaymentCode);
        deleteFolder("target/test/output/testMnemonicWordsPersistence");
    }
}
