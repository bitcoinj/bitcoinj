/*
 * Copyright 2012 Google Inc.
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

package com.google.bitcoin.tools;

import com.google.bitcoin.core.*;
import com.google.bitcoin.discovery.DnsDiscovery;
import com.google.bitcoin.store.BlockStoreException;
import com.google.bitcoin.store.BoundedOverheadBlockStore;
import joptsimple.OptionParser;
import joptsimple.OptionSet;
import joptsimple.OptionSpec;
import org.bouncycastle.util.encoders.Hex;

import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Date;
import java.util.logging.Level;
import java.util.logging.LogManager;

import static joptsimple.util.DateConverter.datePattern;

/**
 * A command line tool for manipulating wallets and working with Bitcoin.<p>
 * 
 */
public class WalletTool {
    private static final String HELP_TEXT =
            "WalletTool: print and manipulate wallets\n\n" +

            "Usage:\n" +
            ">>> GENERAL OPTIONS\n" +
            "  --wallet=<file>      Specifies what wallet file to load and save.\n" +
            "  --chain=<file>       Specifies the name of the file that stores the block chain.\n" +
            "  --force              Overrides any safety checks on the requested action.\n" +
            "  --date               Provide a date in form YYYY/MM/DD to any action that requires one.\n" +

            "\n>>> ACTIONS\n" +
            "  --action=DUMP        Prints the given wallet in textual form to stdout.\n" +
            "  --action=CREATE      Makes a new wallet in the file specified by --wallet.\n" +
            "                       Will complain and require --force if the wallet already exists.\n" +
            "  --action=ADD_KEY     Adds a new key to the wallet, either specified or freshly generated.\n" +
            "                       If --date is specified, that's the creation date.\n" +
            "                       If --privkey is specified, use as a hex encoded private key. " +
                                   "Don't specify --pubkey in that case, it will be derived automatically.\n" +
            "                       If --pubkey is specified, use as a hex encoded non-compressed public key.\n" +
            "  --action=DELETE_KEY  Removes the key specified by --pubkey or --addr from the wallet.\n" +
            "  --action=SYNC        Sync the wallet with the latest block chain (download new transactions).\n" +
            "                       If the chain file does not exist this will RESET the wallet.\n" +
            "  --action=RESET       Deletes all transactions from the wallet, for if you want to replay the chain.\n";

    private static OptionSpec<String> walletFileName;
    private static OptionSpec<ActionEnum> actionFlag;
    private static OptionSpec<NetworkEnum> netFlag;
    private static OptionSpec<Date> dateFlag;
    private static NetworkParameters params;
    private static File walletFile;

    public enum ActionEnum {
        DUMP,
        CREATE,
        ADD_KEY,
        DELETE_KEY,
        SYNC
    };
    
    public enum NetworkEnum {
        PROD,
        TEST
    }

    public static void main(String[] args) throws Exception {
        // Disable logspam.
        LogManager.getLogManager().getLogger("").setLevel(Level.SEVERE);

        OptionParser parser = new OptionParser();
        parser.accepts("help");
        parser.accepts("force");
        walletFileName = parser.accepts("wallet")
                .withRequiredArg()
                .defaultsTo("wallet");
        actionFlag = parser.accepts("action")
                .withRequiredArg()
                .ofType(ActionEnum.class)
                .defaultsTo(ActionEnum.DUMP);
        netFlag = parser.accepts("net")
                .withOptionalArg()
                .ofType(NetworkEnum.class)
                .defaultsTo(NetworkEnum.PROD);
        dateFlag = parser.accepts("date")
                .withRequiredArg()
                .ofType(Date.class)
                .withValuesConvertedBy(datePattern("yyyy/MM/dd"));
        OptionSpec<String> chainFlag = parser.accepts("chain").withRequiredArg();
        // For addkey/delkey.
        parser.accepts("pubkey").withRequiredArg();
        parser.accepts("privkey").withRequiredArg();
        parser.accepts("addr").withRequiredArg();
        OptionSet options = parser.parse(args);
        
        if (args.length == 0 || options.hasArgument("help") || options.nonOptionArguments().size() > 0) {
            System.out.println(HELP_TEXT);
            return;
        }

        File chainFileName;
        switch (netFlag.value(options)) {
            case PROD: 
                params = NetworkParameters.prodNet();
                chainFileName = new File("prodnet.chain");
                break;
            case TEST: 
                params = NetworkParameters.testNet();
                chainFileName = new File("testnet.chain");
                break;
            default:
                throw new RuntimeException("Unreachable.");
        }

        // Allow the user to override the name of the chain used.
        if (options.has(chainFlag)) {
            chainFileName = new File(chainFlag.value(options));
        }

        ActionEnum action = actionFlag.value(options);
        walletFile = new File(walletFileName.value(options));
        if (action == ActionEnum.CREATE) {
            createWallet(options, params, walletFile);
            return;  // We're done.
        }
        if (!walletFile.exists()) {
            System.err.println("Specified wallet file " + walletFile + " does not exist. Try --action=CREATE");
            return;
        }
        Wallet wallet;
        try {
            wallet = Wallet.loadFromFile(walletFile);
        } catch (Exception e) {
            System.err.println("Failed to load wallet '" + walletFile + "': " + e.getMessage());
            e.printStackTrace();
            return;
        }

        // What should we do?
        switch (action) {
            case DUMP: dumpWallet(wallet); break;
            case ADD_KEY: addKey(wallet, options); break;
            case DELETE_KEY: deleteKey(wallet, options); break;
            case SYNC: syncChain(wallet, chainFileName); break;
        }
        saveWallet(walletFile, wallet);
    }

    private static void syncChain(final Wallet wallet, File chainFileName) {
        try {
            // Will create a fresh chain if one doesn't exist or there is an issue with this one.
            System.out.println("Connecting ..." );
            final BoundedOverheadBlockStore store = new BoundedOverheadBlockStore(params, chainFileName);
            final BlockChain chain = new BlockChain(params, wallet, store);
            final PeerGroup peers = new PeerGroup(params, chain);
            peers.setUserAgent("WalletTool", "1.0");
            peers.addWallet(wallet);
            peers.addPeerDiscovery(new DnsDiscovery(params));
            peers.setFastCatchupTimeSecs(wallet.getEarliestKeyCreationTime());
            
            wallet.addEventListener(new AbstractWalletEventListener() {
                @Override
                public void onChange() {
                    saveWallet(walletFile, wallet);
                }
            });
            
            final int startTransactions = wallet.getTransactions(true, true).size();
            
            peers.start();
            peers.startBlockChainDownload(new DownloadListener() {
                @Override
                protected void doneDownload() {
                    super.doneDownload();
                    peers.stop();
                    int endTransactions = wallet.getTransactions(true, true).size();
                    if (endTransactions > startTransactions) {
                        System.out.println("Synced " + (endTransactions - startTransactions) + " transactions.");
                    }
                }
            });
        } catch (BlockStoreException e) {
            System.err.println("Error reading block chain file " + chainFileName + ": " + e.getMessage());
            e.printStackTrace();
        }
    }

    private static void createWallet(OptionSet options, NetworkParameters params, File walletFile) throws IOException {
        if (walletFile.exists() && !options.has("force")) {
            System.err.println("Wallet creation requested but " + walletFile + " already exists, use --force");
            return;
        }
        new Wallet(params).saveToFile(walletFile);
        // Don't add any keys by default.
        return;
    }

    private static void saveWallet(File walletFile, Wallet wallet) {
        // Save the new state of the wallet to a temp file then rename, in case anything goes wrong.
        File tmp;
        try {
            // Create tmp in same directory as wallet to ensure we create on the same drive/volume.
            tmp = File.createTempFile("wallet", null, walletFile.getParentFile());
            tmp.deleteOnExit();
            wallet.saveToFile(tmp);
            tmp.renameTo(walletFile);
        } catch (IOException e) {
            System.err.println("Failed to save wallet! Old wallet should be left untouched.");
            e.printStackTrace();
            System.exit(1);
        }
    }

    private static void addKey(Wallet wallet, OptionSet options) {
        ECKey key;
        long creationTimeSeconds = 0;
        if (options.has(dateFlag)) {
            creationTimeSeconds = dateFlag.value(options).getTime() / 1000;
        }
        if (options.has("privkey")) {
            String data = (String) options.valueOf("privkey");
            key = new ECKey(new BigInteger(1, Hex.decode(data)));
            if (options.has("pubkey")) {
                // Give the user a hint.
                System.out.println("You don't have to specify --pubkey when a private key is supplied.");
            }
            key.setCreationTimeSeconds(creationTimeSeconds);
        } else if (options.has("pubkey")) {
            byte[] pubkey = Hex.decode((String)options.valueOf("pubkey"));
            key = new ECKey(null, pubkey);
            key.setCreationTimeSeconds(creationTimeSeconds);
        } else {
            // Freshly generated key.
            key = new ECKey();
        }
        if (wallet.findKeyFromPubKey(key.getPubKey()) != null) {
            System.err.println("That key already exists in this wallet.");
            return;
        }
        wallet.addKey(key);
        System.out.println("addr:" + key.toAddress(params) + " " + key);
    }

    private static void deleteKey(Wallet wallet, OptionSet options) {
        String pubkey = (String) options.valueOf("pubkey");
        String addr = (String) options.valueOf("addr");
        if (pubkey == null && addr == null) {
            System.err.println("One of --pubkey or --addr must be specified.");
            return;
        }
        ECKey key = null;
        if (pubkey != null) {
            key = wallet.findKeyFromPubKey(Hex.decode(pubkey));
        } else if (addr != null) {
            try {
                Address address = new Address(wallet.getParams(), addr);
                key = wallet.findKeyFromPubHash(address.getHash160());
            } catch (AddressFormatException e) {
                System.err.println(addr + " does not parse as a Bitcoin address of the right network parameters.");
                return;
            }            
        }
        if (key == null) {
            System.err.println("Wallet does not seem to contain that key.");
            return;
        }
        wallet.keychain.remove(key);
    }    
    
    private static void dumpWallet(Wallet wallet) {
        System.out.println(wallet.toString());
    }
}
