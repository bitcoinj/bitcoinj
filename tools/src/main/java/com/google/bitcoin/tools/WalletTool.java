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
import com.google.bitcoin.utils.BriefLogFormatter;
import joptsimple.OptionParser;
import joptsimple.OptionSet;
import joptsimple.OptionSpec;
import joptsimple.util.DateConverter;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Date;
import java.util.concurrent.CountDownLatch;
import java.util.logging.Level;
import java.util.logging.LogManager;

/**
 * A command line tool for manipulating wallets and working with Bitcoin.<p>
 */
public class WalletTool {
    private static final Logger log = LoggerFactory.getLogger(WalletTool.class);

    private static final String HELP_TEXT =
            "WalletTool: print and manipulate wallets\n\n" +

            "Usage:\n" +
            ">>> GENERAL OPTIONS\n" +
            "  --debuglog           Enables logging from the core library.\n" +
            "  --wallet=<file>      Specifies what wallet file to load and save.\n" +
            "  --chain=<file>       Specifies the name of the file that stores the block chain.\n" +
            "  --force              Overrides any safety checks on the requested action.\n" +
            "  --date               Provide a date in form YYYY/MM/DD to any action that requires one.\n" +
            "  --peer=1.2.3.4       Use the given IP address for connections instead of peer discovery.\n" +
            "  --condition=...      Allows you to specify a numeric condition for other commands. The format is\n" +
            "                       one of the following operators = < > <= >= immediately followed by a number.\n" +
            "                       For example --condition=\">5.10\" or --condition=\"<=1\"\n" +

            "\n>>> ACTIONS\n" +
            "  --action=DUMP        Prints the given wallet in textual form to stdout.\n" +
            "  --action=CREATE      Makes a new wallet in the file specified by --wallet.\n" +
            "                       Will complain and require --force if the wallet already exists.\n" +
            "  --action=ADD_KEY     Adds a new key to the wallet, either specified or freshly generated.\n" +
            "                       If --date is specified, that's the creation date.\n" +
            "                       If --privkey is specified, use as a hex encoded private key.\n" +
            "                       Don't specify --pubkey in that case, it will be derived automatically.\n" +
            "                       If --pubkey is specified, use as a hex encoded non-compressed public key.\n" +
            "  --action=DELETE_KEY  Removes the key specified by --pubkey or --addr from the wallet.\n" +
            "  --action=SYNC        Sync the wallet with the latest block chain (download new transactions).\n" +
            "                       If the chain file does not exist this will RESET the wallet.\n" +
            "  --action=RESET       Deletes all transactions from the wallet, for if you want to replay the chain.\n" +

            "\n>>> WAITING\n" +
            "You can wait for the condition specified by the --waitfor flag to become true. Transactions and new\n" +
            "blocks will be processed during this time. When the waited for condition is met, the tx/block hash\n" +
            "will be printed. Waiting occurs after the --action is performed, if any is specified.\n\n" +

            "  --waitfor=EVER       Never quit.\n" +
            "  --waitfor=WALLET_TX  Any transaction that sends coins to or from the wallet.\n" +
            "  --waitfor=BLOCK      A new block that builds on the best chain.\n" +
            "  --waitfor=BALANCE    Waits until the wallets balance meets the --condition.\n";

    private static OptionSpec<String> walletFileName;
    private static OptionSpec<ActionEnum> actionFlag;
    private static OptionSpec<NetworkEnum> netFlag;
    private static OptionSpec<Date> dateFlag;
    private static OptionSpec<WaitForEnum> waitForFlag;
    private static OptionSpec<String> conditionFlag;

    private static NetworkParameters params;
    private static File walletFile;
    private static OptionSet options;
    private static java.util.logging.Logger logger;
    private static BoundedOverheadBlockStore store;
    private static BlockChain chain;
    private static PeerGroup peers;
    private static Wallet wallet;
    private static File chainFileName;

    public static class Condition {
        public enum Type {
            // Less than, greater than, less than or equal, greater than or equal.
            EQUAL, LT, GT, LTE, GTE
        }
        Type type;
        String value;

        public Condition(String from) {
            if (from.length() < 2) throw new RuntimeException("Condition string too short: " + from);

            if (from.startsWith("<")) type = Type.LT;
            else if (from.startsWith("=")) type = Type.EQUAL;
            else if (from.startsWith(">")) type = Type.GT;
            else if (from.startsWith("<=")) type = Type.LTE;
            else if (from.startsWith(">=")) type = Type.GTE;
            else throw new RuntimeException("Unknown operator in condition: " + from);

            String s;
            switch (type) {
                case LT:
                case GT:
                case EQUAL:
                    s = from.substring(1);
                    break;
                case LTE:
                case GTE:
                    s = from.substring(2);
                    break;
                default:
                    throw new RuntimeException("Unreachable");
            }
            value = s;
        }

        public boolean matchBitcoins(BigInteger comparison) {
            BigInteger units = Utils.toNanoCoins(value);
            switch (type) {
                case LT: return comparison.compareTo(units) < 0;
                case GT: return comparison.compareTo(units) > 0;
                case EQUAL: return comparison.compareTo(units) == 0;
                case LTE: return comparison.compareTo(units) <= 0;
                case GTE: return comparison.compareTo(units) >= 0;
                default:
                    throw new RuntimeException("Unreachable");
            }
        }
    }

    private static Condition condition;

    public enum ActionEnum {
        NONE,
        DUMP,
        CREATE,
        ADD_KEY,
        DELETE_KEY,
        SYNC,
        RESET,
    };

    public enum WaitForEnum {
        EVER,
        WALLET_TX,
        BLOCK,
        BALANCE
    };
    
    public enum NetworkEnum {
        PROD,
        TEST
    }

    public static void main(String[] args) throws Exception {
        OptionParser parser = new OptionParser();
        parser.accepts("help");
        parser.accepts("force");
        parser.accepts("debuglog");
        walletFileName = parser.accepts("wallet")
                .withRequiredArg()
                .defaultsTo("wallet");
        actionFlag = parser.accepts("action")
                .withRequiredArg()
                .ofType(ActionEnum.class);
        netFlag = parser.accepts("net")
                .withOptionalArg()
                .ofType(NetworkEnum.class)
                .defaultsTo(NetworkEnum.PROD);
        dateFlag = parser.accepts("date")
                .withRequiredArg()
                .ofType(Date.class)
                .withValuesConvertedBy(DateConverter.datePattern("yyyy/MM/dd"));
        waitForFlag = parser.accepts("waitfor")
                .withRequiredArg()
                .ofType(WaitForEnum.class);
        OptionSpec<String> chainFlag = parser.accepts("chain").withRequiredArg();
        // For addkey/delkey.
        parser.accepts("pubkey").withRequiredArg();
        parser.accepts("privkey").withRequiredArg();
        parser.accepts("addr").withRequiredArg();
        parser.accepts("peer").withRequiredArg();
        conditionFlag = parser.accepts("condition").withRequiredArg();
        options = parser.parse(args);
        
        if (args.length == 0 || options.hasArgument("help") || options.nonOptionArguments().size() > 0) {
            System.out.println(HELP_TEXT);
            return;
        }
        
        if (options.has("debuglog")) {
            BriefLogFormatter.init();
            log.info("Starting up ...");
        } else {
            // Disable logspam unless there is a flag.
            logger = LogManager.getLogManager().getLogger("");
            logger.setLevel(Level.SEVERE);
        }

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

        if (options.has("condition")) {
            condition = new Condition(conditionFlag.value(options));
        }

        ActionEnum action = ActionEnum.NONE;
        if (options.has(actionFlag))
            action = actionFlag.value(options);
        walletFile = new File(walletFileName.value(options));
        if (action == ActionEnum.CREATE) {
            createWallet(options, params, walletFile);
            return;  // We're done.
        }
        if (!walletFile.exists()) {
            System.err.println("Specified wallet file " + walletFile + " does not exist. Try --action=CREATE");
            return;
        }
        try {
            wallet = Wallet.loadFromFile(walletFile);
        } catch (Exception e) {
            System.err.println("Failed to load wallet '" + walletFile + "': " + e.getMessage());
            e.printStackTrace();
            return;
        }

        // What should we do?
        switch (action) {
            case DUMP: dumpWallet(); break;
            case ADD_KEY: addKey(); break;
            case DELETE_KEY: deleteKey(); break;
            case RESET: reset(); break;
            case SYNC: syncChain(); break;
        }
        saveWallet(walletFile);

        if (options.has(waitForFlag)) {
            wait(waitForFlag.value(options));
            saveWallet(walletFile);
        }
    }

    private static void wait(WaitForEnum waitFor) throws BlockStoreException {
        final CountDownLatch latch = new CountDownLatch(1);
        setup();
        switch (waitFor) {
            case EVER:
                break;

            case WALLET_TX:
                wallet.addEventListener(new AbstractWalletEventListener() {
                    private void handleTx(Transaction tx) {
                        System.out.println(tx.getHashAsString());
                        latch.countDown();  // Wake up main thread.
                    }

                    @Override
                    public void onCoinsReceived(Wallet wallet, Transaction tx, BigInteger prevBalance, BigInteger newBalance) {
                        // Runs in a peer thread.
                        super.onCoinsReceived(wallet, tx, prevBalance, newBalance);
                        handleTx(tx);
                    }

                    @Override
                    public void onCoinsSent(Wallet wallet, Transaction tx, BigInteger prevBalance,
                                            BigInteger newBalance) {
                        // Runs in a peer thread.
                        super.onCoinsSent(wallet, tx, prevBalance, newBalance);
                        handleTx(tx);
                    }
                });
                break;

            case BLOCK:
                peers.addEventListener(new AbstractPeerEventListener() {
                    @Override
                    public void onBlocksDownloaded(Peer peer, Block block, int blocksLeft) {
                        super.onBlocksDownloaded(peer, block, blocksLeft);
                        // Check if we already ran. This can happen if a block being received triggers download of more
                        // blocks, or if we receive another block whilst the peer group is shutting down.
                        if (latch.getCount() == 0) return;
                        System.out.println(block.getHashAsString());
                        latch.countDown();
                    }
                });
                break;

            case BALANCE:
                // Check if the balance already meets the given condition.
                if (condition.matchBitcoins(wallet.getBalance(Wallet.BalanceType.ESTIMATED))) {
                    latch.countDown();
                    break;
                }
                wallet.addEventListener(new AbstractWalletEventListener() {
                    @Override
                    public void onChange() {
                        super.onChange();
                        saveWallet(walletFile);
                        BigInteger balance = wallet.getBalance(Wallet.BalanceType.ESTIMATED);
                        if (condition.matchBitcoins(balance)) {
                            System.out.println(Utils.bitcoinValueToFriendlyString(balance));
                            latch.countDown();
                        }
                    }
                });
                break;

        }
        peers.start();
        try {
            latch.await();
        } catch (InterruptedException e) {
        }
        shutdown();
    }

    private static void reset() {
        // Delete the transactions and save. In future, reset the chain head pointer.
        wallet.clearTransactions(0);
        saveWallet(walletFile);
    }

    // Sets up all objects needed for network communication but does not bring up the peers.
    private static void setup() throws BlockStoreException {
        // Will create a fresh chain if one doesn't exist or there is an issue with this one.
        store = new BoundedOverheadBlockStore(params, chainFileName);
        chain = new BlockChain(params, wallet, store);
        wallet.addEventListener(new AbstractWalletEventListener() {
            @Override
            public void onChange() {
                saveWallet(walletFile);
            }
        });
        peers = new PeerGroup(params, chain);
        peers.setUserAgent("WalletTool", "1.0");
        peers.addWallet(wallet);
        peers.setFastCatchupTimeSecs(wallet.getEarliestKeyCreationTime());
        if (options.has("peer")) {
            String peer = (String) options.valueOf("peer");
            try {
                peers.addAddress(new PeerAddress(InetAddress.getByName(peer), params.port));
            } catch (UnknownHostException e) {
                System.err.println("Could not understand peer domain name/IP address: " + peer + ": " + e.getMessage());
                System.exit(1);
            }
        } else {
            peers.addPeerDiscovery(new DnsDiscovery(params));
        }
    }

    private static void syncChain() {
        try {
            setup();
            int startTransactions = wallet.getTransactions(true, true).size();
            DownloadListener listener = new DownloadListener();
            peers.start();
            peers.startBlockChainDownload(listener);
            try {
                listener.await();
            } catch (InterruptedException e) {
                System.err.println("Chain download interrupted, quitting ...");
                System.exit(1);
            }
            shutdown();
            int endTransactions = wallet.getTransactions(true, true).size();
            if (endTransactions > startTransactions) {
                System.out.println("Synced " + (endTransactions - startTransactions) + " transactions.");
            }
        } catch (BlockStoreException e) {
            System.err.println("Error reading block chain file " + chainFileName + ": " + e.getMessage());
            e.printStackTrace();
        }
    }

    private static void shutdown() {
        try {
            peers.stop();
            store.close();
            saveWallet(walletFile);
        } catch (BlockStoreException e) {
            throw new RuntimeException(e);
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

    private static void saveWallet(File walletFile) {
        // Save the new state of the wallet to a temp file then rename, in case anything goes wrong.
        File tmp;
        try {
            // Create tmp in same directory as wallet to ensure we create on the same drive/volume.
            tmp = File.createTempFile("wallet", null, walletFile.getParentFile());
            tmp.deleteOnExit();
            wallet.saveToFile(tmp);
            if (!tmp.renameTo(walletFile)) {
                throw new IOException("Failed to rename wallet");
            }
        } catch (IOException e) {
            System.err.println("Failed to save wallet! Old wallet should be left untouched.");
            e.printStackTrace();
            System.exit(1);
        }
    }

    private static void addKey() {
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

    private static void deleteKey() {
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
    
    private static void dumpWallet() {
        System.out.println(wallet.toString());
    }
}
