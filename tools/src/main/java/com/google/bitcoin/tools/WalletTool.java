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
import com.google.bitcoin.discovery.IrcDiscovery;
import com.google.bitcoin.discovery.PeerDiscovery;
import com.google.bitcoin.store.BlockStoreException;
import com.google.bitcoin.store.BoundedOverheadBlockStore;
import com.google.bitcoin.utils.BriefLogFormatter;
import joptsimple.OptionParser;
import joptsimple.OptionSet;
import joptsimple.OptionSpec;
import joptsimple.util.DateConverter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.spongycastle.util.encoders.Hex;

import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Date;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
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
            "  --net=PROD/TEST      Which network to connect to, defaults to PROD.\n" +
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
            "                       If --privkey is specified, use as a hex/base58 encoded private key.\n" +
            "                       Don't specify --pubkey in that case, it will be derived automatically.\n" +
            "                       If --pubkey is specified, use as a hex/base58 encoded non-compressed public key.\n" +
            "  --action=DELETE_KEY  Removes the key specified by --pubkey or --addr from the wallet.\n" +
            "  --action=SYNC        Sync the wallet with the latest block chain (download new transactions).\n" +
            "                       If the chain file does not exist this will RESET the wallet.\n" +
            "  --action=RESET       Deletes all transactions from the wallet, for if you want to replay the chain.\n" +
            "  --action=SEND        Creates a transaction with the given --output from this wallet and broadcasts.\n" +
            "                       You can repeat --output=address:value multiple times, eg:\n" +
            "                         --output=1GthXFQMktFLWdh5EPNGqbq3H6WdG8zsWj:1.245\n" +

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
    private static PeerDiscovery discovery;

    public static class Condition {
        public enum Type {
            // Less than, greater than, less than or equal, greater than or equal.
            EQUAL, LT, GT, LTE, GTE
        }
        Type type;
        String value;

        public Condition(String from) {
            if (from.length() < 2) throw new RuntimeException("Condition string too short: " + from);

            if (from.startsWith("<=")) type = Type.LTE;
            else if (from.startsWith(">=")) type = Type.GTE;
            else if (from.startsWith("<")) type = Type.LT;
            else if (from.startsWith("=")) type = Type.EQUAL;
            else if (from.startsWith(">")) type = Type.GT;
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
            try {
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
            } catch (NumberFormatException e) {
                System.err.println("Could not parse value from condition string: " + value);
                System.exit(1);
                return false;
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
        SEND
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
        OptionSpec<String> outputFlag = parser.accepts("output").withRequiredArg();
        parser.accepts("value").withRequiredArg();
        conditionFlag = parser.accepts("condition").withRequiredArg();
        options = parser.parse(args);
        
        if (args.length == 0 || options.has("help") || options.nonOptionArguments().size() > 0) {
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
                discovery = new DnsDiscovery(params);
                break;
            case TEST: 
                params = NetworkParameters.testNet();
                chainFileName = new File("testnet.chain");
                discovery = new IrcDiscovery("#bitcoinTEST");
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
            if (!wallet.getParams().equals(params)) {
                System.err.println("Wallet does not match requested network parameters: " +
                        wallet.getParams().getId() + " vs " + params.getId());
                return;
            }
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
            case SEND:
                if (!options.has(outputFlag)) {
                    System.err.println("You must specify at least one --output=addr:value.");
                    return;
                }
                send(outputFlag.values(options));
                break;
        }

        if (!wallet.isConsistent()) {
            System.err.println("************** WALLET IS INCONSISTENT *****************");
            return;
        }
        
        saveWallet(walletFile);

        if (options.has(waitForFlag)) {
            wait(waitForFlag.value(options));
            if (!wallet.isConsistent()) {
                System.err.println("************** WALLET IS INCONSISTENT *****************");
                return;
            }
            saveWallet(walletFile);
        } else {
            shutdown();
        }
    }

    private static void send(List<String> outputs) {
        try {
            // Convert the input strings to outputs.
            Transaction t = new Transaction(params);
            for (String spec : outputs) {
                String[] parts = spec.split(":");
                if (parts.length != 2) {
                    System.err.println("Malformed output specification, must have two parts separated by :");
                    return;
                }
                try {
                    Address addr = new Address(params, parts[0]);
                    BigInteger value = Utils.toNanoCoins(parts[1]);
                    t.addOutput(value, addr);
                } catch (WrongNetworkException e) {
                    System.err.println("Malformed output specification, address is for a different network: " + parts[0]);
                    return;
                } catch (AddressFormatException e) {
                    System.err.println("Malformed output specification, could not parse as address: " + parts[0]);
                    return;
                } catch (NumberFormatException e) {
                    System.err.println("Malformed output specification, could not parse as value: " + parts[1]);
                }
            }
            if (!wallet.completeTx(t)) {
                System.err.println("Insufficient funds: have " + wallet.getBalance());
                return;
            }
            setup();
            peers.start();
            peers.broadcastTransaction(t).get();  // The .get() is so we wait until the broadcast has completed.
            wallet.commitTx(t);
            System.out.println(t.getHashAsString());
        } catch (BlockStoreException e) {
            throw new RuntimeException(e);
        } catch (VerificationException e) {
            // Cannot happen, created transaction ourselves.
            throw new RuntimeException(e);
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        } catch (ExecutionException e) {
            throw new RuntimeException(e);
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
    }

    private static void reset() {
        // Delete the transactions and save. In future, reset the chain head pointer.
        wallet.clearTransactions(0);
        saveWallet(walletFile);
    }

    // Sets up all objects needed for network communication but does not bring up the peers.
    private static void setup() throws BlockStoreException {
        if (store != null) return;  // Already done.
        // Will create a fresh chain if one doesn't exist or there is an issue with this one.
        if (!chainFileName.exists() && wallet.getTransactions(true, true).size() > 0) {
            // No chain, so reset the wallet as we will be downloading from scratch.
            System.out.println("Chain file is missing so clearing transactions from the wallet.");
            reset();
        }
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
            peers.addPeerDiscovery(discovery);
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
            if (peers == null) return;  // setup() never called so nothing to do.
            peers.stop();
            saveWallet(walletFile);
            store.close();
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
        try {
            // This will save the new state of the wallet to a temp file then rename, in case anything goes wrong.
            wallet.saveToFile(walletFile);
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
            BigInteger decode = Utils.parseAsHexOrBase58(data);
            if (decode == null) {
                System.err.println("Could not understand --privkey as either hex or base58: " + data);
                return;
            }
            key = new ECKey(decode);
            if (options.has("pubkey")) {
                // Give the user a hint.
                System.out.println("You don't have to specify --pubkey when a private key is supplied.");
            }
            key.setCreationTimeSeconds(creationTimeSeconds);
        } else if (options.has("pubkey")) {
            BigInteger decode = Utils.parseAsHexOrBase58((String) options.valueOf("pubkey"));
            byte[] pubkey = Utils.bigIntegerToBytes(decode, ECKey.PUBLIC_KEY_LENGTH);
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
