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
import com.google.bitcoin.crypto.KeyCrypterException;
import com.google.bitcoin.net.discovery.DnsDiscovery;
import com.google.bitcoin.net.discovery.PeerDiscovery;
import com.google.bitcoin.params.MainNetParams;
import com.google.bitcoin.params.RegTestParams;
import com.google.bitcoin.params.TestNet3Params;
import com.google.bitcoin.protocols.payments.PaymentRequestException;
import com.google.bitcoin.protocols.payments.PaymentSession;
import com.google.bitcoin.store.*;
import com.google.bitcoin.uri.BitcoinURI;
import com.google.bitcoin.uri.BitcoinURIParseException;
import com.google.bitcoin.utils.BriefLogFormatter;
import com.google.common.base.Charsets;
import com.google.common.collect.ImmutableList;
import com.google.common.io.Resources;
import com.google.common.util.concurrent.ListenableFuture;
import joptsimple.OptionParser;
import joptsimple.OptionSet;
import joptsimple.OptionSpec;
import joptsimple.util.DateConverter;
import org.bitcoinj.wallet.Protos;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.spongycastle.util.encoders.Hex;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.text.ParseException;
import java.util.Date;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.LogManager;

/**
 * A command line tool for manipulating wallets and working with Bitcoin.
 */
public class WalletTool {
    private static final Logger log = LoggerFactory.getLogger(WalletTool.class);

    private static OptionSpec<Date> dateFlag;
    private static OptionSpec<Integer> unixtimeFlag;

    private static NetworkParameters params;
    private static File walletFile;
    private static OptionSet options;
    private static BlockStore store;
    private static AbstractBlockChain chain;
    private static PeerGroup peers;
    private static Wallet wallet;
    private static File chainFileName;
    private static PeerDiscovery discovery;
    private static ValidationMode mode;
    private static String password;
    private static org.bitcoin.protocols.payments.Protos.PaymentRequest paymentRequest;

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
        DUMP,
        RAW_DUMP,
        CREATE,
        ADD_KEY,
        ADD_ADDR,
        DELETE_KEY,
        SYNC,
        RESET,
        SEND
    }

    public enum WaitForEnum {
        EVER,
        WALLET_TX,
        BLOCK,
        BALANCE
    }
    
    public enum NetworkEnum {
        PROD,
        TEST,
        REGTEST
    }

    public enum ValidationMode {
        FULL,
        SPV
    }

    public static void main(String[] args) throws Exception {
        OptionParser parser = new OptionParser();
        parser.accepts("help");
        parser.accepts("force");
        parser.accepts("debuglog");
        OptionSpec<String> walletFileName = parser.accepts("wallet")
                .withRequiredArg()
                .defaultsTo("wallet");
        OptionSpec<NetworkEnum> netFlag = parser.accepts("net")
                .withOptionalArg()
                .ofType(NetworkEnum.class)
                .defaultsTo(NetworkEnum.PROD);
        dateFlag = parser.accepts("date")
                .withRequiredArg()
                .ofType(Date.class)
                .withValuesConvertedBy(DateConverter.datePattern("yyyy/MM/dd"));
        OptionSpec<WaitForEnum> waitForFlag = parser.accepts("waitfor")
                .withRequiredArg()
                .ofType(WaitForEnum.class);
        OptionSpec<ValidationMode> modeFlag = parser.accepts("mode")
                .withRequiredArg()
                .ofType(ValidationMode.class)
                .defaultsTo(ValidationMode.SPV);
        OptionSpec<String> chainFlag = parser.accepts("chain").withRequiredArg();
        // For addkey/delkey.
        parser.accepts("pubkey").withRequiredArg();
        parser.accepts("privkey").withRequiredArg();
        parser.accepts("addr").withRequiredArg();
        parser.accepts("peers").withRequiredArg();
        OptionSpec<String> outputFlag = parser.accepts("output").withRequiredArg();
        parser.accepts("value").withRequiredArg();
        parser.accepts("fee").withRequiredArg();
        unixtimeFlag = parser.accepts("unixtime").withRequiredArg().ofType(Integer.class);
        OptionSpec<String> conditionFlag = parser.accepts("condition").withRequiredArg();
        parser.accepts("locktime").withRequiredArg();
        parser.accepts("allow-unconfirmed");
        parser.accepts("offline");
        parser.accepts("ignore-mandatory-extensions");
        OptionSpec<String> passwordFlag = parser.accepts("password").withRequiredArg();
        OptionSpec<String> paymentRequestLocation = parser.accepts("payment-request").withRequiredArg();
        parser.accepts("no-pki");
        options = parser.parse(args);

        final String HELP_TEXT = Resources.toString(WalletTool.class.getResource("wallet-tool-help.txt"), Charsets.UTF_8);

        if (args.length == 0 || options.has("help") || options.nonOptionArguments().size() < 1) {
            System.out.println(HELP_TEXT);
            return;
        }

        ActionEnum action;
        try {
            String actionStr = options.nonOptionArguments().get(0);
            actionStr = actionStr.toUpperCase().replace("-", "_");
            action = ActionEnum.valueOf(actionStr);
        } catch (IllegalArgumentException e) {
            System.err.println("Could not understand action name " + options.nonOptionArguments().get(0));
            return;
        }

        if (options.has("debuglog")) {
            BriefLogFormatter.init();
            log.info("Starting up ...");
        } else {
            // Disable logspam unless there is a flag.
            java.util.logging.Logger logger = LogManager.getLogManager().getLogger("");
            logger.setLevel(Level.SEVERE);
        }
        switch (netFlag.value(options)) {
            case PROD:
                params = MainNetParams.get();
                chainFileName = new File("prodnet.chain");
                break;
            case TEST:
                params = TestNet3Params.get();
                chainFileName = new File("testnet.chain");
                break;
            case REGTEST:
                params = RegTestParams.get();
                chainFileName = new File("regtest.chain");
                break;
            default:
                throw new RuntimeException("Unreachable.");
        }
        mode = modeFlag.value(options);

        // Allow the user to override the name of the chain used.
        if (options.has(chainFlag)) {
            chainFileName = new File(chainFlag.value(options));
        }

        if (options.has("condition")) {
            condition = new Condition(conditionFlag.value(options));
        }

        if (options.has(passwordFlag)) {
            password = passwordFlag.value(options);
        }

        walletFile = new File(walletFileName.value(options));
        if (action == ActionEnum.CREATE) {
            createWallet(options, params, walletFile);
            return;  // We're done.
        }
        if (!walletFile.exists()) {
            System.err.println("Specified wallet file " + walletFile + " does not exist. Try wallet-tool --wallet=" + walletFile + " create");
            return;
        }

        if (action == ActionEnum.RAW_DUMP) {
            // Just parse the protobuf and print, then bail out. Don't try and do a real deserialization. This is
            // useful mostly for investigating corrupted wallets.
            FileInputStream stream = new FileInputStream(walletFile);
            try {
                Protos.Wallet proto = WalletProtobufSerializer.parseToProto(stream);
                System.out.println(proto.toString());
                return;
            } finally {
                stream.close();
            }
        }

        try {
            WalletProtobufSerializer loader = new WalletProtobufSerializer();
            if (options.has("ignore-mandatory-extensions"))
                loader.setRequireMandatoryExtensions(false);
            wallet = loader.readWallet(new BufferedInputStream(new FileInputStream(walletFile)));
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
            case ADD_ADDR: addAddr(); break;
            case DELETE_KEY: deleteKey(); break;
            case RESET: reset(); break;
            case SYNC: syncChain(); break;
            case SEND:
                if (options.has(paymentRequestLocation) && options.has(outputFlag)) {
                    System.err.println("--payment-request and --output cannot be used together.");
                    return;
                } else if (options.has(outputFlag)) {
                    BigInteger fee = BigInteger.ZERO;
                    if (options.has("fee")) {
                        fee = Utils.toNanoCoins((String)options.valueOf("fee"));
                    }
                    String lockTime = null;
                    if (options.has("locktime")) {
                        lockTime = (String) options.valueOf("locktime");
                    }
                    boolean allowUnconfirmed = options.has("allow-unconfirmed");
                    send(outputFlag.values(options), fee, lockTime, allowUnconfirmed);
                } else if (options.has(paymentRequestLocation)) {
                    sendPaymentRequest(paymentRequestLocation.value(options), !options.has("no-pki"));
                } else {
                    System.err.println("You must specify a --payment-request or at least one --output=addr:value.");
                    return;
                }
                break;
        }

        if (!wallet.isConsistent()) {
            System.err.println("************** WALLET IS INCONSISTENT *****************");
            return;
        }
        
        saveWallet(walletFile);

        if (options.has(waitForFlag)) {
            WaitForEnum value;
            try {
                value = waitForFlag.value(options);
            } catch (Exception e) {
                System.err.println("Could not understand the --waitfor flag: Valid options are WALLET_TX, BLOCK, " +
                                   "BALANCE and EVER");
                return;
            }
            wait(value);
            if (!wallet.isConsistent()) {
                System.err.println("************** WALLET IS INCONSISTENT *****************");
                return;
            }
            saveWallet(walletFile);
        }
        shutdown();
    }

    private static void addAddr() {
        String addr = (String) options.valueOf("addr");
        if (addr == null) {
            System.err.println("You must specify an --addr to watch.");
            return;
        }
        try {
            Address address = new Address(params, addr);
            // If no creation time is specified, assume genesis (zero).
            wallet.addWatchedAddress(address, getCreationTimeSeconds());
        } catch (AddressFormatException e) {
            System.err.println("Could not parse given address, or wrong network: " + addr);
        }
    }

    private static void send(List<String> outputs, BigInteger fee, String lockTimeStr, boolean allowUnconfirmed) throws VerificationException {
        try {
            // Convert the input strings to outputs.
            Transaction t = new Transaction(params);
            for (String spec : outputs) {
                String[] parts = spec.split(":");
                if (parts.length != 2) {
                    System.err.println("Malformed output specification, must have two parts separated by :");
                    return;
                }
                String destination = parts[0];
                try {
                    BigInteger value = Utils.toNanoCoins(parts[1]);
                    if (destination.startsWith("0")) {
                        boolean compressed = destination.startsWith("02") || destination.startsWith("03");
                        // Treat as a raw public key.
                        BigInteger pubKey = new BigInteger(destination, 16);
                        ECKey key = new ECKey(null, pubKey.toByteArray(), compressed);
                        t.addOutput(value, key);
                    } else {
                        // Treat as an address.
                        Address addr = new Address(params, destination);
                        t.addOutput(value, addr);
                    }
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
            Wallet.SendRequest req = Wallet.SendRequest.forTx(t);
            if (t.getOutputs().size() == 1 && t.getOutput(0).getValue().equals(wallet.getBalance())) {
                log.info("Emptying out wallet, recipient may get less than what you expect");
                req.emptyWallet = true;
            }
            req.fee = fee;
            if (allowUnconfirmed) {
                wallet.allowSpendingUnconfirmedTransactions();
            }
            if (password != null) {
                if (!wallet.checkPassword(password)) {
                    System.err.println("Password is incorrect.");
                    return;
                }
                req.aesKey = wallet.getKeyCrypter().deriveKey(password);
            }
            wallet.completeTx(req);

            try {
                if (lockTimeStr != null) {
                    t.setLockTime(Transaction.parseLockTimeStr(lockTimeStr));
                    // For lock times to take effect, at least one output must have a non-final sequence number.
                    t.getInputs().get(0).setSequenceNumber(0);
                    // And because we modified the transaction after it was completed, we must re-sign the inputs.
                    t.signInputs(Transaction.SigHash.ALL, wallet);
                }
            } catch (ParseException e) {
                System.err.println("Could not understand --locktime of " + lockTimeStr);
                return;
            } catch (ScriptException e) {
                throw new RuntimeException(e);
            }
            t = req.tx;   // Not strictly required today.
            System.out.println(t.getHashAsString());
            if (options.has("offline")) {
                wallet.commitTx(t);
                return;
            }

            setup();
            peers.startAndWait();
            // Wait for peers to connect, the tx to be sent to one of them and for it to be propagated across the
            // network. Once propagation is complete and we heard the transaction back from all our peers, it will
            // be committed to the wallet.
            peers.broadcastTransaction(t).get();
            // Hack for regtest/single peer mode, as we're about to shut down and won't get an ACK from the remote end.
            List<Peer> peerList = peers.getConnectedPeers();
            if (peerList.size() == 1)
                peerList.get(0).ping().get();
        } catch (BlockStoreException e) {
            throw new RuntimeException(e);
        } catch (KeyCrypterException e) {
            throw new RuntimeException(e);
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        } catch (ExecutionException e) {
            throw new RuntimeException(e);
        } catch (InsufficientMoneyException e) {
            System.err.println("Insufficient funds: have " + Utils.bitcoinValueToFriendlyString(wallet.getBalance()));
        }
    }

    private static void sendPaymentRequest(String location, boolean verifyPki) {
        if (location.startsWith("http") || location.startsWith("bitcoin")) {
            try {
                ListenableFuture<PaymentSession> future;
                if (location.startsWith("http")) {
                    future = PaymentSession.createFromUrl(location, verifyPki);
                } else {
                    BitcoinURI paymentRequestURI = new BitcoinURI(location);
                    future = PaymentSession.createFromBitcoinUri(paymentRequestURI, verifyPki);
                }
                PaymentSession session = future.get();
                if (session != null) {
                    send(session);
                } else {
                    System.err.println("Server returned null session");
                    System.exit(1);
                }
            } catch (PaymentRequestException e) {
                System.err.println("Error creating payment session " + e.getMessage());
                System.exit(1);
            } catch (BitcoinURIParseException e) {
                System.err.println("Invalid bitcoin uri: " + e.getMessage());
                System.exit(1);
            } catch (InterruptedException e) {
                // Ignore.
            } catch (ExecutionException e) {
                throw new RuntimeException(e);
            }
        } else {
            // Try to open the payment request as a file.
            FileInputStream stream = null;
            try {
                File paymentRequestFile = new File(location);
                stream = new FileInputStream(paymentRequestFile);
            } catch (Exception e) {
                System.err.println("Failed to open file: " + e.getMessage());
                System.exit(1);
            }
            try {
                paymentRequest = org.bitcoin.protocols.payments.Protos.PaymentRequest.newBuilder().mergeFrom(stream).build();
            } catch(IOException e) {
                System.err.println("Failed to parse payment request from file " + e.getMessage());
                System.exit(1);
            }
            PaymentSession session = null;
            try {
                session = new PaymentSession(paymentRequest, verifyPki);
            } catch (PaymentRequestException e) {
                System.err.println("Error creating payment session " + e.getMessage());
                System.exit(1);
            }
            send(session);
        }
    }

    private static void send(PaymentSession session) {
        try {
            System.out.println("Payment Request");
            System.out.println("Amount: " + session.getValue().doubleValue() / 100000 + "mBTC");
            System.out.println("Date: " + session.getDate());
            System.out.println("Memo: " + session.getMemo());
            if (session.pkiVerificationData != null) {
                System.out.println("Pki-Verified Name: " + session.pkiVerificationData.name);
                if (session.pkiVerificationData.orgName != null)
                    System.out.println("Pki-Verified Org: " + session.pkiVerificationData.orgName);
                System.out.println("PKI data verified by: " + session.pkiVerificationData.rootAuthorityName);
            }
            final Wallet.SendRequest req = session.getSendRequest();
            if (password != null) {
                if (!wallet.checkPassword(password)) {
                    System.err.println("Password is incorrect.");
                    return;
                }
                req.aesKey = wallet.getKeyCrypter().deriveKey(password);
            }
            wallet.completeTx(req);  // may throw InsufficientMoneyException.
            if (options.has("offline")) {
                wallet.commitTx(req.tx);
                return;
            }
            setup();
            // No refund address specified, no user-specified memo field.
            ListenableFuture<PaymentSession.Ack> future = session.sendPayment(ImmutableList.of(req.tx), null, null);
            if (future == null) {
                // No payment_url for submission so, broadcast and wait.
                peers.startAndWait();
                peers.broadcastTransaction(req.tx).get();
            } else {
                PaymentSession.Ack ack = future.get();
                wallet.commitTx(req.tx);
                System.out.println("Memo from server: " + ack.getMemo());
            }
        } catch (PaymentRequestException e) {
            System.err.println("Failed to send payment " + e.getMessage());
            System.exit(1);
        } catch (VerificationException e) {
            System.err.println("Failed to send payment " + e.getMessage());
            System.exit(1);
        } catch (ExecutionException e) {
            System.err.println("Failed to send payment " + e.getMessage());
            System.exit(1);
        } catch (IOException e) {
            System.err.println("Invalid payment " + e.getMessage());
            System.exit(1);
        } catch (InterruptedException e1) {
            // Ignore.
        } catch (InsufficientMoneyException e) {
            System.err.println("Insufficient funds: have " + Utils.bitcoinValueToFriendlyString(wallet.getBalance()));
        } catch (BlockStoreException e) {
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
                    public synchronized void onChange() {
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
            // Ignore.
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
        if (!chainFileName.exists() && wallet.getTransactions(true).size() > 0) {
            // No chain, so reset the wallet as we will be downloading from scratch.
            System.out.println("Chain file is missing so clearing transactions from the wallet.");
            reset();
        }
        if (mode == ValidationMode.SPV) {
            store = new SPVBlockStore(params, chainFileName);
            chain = new BlockChain(params, wallet, store);
        } else if (mode == ValidationMode.FULL) {
            FullPrunedBlockStore s = new H2FullPrunedBlockStore(params, chainFileName.getAbsolutePath(), 5000);
            store = s;
            chain = new FullPrunedBlockChain(params, wallet, s);
        }
        // This will ensure the wallet is saved when it changes.
        wallet.autosaveToFile(walletFile, 200, TimeUnit.MILLISECONDS, null);
        peers = new PeerGroup(params, chain);
        peers.setUserAgent("WalletTool", "1.0");
        peers.addWallet(wallet);
        if (options.has("peers")) {
            String peersFlag = (String) options.valueOf("peers");
            String[] peerAddrs = peersFlag.split(",");
            for (String peer : peerAddrs) {
                try {
                    peers.addAddress(new PeerAddress(InetAddress.getByName(peer), params.getPort()));
                } catch (UnknownHostException e) {
                    System.err.println("Could not understand peer domain name/IP address: " + peer + ": " + e.getMessage());
                    System.exit(1);
                }
            }
        } else {
            peers.addPeerDiscovery(new DnsDiscovery(params));
        }
    }

    private static void syncChain() {
        try {
            setup();
            int startTransactions = wallet.getTransactions(true).size();
            DownloadListener listener = new DownloadListener();
            peers.startAndWait();
            peers.startBlockChainDownload(listener);
            try {
                listener.await();
            } catch (InterruptedException e) {
                System.err.println("Chain download interrupted, quitting ...");
                System.exit(1);
            }
            int endTransactions = wallet.getTransactions(true).size();
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
            peers.stopAndWait();
            saveWallet(walletFile);
            store.close();
            wallet = null;
        } catch (BlockStoreException e) {
            throw new RuntimeException(e);
        }
    }

    private static void createWallet(OptionSet options, NetworkParameters params, File walletFile) throws IOException {
        if (walletFile.exists() && !options.has("force")) {
            System.err.println("Wallet creation requested but " + walletFile + " already exists, use --force");
            return;
        }
        wallet = new Wallet(params);
        if (password != null) {
            wallet.encrypt(password);
            wallet.addNewEncryptedKey(password);
        }
        wallet.saveToFile(walletFile);
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
        long creationTimeSeconds = getCreationTimeSeconds();
        if (options.has("privkey")) {
            String data = (String) options.valueOf("privkey");
            if (data.startsWith("5J") || data.startsWith("5H") || data.startsWith("5K")) {
                DumpedPrivateKey dpk;
                try {
                    dpk = new DumpedPrivateKey(params, data);
                } catch (AddressFormatException e) {
                    System.err.println("Could not parse dumped private key " + data);
                    return;
                }
                key = dpk.getKey();
            } else {
                byte[] decode = Utils.parseAsHexOrBase58(data);
                if (decode == null) {
                    System.err.println("Could not understand --privkey as either hex or base58: " + data);
                    return;
                }
                key = new ECKey(new BigInteger(1, decode));
            }
            if (options.has("pubkey")) {
                // Give the user a hint.
                System.out.println("You don't have to specify --pubkey when a private key is supplied.");
            }
            key.setCreationTimeSeconds(creationTimeSeconds);
        } else if (options.has("pubkey")) {
            byte[] pubkey = Utils.parseAsHexOrBase58((String) options.valueOf("pubkey"));
            key = new ECKey(null, pubkey);
            key.setCreationTimeSeconds(creationTimeSeconds);
        } else {
            // Freshly generated key.
            key = new ECKey();
            if (creationTimeSeconds > 0)
                key.setCreationTimeSeconds(creationTimeSeconds);
        }
        if (wallet.findKeyFromPubKey(key.getPubKey()) != null) {
            System.err.println("That key already exists in this wallet.");
            return;
        }
        try {
            if (wallet.isEncrypted()) {
                if (password == null || !wallet.checkPassword(password)) {
                    System.err.println("The password is incorrect.");
                    return;
                }
                key = key.encrypt(wallet.getKeyCrypter(), wallet.getKeyCrypter().deriveKey(password));
            }
            wallet.addKey(key);
        } catch (KeyCrypterException kce) {
            System.err.println("There was an encryption related error when adding the key. The error was '" + kce.getMessage() + "'.");
        }
        System.out.println(key.toAddress(params) + " " + key);
    }

    private static long getCreationTimeSeconds() {
        long creationTimeSeconds = 0;
        if (options.has(unixtimeFlag)) {
            creationTimeSeconds = unixtimeFlag.value(options);
        } else if (options.has(dateFlag)) {
            creationTimeSeconds = dateFlag.value(options).getTime() / 1000;
        }
        return creationTimeSeconds;
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
        } else {
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
        wallet.removeKey(key);
    }

    private static void dumpWallet() throws BlockStoreException {
        // Setup to get the chain height so we can estimate lock times, but don't wipe the transactions if it's not
        // there just for the dump case.
        if (chainFileName.exists())
            setup();
        System.out.println(wallet.toString(true, true, true, chain));
    }
}
