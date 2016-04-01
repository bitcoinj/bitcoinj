/*
 * Copyright 2012 Google Inc.
 * Copyright 2014 Andreas Schildbach
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

package org.bitcoinj.tools;

import org.bitcoinj.core.*;
import org.bitcoinj.crypto.*;
import org.bitcoinj.net.discovery.DnsDiscovery;
import org.bitcoinj.params.MainNetParams;
import org.bitcoinj.params.RegTestParams;
import org.bitcoinj.params.TestNet3Params;
import org.bitcoinj.protocols.payments.PaymentProtocol;
import org.bitcoinj.protocols.payments.PaymentProtocolException;
import org.bitcoinj.protocols.payments.PaymentSession;
import org.bitcoinj.script.ScriptBuilder;
import org.bitcoinj.store.*;
import org.bitcoinj.uri.BitcoinURI;
import org.bitcoinj.uri.BitcoinURIParseException;
import org.bitcoinj.utils.BriefLogFormatter;
import org.bitcoinj.wallet.DeterministicSeed;
import org.bitcoinj.wallet.DeterministicUpgradeRequiredException;
import org.bitcoinj.wallet.DeterministicUpgradeRequiresPassword;
import com.google.common.base.Charsets;
import com.google.common.base.Splitter;
import com.google.common.collect.ImmutableList;
import com.google.common.io.Resources;
import com.google.common.util.concurrent.Futures;
import com.google.common.util.concurrent.ListenableFuture;
import com.google.protobuf.ByteString;
import com.subgraph.orchid.TorClient;
import joptsimple.OptionParser;
import joptsimple.OptionSet;
import joptsimple.OptionSpec;
import joptsimple.util.DateConverter;

import org.bitcoinj.core.listeners.BlocksDownloadedEventListener;
import org.bitcoinj.core.listeners.DownloadProgressTracker;
import org.bitcoinj.wallet.MarriedKeyChain;
import org.bitcoinj.wallet.Protos;
import org.bitcoinj.wallet.SendRequest;
import org.bitcoinj.wallet.Wallet;
import org.bitcoinj.wallet.WalletExtension;
import org.bitcoinj.wallet.WalletProtobufSerializer;
import org.bitcoinj.wallet.Wallet.BalanceType;
import org.bitcoinj.wallet.listeners.WalletChangeEventListener;
import org.bitcoinj.wallet.listeners.WalletCoinsReceivedEventListener;
import org.bitcoinj.wallet.listeners.WalletCoinsSentEventListener;
import org.bitcoinj.wallet.listeners.WalletReorganizeEventListener;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.spongycastle.crypto.params.KeyParameter;
import org.spongycastle.util.encoders.Hex;

import javax.annotation.Nullable;
import java.io.*;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.SecureRandom;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.logging.Level;
import java.util.logging.LogManager;

import static org.bitcoinj.core.Coin.parseCoin;
import static com.google.common.base.Preconditions.checkNotNull;

/**
 * A command line tool for manipulating wallets and working with Bitcoin.
 */
public class WalletTool {
    private static final Logger log = LoggerFactory.getLogger(WalletTool.class);

    private static OptionSet options;
    private static OptionSpec<Date> dateFlag;
    private static OptionSpec<Long> unixtimeFlag;
    private static OptionSpec<String> seedFlag, watchFlag;
    private static OptionSpec<String> xpubkeysFlag;

    private static NetworkParameters params;
    private static File walletFile;
    private static BlockStore store;
    private static AbstractBlockChain chain;
    private static PeerGroup peers;
    private static Wallet wallet;
    private static File chainFileName;
    private static ValidationMode mode;
    private static String password;
    private static org.bitcoin.protocols.payments.Protos.PaymentRequest paymentRequest;
    private static OptionSpec<Integer> lookaheadSize;

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

        public boolean matchBitcoins(Coin comparison) {
            try {
                Coin units = parseCoin(value);
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
        CURRENT_RECEIVE_ADDR,
        SYNC,
        RESET,
        SEND,
        SEND_CLTVPAYMENTCHANNEL,
        SETTLE_CLTVPAYMENTCHANNEL,
        REFUND_CLTVPAYMENTCHANNEL,
        ENCRYPT,
        DECRYPT,
        MARRY,
        ROTATE,
        SET_CREATION_TIME,
    }

    public enum WaitForEnum {
        EVER,
        WALLET_TX,
        BLOCK,
        BALANCE
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
        OptionSpec<String> walletFileName = parser.accepts("wallet").withRequiredArg().defaultsTo("wallet");
        seedFlag = parser.accepts("seed").withRequiredArg();
        watchFlag = parser.accepts("watchkey").withRequiredArg();
        OptionSpec<NetworkEnum> netFlag = parser.accepts("net").withRequiredArg().ofType(NetworkEnum.class).defaultsTo(NetworkEnum.MAIN);
        dateFlag = parser.accepts("date").withRequiredArg().ofType(Date.class)
                .withValuesConvertedBy(DateConverter.datePattern("yyyy/MM/dd"));
        OptionSpec<WaitForEnum> waitForFlag = parser.accepts("waitfor").withRequiredArg().ofType(WaitForEnum.class);
        OptionSpec<ValidationMode> modeFlag = parser.accepts("mode").withRequiredArg().ofType(ValidationMode.class)
                .defaultsTo(ValidationMode.SPV);
        OptionSpec<String> chainFlag = parser.accepts("chain").withRequiredArg();
        // For addkey/delkey.
        parser.accepts("pubkey").withRequiredArg();
        parser.accepts("privkey").withRequiredArg();
        parser.accepts("addr").withRequiredArg();
        parser.accepts("peers").withRequiredArg();
        xpubkeysFlag = parser.accepts("xpubkeys").withRequiredArg();
        OptionSpec<String> outputFlag = parser.accepts("output").withRequiredArg();
        parser.accepts("value").withRequiredArg();
        OptionSpec<String> feePerKbOption = parser.accepts("fee-per-kb").withRequiredArg();
        unixtimeFlag = parser.accepts("unixtime").withRequiredArg().ofType(Long.class);
        OptionSpec<String> conditionFlag = parser.accepts("condition").withRequiredArg();
        parser.accepts("locktime").withRequiredArg();
        parser.accepts("allow-unconfirmed");
        parser.accepts("offline");
        parser.accepts("ignore-mandatory-extensions");
        lookaheadSize = parser.accepts("lookahead-size").withRequiredArg().ofType(Integer.class);
        OptionSpec<String> passwordFlag = parser.accepts("password").withRequiredArg();
        OptionSpec<String> paymentRequestLocation = parser.accepts("payment-request").withRequiredArg();
        parser.accepts("no-pki");
        parser.accepts("tor");
        parser.accepts("dump-privkeys");
        OptionSpec<String> refundFlag = parser.accepts("refund-to").withRequiredArg();
        OptionSpec<String> txHashFlag = parser.accepts("txhash").withRequiredArg();
        options = parser.parse(args);

        if (args.length == 0 || options.has("help") ||
                options.nonOptionArguments().size() < 1 || options.nonOptionArguments().contains("help")) {
            System.out.println(Resources.toString(WalletTool.class.getResource("wallet-tool-help.txt"), Charsets.UTF_8));
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
            case MAIN:
            case PROD:
                params = MainNetParams.get();
                chainFileName = new File("mainnet.chain");
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
        Context.propagate(new Context(params));

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
                proto = attemptHexConversion(proto);
                System.out.println(proto.toString());
                return;
            } finally {
                stream.close();
            }
        }

        InputStream walletInputStream = null;
        try {
            boolean forceReset = action == ActionEnum.RESET
                || (action == ActionEnum.SYNC
                    && options.has("force"));
            WalletProtobufSerializer loader = new WalletProtobufSerializer();
            if (options.has("ignore-mandatory-extensions"))
                loader.setRequireMandatoryExtensions(false);
            walletInputStream = new BufferedInputStream(new FileInputStream(walletFile));
            wallet = loader.readWallet(walletInputStream, forceReset, (WalletExtension[])(null));
            if (!wallet.getParams().equals(params)) {
                System.err.println("Wallet does not match requested network parameters: " +
                        wallet.getParams().getId() + " vs " + params.getId());
                return;
            }
        } catch (Exception e) {
            System.err.println("Failed to load wallet '" + walletFile + "': " + e.getMessage());
            e.printStackTrace();
            return;
        } finally {
            if (walletInputStream != null) {
                walletInputStream.close();
            }
        }

        // What should we do?
        switch (action) {
            case DUMP: dumpWallet(); break;
            case ADD_KEY: addKey(); break;
            case ADD_ADDR: addAddr(); break;
            case DELETE_KEY: deleteKey(); break;
            case CURRENT_RECEIVE_ADDR: currentReceiveAddr(); break;
            case RESET: reset(); break;
            case SYNC: syncChain(); break;
            case SEND:
                if (options.has(paymentRequestLocation) && options.has(outputFlag)) {
                    System.err.println("--payment-request and --output cannot be used together.");
                    return;
                } else if (options.has(outputFlag)) {
                    Coin feePerKb = null;
                    if (options.has(feePerKbOption))
                        feePerKb = parseCoin((String) options.valueOf(feePerKbOption));
                    String lockTime = null;
                    if (options.has("locktime")) {
                        lockTime = (String) options.valueOf("locktime");
                    }
                    boolean allowUnconfirmed = options.has("allow-unconfirmed");
                    send(outputFlag.values(options), feePerKb, lockTime, allowUnconfirmed);
                } else if (options.has(paymentRequestLocation)) {
                    sendPaymentRequest(paymentRequestLocation.value(options), !options.has("no-pki"));
                } else {
                    System.err.println("You must specify a --payment-request or at least one --output=addr:value.");
                    return;
                }
                break;
            case SEND_CLTVPAYMENTCHANNEL: {
                if (!options.has(outputFlag)) {
                    System.err.println("You must specify a --output=addr:value");
                    return;
                }
                Coin feePerKb = null;
                if (options.has(feePerKbOption))
                    feePerKb = parseCoin((String) options.valueOf(feePerKbOption));
                if (!options.has("locktime")) {
                    System.err.println("You must specify a --locktime");
                    return;
                }
                String lockTime = (String) options.valueOf("locktime");
                boolean allowUnconfirmed = options.has("allow-unconfirmed");
                if (!options.has(refundFlag)) {
                    System.err.println("You must specify an address to refund money to after expiry: --refund-to=addr");
                    return;
                }
                sendCLTVPaymentChannel(refundFlag.value(options), outputFlag.value(options), feePerKb, lockTime, allowUnconfirmed);
                } break;
            case SETTLE_CLTVPAYMENTCHANNEL: {
                if (!options.has(outputFlag)) {
                    System.err.println("You must specify a --output=addr:value");
                    return;
                }
                Coin feePerKb = null;
                if (options.has(feePerKbOption))
                    feePerKb = parseCoin((String) options.valueOf(feePerKbOption));
                boolean allowUnconfirmed = options.has("allow-unconfirmed");
                if (!options.has(txHashFlag)) {
                    System.err.println("You must specify the transaction to spend: --txhash=tx-hash");
                    return;
                }
                settleCLTVPaymentChannel(txHashFlag.value(options), outputFlag.value(options), feePerKb, allowUnconfirmed);
                } break;
            case REFUND_CLTVPAYMENTCHANNEL: {
                if (!options.has(outputFlag)) {
                    System.err.println("You must specify a --output=addr:value");
                    return;
                }
                Coin feePerKb = null;
                if (options.has(feePerKbOption))
                    feePerKb = parseCoin((String) options.valueOf(feePerKbOption));
                boolean allowUnconfirmed = options.has("allow-unconfirmed");
                if (!options.has(txHashFlag)) {
                    System.err.println("You must specify the transaction to spend: --txhash=tx-hash");
                    return;
                }
                refundCLTVPaymentChannel(txHashFlag.value(options), outputFlag.value(options), feePerKb, allowUnconfirmed);
            } break;
            case ENCRYPT: encrypt(); break;
            case DECRYPT: decrypt(); break;
            case MARRY: marry(); break;
            case ROTATE: rotate(); break;
            case SET_CREATION_TIME: setCreationTime(); break;
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

    private static Protos.Wallet attemptHexConversion(Protos.Wallet proto) {
        // Try to convert any raw hashes and such to textual equivalents for easier debugging. This makes it a bit
        // less "raw" but we will just abort on any errors.
        try {
            Protos.Wallet.Builder builder = proto.toBuilder();
            for (Protos.Transaction.Builder tx : builder.getTransactionBuilderList()) {
                tx.setHash(bytesToHex(tx.getHash()));
                for (int i = 0; i < tx.getBlockHashCount(); i++)
                    tx.setBlockHash(i, bytesToHex(tx.getBlockHash(i)));
                for (Protos.TransactionInput.Builder input : tx.getTransactionInputBuilderList())
                    input.setTransactionOutPointHash(bytesToHex(input.getTransactionOutPointHash()));
                for (Protos.TransactionOutput.Builder output : tx.getTransactionOutputBuilderList()) {
                    if (output.hasSpentByTransactionHash())
                        output.setSpentByTransactionHash(bytesToHex(output.getSpentByTransactionHash()));
                }
                // TODO: keys, ip addresses etc.
            }
            return builder.build();
        } catch (Throwable throwable) {
            log.error("Failed to do hex conversion on wallet proto", throwable);
            return proto;
        }
    }

    private static ByteString bytesToHex(ByteString bytes) {
        return ByteString.copyFrom(Utils.HEX.encode(bytes.toByteArray()).getBytes());
    }

    private static void marry() {
        if (!options.has(xpubkeysFlag)) {
            throw new IllegalStateException();
        }

        String[] xpubkeys = options.valueOf(xpubkeysFlag).split(",");
        ImmutableList.Builder<DeterministicKey> keys = ImmutableList.builder();
        for (String xpubkey : xpubkeys) {
            keys.add(DeterministicKey.deserializeB58(null, xpubkey.trim(), params));
        }
        MarriedKeyChain chain = MarriedKeyChain.builder()
                .random(new SecureRandom())
                .followingKeys(keys.build())
                .build();
        wallet.addAndActivateHDChain(chain);
    }

    private static void rotate() throws BlockStoreException {
        setup();
        peers.start();
        // Set a key rotation time and possibly broadcast the resulting maintenance transactions.
        long rotationTimeSecs = Utils.currentTimeSeconds();
        if (options.has(dateFlag)) {
            rotationTimeSecs = options.valueOf(dateFlag).getTime() / 1000;
        } else if (options.has(unixtimeFlag)) {
            rotationTimeSecs = options.valueOf(unixtimeFlag);
        }
        log.info("Setting wallet key rotation time to {}", rotationTimeSecs);
        wallet.setKeyRotationTime(rotationTimeSecs);
        KeyParameter aesKey = null;
        if (wallet.isEncrypted()) {
            aesKey = passwordToKey(true);
            if (aesKey == null)
                return;
        }
        Futures.getUnchecked(wallet.doMaintenance(aesKey, true));
    }

    private static void encrypt() {
        if (password == null) {
            System.err.println("You must provide a --password");
            return;
        }
        if (wallet.isEncrypted()) {
            System.err.println("This wallet is already encrypted.");
            return;
        }
        wallet.encrypt(password);
    }

    private static void decrypt() {
        if (password == null) {
            System.err.println("You must provide a --password");
            return;
        }
        if (!wallet.isEncrypted()) {
            System.err.println("This wallet is not encrypted.");
            return;
        }
        try {
            wallet.decrypt(password);
        } catch (KeyCrypterException e) {
            System.err.println("Password incorrect.");
        }
    }

    private static void addAddr() {
        String addr = (String) options.valueOf("addr");
        if (addr == null) {
            System.err.println("You must specify an --addr to watch.");
            return;
        }
        try {
            Address address = Address.fromBase58(params, addr);
            // If no creation time is specified, assume genesis (zero).
            wallet.addWatchedAddress(address, getCreationTimeSeconds());
        } catch (AddressFormatException e) {
            System.err.println("Could not parse given address, or wrong network: " + addr);
        }
    }

    private static void send(List<String> outputs, Coin feePerKb, String lockTimeStr, boolean allowUnconfirmed) throws VerificationException {
        try {
            // Convert the input strings to outputs.
            Transaction t = new Transaction(params);
            for (String spec : outputs) {
                try {
                    OutputSpec outputSpec = new OutputSpec(spec);
                    if (outputSpec.isAddress()) {
                        t.addOutput(outputSpec.value, outputSpec.addr);
                    } else {
                        t.addOutput(outputSpec.value, outputSpec.key);
                    }
                } catch (WrongNetworkException e) {
                    System.err.println("Malformed output specification, address is for a different network: " + spec);
                    return;
                } catch (AddressFormatException e) {
                    System.err.println("Malformed output specification, could not parse as address: " + spec);
                    return;
                } catch (NumberFormatException e) {
                    System.err.println("Malformed output specification, could not parse as value: " + spec);
                    return;
                } catch (IllegalArgumentException e) {
                    System.err.println(e.getMessage());
                    return;
                }
            }
            SendRequest req = SendRequest.forTx(t);
            if (t.getOutputs().size() == 1 && t.getOutput(0).getValue().equals(wallet.getBalance())) {
                log.info("Emptying out wallet, recipient may get less than what you expect");
                req.emptyWallet = true;
            }
            if (feePerKb != null)
                req.feePerKb = feePerKb;
            if (allowUnconfirmed) {
                wallet.allowSpendingUnconfirmedTransactions();
            }
            if (password != null) {
                req.aesKey = passwordToKey(true);
                if (req.aesKey == null)
                    return;  // Error message already printed.
            }
            wallet.completeTx(req);

            try {
                if (lockTimeStr != null) {
                    t.setLockTime(parseLockTimeStr(lockTimeStr));
                    // For lock times to take effect, at least one output must have a non-final sequence number.
                    t.getInputs().get(0).setSequenceNumber(0);
                    // And because we modified the transaction after it was completed, we must re-sign the inputs.
                    wallet.signTransaction(req);
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
            peers.start();
            // Wait for peers to connect, the tx to be sent to one of them and for it to be propagated across the
            // network. Once propagation is complete and we heard the transaction back from all our peers, it will
            // be committed to the wallet.
            peers.broadcastTransaction(t).future().get();
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
            System.err.println("Insufficient funds: have " + wallet.getBalance().toFriendlyString());
        }
    }

    static class OutputSpec {
        public final Coin value;
        public final Address addr;
        public final ECKey key;

        public OutputSpec(String spec) throws IllegalArgumentException {
            String[] parts = spec.split(":");
            if (parts.length != 2) {
                throw new IllegalArgumentException("Malformed output specification, must have two parts separated by :");
            }
            String destination = parts[0];
            if ("ALL".equalsIgnoreCase(parts[1]))
                value = wallet.getBalance(BalanceType.ESTIMATED);
            else
                value = parseCoin(parts[1]);
            if (destination.startsWith("0")) {
                // Treat as a raw public key.
                byte[] pubKey = new BigInteger(destination, 16).toByteArray();
                key = ECKey.fromPublicOnly(pubKey);
                addr = null;
            } else {
                // Treat as an address.
                addr = Address.fromBase58(params, destination);
                key = null;
            }
        }

        public boolean isAddress() {
            return addr != null;
        }
    }

    private static void sendCLTVPaymentChannel(String refund, String output, Coin feePerKb, String lockTimeStr, boolean allowUnconfirmed) throws VerificationException {
        try {
            // Convert the input strings to outputs.
            ECKey outputKey, refundKey;
            Coin value;
            try {
                OutputSpec outputSpec = new OutputSpec(output);
                if (outputSpec.isAddress()) {
                    System.err.println("Output specification must be a public key");
                    return;
                }
                outputKey = outputSpec.key;
                value = outputSpec.value;
                byte[] refundPubKey = new BigInteger(refund, 16).toByteArray();
                refundKey = ECKey.fromPublicOnly(refundPubKey);
            } catch (WrongNetworkException e) {
                System.err.println("Malformed output specification, address is for a different network.");
                return;
            } catch (AddressFormatException e) {
                System.err.println("Malformed output specification, could not parse as address.");
                return;
            } catch (NumberFormatException e) {
                System.err.println("Malformed output specification, could not parse as value.");
                return;
            } catch (IllegalArgumentException e) {
                System.err.println(e.getMessage());
                return;
            }

            long lockTime;
            try {
                lockTime = parseLockTimeStr(lockTimeStr);
            } catch (ParseException e) {
                System.err.println("Could not understand --locktime of " + lockTimeStr);
                return;
            } catch (ScriptException e) {
                throw new RuntimeException(e);
            }

            SendRequest req = SendRequest.toCLTVPaymentChannel(params, BigInteger.valueOf(lockTime), refundKey, outputKey, value);
            if (req.tx.getOutputs().size() == 1 && req.tx.getOutput(0).getValue().equals(wallet.getBalance())) {
                log.info("Emptying out wallet, recipient may get less than what you expect");
                req.emptyWallet = true;
            }
            if (feePerKb != null)
                req.feePerKb = feePerKb;
            if (allowUnconfirmed) {
                wallet.allowSpendingUnconfirmedTransactions();
            }
            if (password != null) {
                req.aesKey = passwordToKey(true);
                if (req.aesKey == null)
                    return;  // Error message already printed.
            }
            wallet.completeTx(req);

            System.out.println(req.tx.getHashAsString());
            if (options.has("offline")) {
                wallet.commitTx(req.tx);
                return;
            }

            setup();
            peers.start();
            // Wait for peers to connect, the tx to be sent to one of them and for it to be propagated across the
            // network. Once propagation is complete and we heard the transaction back from all our peers, it will
            // be committed to the wallet.
            peers.broadcastTransaction(req.tx).future().get();
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
            System.err.println("Insufficient funds: have " + wallet.getBalance().toFriendlyString());
        }
    }

    /**
     * Settles a CLTV payment channel transaction given that we own both private keys (ie. for testing).
     */
    private static void settleCLTVPaymentChannel(String txHash, String output, Coin feePerKb, boolean allowUnconfirmed) {
        try {
            OutputSpec outputSpec;
            Coin value;
            try {
                outputSpec = new OutputSpec(output);
                value = outputSpec.value;
            } catch (WrongNetworkException e) {
                System.err.println("Malformed output specification, address is for a different network.");
                return;
            } catch (AddressFormatException e) {
                System.err.println("Malformed output specification, could not parse as address.");
                return;
            } catch (NumberFormatException e) {
                System.err.println("Malformed output specification, could not parse as value.");
                return;
            } catch (IllegalArgumentException e) {
                System.err.println(e.getMessage());
                return;
            }

            SendRequest req = outputSpec.isAddress() ?
                    SendRequest.to(outputSpec.addr, value) :
                    SendRequest.to(params, outputSpec.key, value);
            if (feePerKb != null)
                req.feePerKb = feePerKb;

            Transaction lockTimeVerify = wallet.getTransaction(Sha256Hash.wrap(txHash));
            if (lockTimeVerify == null) {
                System.err.println("Couldn't find transaction with given hash");
                return;
            }
            TransactionOutput lockTimeVerifyOutput = null;
            for (TransactionOutput out : lockTimeVerify.getOutputs()) {
                if (out.getScriptPubKey().isSentToCLTVPaymentChannel()) {
                    lockTimeVerifyOutput = out;
                }
            }
            if (lockTimeVerifyOutput == null) {
                System.err.println("TX to spend wasn't sent to LockTimeVerify");
                return;
            }

            if (!value.equals(lockTimeVerifyOutput.getValue())) {
                System.err.println("You must spend all the money in the input transaction");
            }

            if (allowUnconfirmed) {
                wallet.allowSpendingUnconfirmedTransactions();
            }
            if (password != null) {
                req.aesKey = passwordToKey(true);
                if (req.aesKey == null)
                    return;  // Error message already printed.
            }

            ECKey key1 = wallet.findKeyFromPubKey(
                    lockTimeVerifyOutput.getScriptPubKey().getCLTVPaymentChannelSenderPubKey());
            ECKey key2 = wallet.findKeyFromPubKey(
                    lockTimeVerifyOutput.getScriptPubKey().getCLTVPaymentChannelRecipientPubKey());
            if (key1 == null || key2 == null) {
                System.err.println("Don't own private keys for both pubkeys");
                return;
            }

            TransactionInput input = new TransactionInput(
                    params, req.tx, new byte[] {}, lockTimeVerifyOutput.getOutPointFor());
            req.tx.addInput(input);
            TransactionSignature sig1 =
                    req.tx.calculateSignature(0, key1, lockTimeVerifyOutput.getScriptPubKey(), Transaction.SigHash.SINGLE, false);
            TransactionSignature sig2 =
                    req.tx.calculateSignature(0, key2, lockTimeVerifyOutput.getScriptPubKey(), Transaction.SigHash.SINGLE, false);
            input.setScriptSig(ScriptBuilder.createCLTVPaymentChannelInput(sig1, sig2));

            System.out.println(req.tx.getHashAsString());
            if (options.has("offline")) {
                wallet.commitTx(req.tx);
                return;
            }

            setup();
            peers.start();
            // Wait for peers to connect, the tx to be sent to one of them and for it to be propagated across the
            // network. Once propagation is complete and we heard the transaction back from all our peers, it will
            // be committed to the wallet.
            peers.broadcastTransaction(req.tx).future().get();
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
        }
    }

    /**
     * Refunds a CLTV payment channel transaction after the lock time has expired.
     */
    private static void refundCLTVPaymentChannel(String txHash, String output, Coin feePerKb, boolean allowUnconfirmed) {
        try {
            OutputSpec outputSpec;
            Coin value;
            try {
                outputSpec = new OutputSpec(output);
                value = outputSpec.value;
            } catch (WrongNetworkException e) {
                System.err.println("Malformed output specification, address is for a different network.");
                return;
            } catch (AddressFormatException e) {
                System.err.println("Malformed output specification, could not parse as address.");
                return;
            } catch (NumberFormatException e) {
                System.err.println("Malformed output specification, could not parse as value.");
                return;
            } catch (IllegalArgumentException e) {
                System.err.println(e.getMessage());
                return;
            }

            SendRequest req = outputSpec.isAddress() ?
                    SendRequest.to(outputSpec.addr, value) :
                    SendRequest.to(params, outputSpec.key, value);
            if (feePerKb != null)
                req.feePerKb = feePerKb;

            Transaction lockTimeVerify = wallet.getTransaction(Sha256Hash.wrap(txHash));
            if (lockTimeVerify == null) {
                System.err.println("Couldn't find transaction with given hash");
                return;
            }
            TransactionOutput lockTimeVerifyOutput = null;
            for (TransactionOutput out : lockTimeVerify.getOutputs()) {
                if (out.getScriptPubKey().isSentToCLTVPaymentChannel()) {
                    lockTimeVerifyOutput = out;
                }
            }
            if (lockTimeVerifyOutput == null) {
                System.err.println("TX to spend wasn't sent to LockTimeVerify");
                return;
            }

            req.tx.setLockTime(lockTimeVerifyOutput.getScriptPubKey().getCLTVPaymentChannelExpiry().longValue());

            if (!value.equals(lockTimeVerifyOutput.getValue())) {
                System.err.println("You must spend all the money in the input transaction");
            }

            if (allowUnconfirmed) {
                wallet.allowSpendingUnconfirmedTransactions();
            }
            if (password != null) {
                req.aesKey = passwordToKey(true);
                if (req.aesKey == null)
                    return;  // Error message already printed.
            }

            ECKey key = wallet.findKeyFromPubKey(
                    lockTimeVerifyOutput.getScriptPubKey().getCLTVPaymentChannelSenderPubKey());
            if (key == null) {
                System.err.println("Don't own private key for pubkey");
                return;
            }

            TransactionInput input = new TransactionInput(
                    params, req.tx, new byte[] {}, lockTimeVerifyOutput.getOutPointFor());
            input.setSequenceNumber(0);
            req.tx.addInput(input);
            TransactionSignature sig =
                    req.tx.calculateSignature(0, key, lockTimeVerifyOutput.getScriptPubKey(), Transaction.SigHash.SINGLE, false);
            input.setScriptSig(ScriptBuilder.createCLTVPaymentChannelRefund(sig));

            System.out.println(req.tx.getHashAsString());
            if (options.has("offline")) {
                wallet.commitTx(req.tx);
                return;
            }

            setup();
            peers.start();
            // Wait for peers to connect, the tx to be sent to one of them and for it to be propagated across the
            // network. Once propagation is complete and we heard the transaction back from all our peers, it will
            // be committed to the wallet.
            peers.broadcastTransaction(req.tx).future().get();
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
        }
    }

    /**
     * Parses the string either as a whole number of blocks, or if it contains slashes as a YYYY/MM/DD format date
     * and returns the lock time in wire format.
     */
    private static long parseLockTimeStr(String lockTimeStr) throws ParseException {
        if (lockTimeStr.indexOf("/") != -1) {
            SimpleDateFormat format = new SimpleDateFormat("yyyy/MM/dd", Locale.US);
            Date date = format.parse(lockTimeStr);
            return date.getTime() / 1000;
        }
        return Long.parseLong(lockTimeStr);
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
            } catch (PaymentProtocolException e) {
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
            } catch (PaymentProtocolException e) {
                System.err.println("Error creating payment session " + e.getMessage());
                System.exit(1);
            }
            send(session);
        }
    }

    private static void send(PaymentSession session) {
        try {
            System.out.println("Payment Request");
            System.out.println("Coin: " + session.getValue().toFriendlyString());
            System.out.println("Date: " + session.getDate());
            System.out.println("Memo: " + session.getMemo());
            if (session.pkiVerificationData != null) {
                System.out.println("Pki-Verified Name: " + session.pkiVerificationData.displayName);
                System.out.println("PKI data verified by: " + session.pkiVerificationData.rootAuthorityName);
            }
            final SendRequest req = session.getSendRequest();
            if (password != null) {
                req.aesKey = passwordToKey(true);
                if (req.aesKey == null)
                    return;   // Error message already printed.
            }
            wallet.completeTx(req);  // may throw InsufficientMoneyException.
            if (options.has("offline")) {
                wallet.commitTx(req.tx);
                return;
            }
            setup();
            // No refund address specified, no user-specified memo field.
            ListenableFuture<PaymentProtocol.Ack> future = session.sendPayment(ImmutableList.of(req.tx), null, null);
            if (future == null) {
                // No payment_url for submission so, broadcast and wait.
                peers.start();
                peers.broadcastTransaction(req.tx).future().get();
            } else {
                PaymentProtocol.Ack ack = future.get();
                wallet.commitTx(req.tx);
                System.out.println("Memo from server: " + ack.getMemo());
            }
        } catch (PaymentProtocolException e) {
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
            System.err.println("Insufficient funds: have " + wallet.getBalance().toFriendlyString());
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
                wallet.addCoinsReceivedEventListener(new WalletCoinsReceivedEventListener() {
                    @Override
                    public void onCoinsReceived(Wallet wallet, Transaction tx, Coin prevBalance, Coin newBalance) {
                        // Runs in a peer thread.
                        System.out.println(tx.getHashAsString());
                        latch.countDown();  // Wake up main thread.
                    }
                });
                wallet.addCoinsSentEventListener(new WalletCoinsSentEventListener() {
                    @Override
                    public void onCoinsSent(Wallet wallet, Transaction tx, Coin prevBalance, Coin newBalance) {
                        // Runs in a peer thread.
                        System.out.println(tx.getHashAsString());
                        latch.countDown();  // Wake up main thread.
                    }
                });
                break;

            case BLOCK:
                peers.addBlocksDownloadedEventListener(new BlocksDownloadedEventListener() {
                    @Override
                    public void onBlocksDownloaded(Peer peer, Block block, @Nullable FilteredBlock filteredBlock, int blocksLeft) {
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
                final WalletEventListener listener = new WalletEventListener(latch);
                wallet.addCoinsReceivedEventListener(listener);
                wallet.addCoinsSentEventListener(listener);
                wallet.addChangeEventListener(listener);
                wallet.addReorganizeEventListener(listener);
                break;

        }
        if (!peers.isRunning())
            peers.startAsync();
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
        boolean reset = !chainFileName.exists();
        if (reset) {
            // No chain, so reset the wallet as we will be downloading from scratch.
            System.out.println("Chain file is missing so resetting the wallet.");
            reset();
        }
        if (mode == ValidationMode.SPV) {
            store = new SPVBlockStore(params, chainFileName);
            chain = new BlockChain(params, wallet, store);
            if (reset) {
                try {
                    CheckpointManager.checkpoint(params, CheckpointManager.openStream(params), store,
                            wallet.getEarliestKeyCreationTime());
                    StoredBlock head = store.getChainHead();
                    System.out.println("Skipped to checkpoint " + head.getHeight() + " at "
                            + Utils.dateTimeFormat(head.getHeader().getTimeSeconds() * 1000));
                } catch (IOException x) {
                    System.out.println("Could not load checkpoints: " + x.getMessage());
                }
            }
        } else if (mode == ValidationMode.FULL) {
            FullPrunedBlockStore s = new H2FullPrunedBlockStore(params, chainFileName.getAbsolutePath(), 5000);
            store = s;
            chain = new FullPrunedBlockChain(params, wallet, s);
        }
        // This will ensure the wallet is saved when it changes.
        wallet.autosaveToFile(walletFile, 5, TimeUnit.SECONDS, null);
        if (options.has("tor")) {
            try {
                peers = PeerGroup.newWithTor(params, chain, new TorClient());
            } catch (TimeoutException e) {
                System.err.println("Tor startup timed out, falling back to clear net ...");
            }
        }
        if (peers == null) {
            peers = new PeerGroup(params, chain);
        }
        peers.setUserAgent("WalletTool", "1.0");
        if (params == RegTestParams.get())
            peers.setMinBroadcastConnections(1);
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
        } else if (!options.has("tor")) {
            peers.addPeerDiscovery(new DnsDiscovery(params));
        }
    }

    private static void syncChain() {
        try {
            setup();
            int startTransactions = wallet.getTransactions(true).size();
            DownloadProgressTracker listener = new DownloadProgressTracker();
            peers.start();
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
            if (peers.isRunning())
                peers.stop();
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
        long creationTimeSecs = getCreationTimeSeconds();
        if (creationTimeSecs == 0)
            creationTimeSecs = MnemonicCode.BIP39_STANDARDISATION_TIME_SECS;
        if (options.has(seedFlag)) {
            String seedStr = options.valueOf(seedFlag);
            DeterministicSeed seed;
            // Parse as mnemonic code.
            final List<String> split = ImmutableList.copyOf(Splitter.on(" ").omitEmptyStrings().split(seedStr));
            String passphrase = ""; // TODO allow user to specify a passphrase
            seed = new DeterministicSeed(split, null, passphrase, creationTimeSecs);
            try {
                seed.check();
            } catch (MnemonicException.MnemonicLengthException e) {
                System.err.println("The seed did not have 12 words in, perhaps you need quotes around it?");
                return;
            } catch (MnemonicException.MnemonicWordException e) {
                System.err.println("The seed contained an unrecognised word: " + e.badWord);
                return;
            } catch (MnemonicException.MnemonicChecksumException e) {
                System.err.println("The seed did not pass checksumming, perhaps one of the words is wrong?");
                return;
            } catch (MnemonicException e) {
                // not reached - all subclasses handled above
                throw new RuntimeException(e);
            }
            wallet = Wallet.fromSeed(params, seed);
        } else if (options.has(watchFlag)) {
            wallet = Wallet.fromWatchingKeyB58(params, options.valueOf(watchFlag), creationTimeSecs);
        } else {
            wallet = new Wallet(params);
        }
        if (password != null)
            wallet.encrypt(password);
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
        // If we're being given precise details, we have to import the key.
        if (options.has("privkey") || options.has("pubkey")) {
            importKey();
        } else {
            if (options.has(lookaheadSize)) {
                Integer size = options.valueOf(lookaheadSize);
                log.info("Setting keychain lookahead size to {}", size);
                wallet.setKeyChainGroupLookaheadSize(size);
            }
            ECKey key;
            try {
                key = wallet.freshReceiveKey();
            } catch (DeterministicUpgradeRequiredException e) {
                try {
                    KeyParameter aesKey = passwordToKey(false);
                    wallet.upgradeToDeterministic(aesKey);
                } catch (DeterministicUpgradeRequiresPassword e2) {
                    System.err.println("This wallet must be upgraded to be deterministic, but it's encrypted: please supply the password and try again.");
                    return;
                }
                key = wallet.freshReceiveKey();
            }
            System.out.println(key.toAddress(params) + " " + key);
        }
    }

    @Nullable
    private static KeyParameter passwordToKey(boolean printError) {
        if (password == null) {
            if (printError)
                System.err.println("You must provide a password.");
            return null;
        }
        if (!wallet.checkPassword(password)) {
            if (printError)
                System.err.println("The password is incorrect.");
            return null;
        }
        return checkNotNull(wallet.getKeyCrypter()).deriveKey(password);
    }

    private static void importKey() {
        ECKey key;
        long creationTimeSeconds = getCreationTimeSeconds();
        if (options.has("privkey")) {
            String data = (String) options.valueOf("privkey");
            if (data.startsWith("5J") || data.startsWith("5H") || data.startsWith("5K")) {
                DumpedPrivateKey dpk;
                try {
                    dpk = DumpedPrivateKey.fromBase58(params, data);
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
                key = ECKey.fromPrivate(new BigInteger(1, decode));
            }
            if (options.has("pubkey")) {
                // Give the user a hint.
                System.out.println("You don't have to specify --pubkey when a private key is supplied.");
            }
            key.setCreationTimeSeconds(creationTimeSeconds);
        } else if (options.has("pubkey")) {
            byte[] pubkey = Utils.parseAsHexOrBase58((String) options.valueOf("pubkey"));
            key = ECKey.fromPublicOnly(pubkey);
            key.setCreationTimeSeconds(creationTimeSeconds);
        } else {
            throw new IllegalStateException();
        }
        if (wallet.findKeyFromPubKey(key.getPubKey()) != null) {
            System.err.println("That key already exists in this wallet.");
            return;
        }
        try {
            if (wallet.isEncrypted()) {
                KeyParameter aesKey = passwordToKey(true);
                if (aesKey == null)
                    return;   // Error message already printed.
                key = key.encrypt(checkNotNull(wallet.getKeyCrypter()), aesKey);
            }
            wallet.importKey(key);
            System.out.println(key.toAddress(params) + " " + key);
        } catch (KeyCrypterException kce) {
            System.err.println("There was an encryption related error when adding the key. The error was '" + kce.getMessage() + "'.");
        }
    }

    private static long getCreationTimeSeconds() {
        if (options.has(unixtimeFlag))
            return unixtimeFlag.value(options);
        else if (options.has(dateFlag))
            return dateFlag.value(options).getTime() / 1000;
        else
            return 0;
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
                Address address = Address.fromBase58(wallet.getParams(), addr);
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

    private static void currentReceiveAddr() {
        ECKey key = wallet.currentReceiveKey();
        System.out.println(key.toAddress(params) + " " + key);
    }

    private static void dumpWallet() throws BlockStoreException {
        // Setup to get the chain height so we can estimate lock times, but don't wipe the transactions if it's not
        // there just for the dump case.
        if (chainFileName.exists())
            setup();
        System.out.println(wallet.toString(options.has("dump-privkeys"), true, true, chain));
    }

    private static void setCreationTime() {
        DeterministicSeed seed = wallet.getActiveKeyChain().getSeed();
        if (seed == null) {
            System.err.println("Active chain does not have a seed.");
            return;
        }
        long creationTime = getCreationTimeSeconds();
        if (creationTime > 0)
            System.out.println("Setting creation time to: " + Utils.dateTimeFormat(creationTime * 1000));
        else
            System.out.println("Clearing creation time.");
        seed.setCreationTimeSeconds(creationTime);
    }

    static synchronized void onChange(final CountDownLatch latch) {
        saveWallet(walletFile);
        Coin balance = wallet.getBalance(Wallet.BalanceType.ESTIMATED);
        if (condition.matchBitcoins(balance)) {
            System.out.println(balance.toFriendlyString());
            latch.countDown();
        }
    }

    private static class WalletEventListener implements WalletChangeEventListener, WalletCoinsReceivedEventListener,
            WalletCoinsSentEventListener, WalletReorganizeEventListener {
        private final CountDownLatch latch;

        private  WalletEventListener(final CountDownLatch latch) {
            this.latch = latch;
        }

        @Override
        public void onWalletChanged(Wallet wallet) {
            onChange(latch);
        }

        @Override
        public void onCoinsReceived(Wallet wallet, Transaction tx, Coin prevBalance, Coin newBalance) {
            onChange(latch);
        }

        @Override
        public void onCoinsSent(Wallet wallet, Transaction tx, Coin prevBalance, Coin newBalance) {
            onChange(latch);
        }

        @Override
        public void onReorganize(Wallet wallet) {
            onChange(latch);
        }
    }
}
