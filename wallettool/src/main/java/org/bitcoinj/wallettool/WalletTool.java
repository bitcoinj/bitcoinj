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

package org.bitcoinj.wallettool;

import com.google.protobuf.ByteString;
import org.bitcoinj.base.Address;
import org.bitcoinj.base.Base58;
import org.bitcoinj.base.BitcoinNetwork;
import org.bitcoinj.base.Coin;
import org.bitcoinj.base.LegacyAddress;
import org.bitcoinj.base.Network;
import org.bitcoinj.base.ScriptType;
import org.bitcoinj.base.Sha256Hash;
import org.bitcoinj.base.exceptions.AddressFormatException;
import org.bitcoinj.base.internal.ByteUtils;
import org.bitcoinj.base.internal.TimeUtils;
import org.bitcoinj.core.AbstractBlockChain;
import org.bitcoinj.core.BlockChain;
import org.bitcoinj.core.CheckpointManager;
import org.bitcoinj.core.Context;
import org.bitcoinj.core.InsufficientMoneyException;
import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.core.Peer;
import org.bitcoinj.core.PeerAddress;
import org.bitcoinj.core.PeerGroup;
import org.bitcoinj.core.StoredBlock;
import org.bitcoinj.core.Transaction;
import org.bitcoinj.core.VerificationException;
import org.bitcoinj.core.listeners.DownloadProgressTracker;
import org.bitcoinj.crypto.AesKey;
import org.bitcoinj.crypto.DumpedPrivateKey;
import org.bitcoinj.crypto.ECKey;
import org.bitcoinj.crypto.KeyCrypterException;
import org.bitcoinj.crypto.MnemonicCode;
import org.bitcoinj.crypto.MnemonicException;
import org.bitcoinj.protobuf.wallet.Protos;
import org.bitcoinj.script.ScriptException;
import org.bitcoinj.store.BlockStore;
import org.bitcoinj.store.BlockStoreException;
import org.bitcoinj.store.SPVBlockStore;
import org.bitcoinj.utils.BriefLogFormatter;
import org.bitcoinj.wallet.CoinSelector;
import org.bitcoinj.wallet.DeterministicKeyChain;
import org.bitcoinj.wallet.DeterministicSeed;
import org.bitcoinj.wallet.KeyChainGroupStructure;
import org.bitcoinj.wallet.SendRequest;
import org.bitcoinj.wallet.UnreadableWalletException;
import org.bitcoinj.wallet.Wallet;
import org.bitcoinj.wallet.Wallet.BalanceType;
import org.bitcoinj.wallet.WalletProtobufSerializer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import picocli.CommandLine;

import javax.annotation.Nullable;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.text.ParseException;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.Callable;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.function.Consumer;
import java.util.logging.Level;
import java.util.logging.LogManager;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.bitcoinj.base.Coin.parseCoin;

/**
 * A command line tool for manipulating wallets and working with Bitcoin.
 */
@CommandLine.Command(name = "wallet-tool", usageHelpAutoWidth = true, sortOptions = false, description = "Print and manipulate wallets.",subcommands = {CommandLine.HelpCommand.class})
public class WalletTool implements Callable<Integer> {

    private String actionStr;
    @CommandLine.Option(names = "--net", description = "Which network to connect to. Valid values: ${COMPLETION-CANDIDATES}. Default: ${DEFAULT-VALUE}")
    private static BitcoinNetwork net = BitcoinNetwork.MAINNET;
    @CommandLine.Option(names = "--debuglog", description = "Enables logging from the core library.")
    private static boolean debugLog = false;
    @CommandLine.Option(names = "--force", description = "Overrides any safety checks on the requested action.")
    private boolean force = false;
    @CommandLine.Option(names = "--wallet", description = "Specifies what wallet file to load and save.")
    private static File walletFile = null;
    @CommandLine.Option(names = "--seed", description = "Specifies either a mnemonic code or hex/base58 raw seed bytes.")
    private String seedStr = null;
    @CommandLine.Option(names = "--watchkey", description = "Describes a watching wallet using the specified base58 xpub.")
    private String watchKeyStr = null;
    @CommandLine.Option(names = "--output-script-type", description = "Provide an output script type to any action that requires one. Valid values: P2PKH, P2WPKH. Default: ${DEFAULT-VALUE}")
    private ScriptType outputScriptType = ScriptType.P2PKH;
    @CommandLine.Option(names = "--date", description = "Provide a date in form YYYY-MM-DD to any action that requires one.")
    private LocalDate date = null;
    @CommandLine.Option(names = "--unixtime", description = "Provide a date in seconds since epoch.")
    private Long unixtime = null;
    @CommandLine.Option(names = "--waitfor", description = "You can wait for the condition specified by the --waitfor flag to become true. Transactions and new blocks will be processed during this time. When the waited for condition is met, the tx/block hash will be printed. Waiting occurs after the --action is performed, if any is specified. Valid values:%n" +
            "EVER       Never quit.%n" +
            "WALLET_TX  Any transaction that sends coins to or from the wallet.%n" +
            "BLOCK      A new block that builds on the best chain.%n" +
            "BALANCE    Waits until the wallets balance meets the --condition.")
    private WaitForEnum waitFor = null;
    @CommandLine.Option(names = "--filter", description = "Use filter when synching the chain. Valid values: ${COMPLETION-CANDIDATES}. Default: ${DEFAULT-VALUE}")
    private Filter filter = Filter.SERVER;
    @CommandLine.Option(names = "--chain", description = "Specifies the name of the file that stores the block chain.")
    private static File chainFile = null;
    @CommandLine.Option(names = "--pubkey", description = "Specifies a hex/base58 encoded non-compressed public key.")
    private String pubKeyStr;
    @CommandLine.Option(names = "--privkey", description = "Specifies a WIF-, hex- or base58-encoded private key.")
    private String privKeyStr;
    @CommandLine.Option(names = "--addr", description = "Specifies a Bitcoin address, either segwit or legacy.")
    private String addrStr;
    @CommandLine.Option(names = "--peers", description = "Comma separated IP addresses/domain names for connections instead of peer discovery.")
    private String peersStr;
    @CommandLine.Option(names = "--xpubkeys", description = "Specifies external public keys.")
    private String xpubKeysStr;
    @CommandLine.Option(names = "--select-addr", description = "When sending, only pick coins from this address.")
    private String selectAddrStr;
    @CommandLine.Option(names = "--select-output", description = "When sending, only pick coins from this output.")
    private String selectOutputStr;
    @CommandLine.Option(names = "--output", description = "Creates an output with the specified amount, separated by a colon. The special amount ALL is used to use the entire balance.")
    private List<String> outputsStr;
    @CommandLine.Option(names = "--fee-per-vkb", description = "Sets the network fee in Bitcoin per kilobyte when sending, e.g. --fee-per-vkb=0.0005")
    private String feePerVkbStr;
    @CommandLine.Option(names = "--fee-sat-per-vbyte", description = "Sets the network fee in satoshi per byte when sending, e.g. --fee-sat-per-vbyte=50")
    private String feeSatPerVbyteStr;
    @CommandLine.Option(names = "--condition", description = "Allows you to specify a numeric condition for other commands. The format is one of the following operators = < > <= >= immediately followed by a number.%nExamples: --condition=\">5.10\" or --condition=\"<=1\"")
    private static String conditionStr = null;
    @CommandLine.Option(names = "--locktime", description = "Specifies a lock-time either by date or by block number.")
    private String lockTimeStr;
    @CommandLine.Option(names = "--allow-unconfirmed", description = "Lets you create spends of pending non-change outputs.")
    private boolean allowUnconfirmed = false;
    @CommandLine.Option(names = "--offline", description = "If specified when sending, don't try and connect, just write the tx to the wallet.")
    private boolean offline = false;
    @CommandLine.Option(names = "--ignore-mandatory-extensions", description = "If a wallet has unknown required extensions that would otherwise cause load failures, this overrides that.")
    private static boolean ignoreMandatoryExtensions = false;
    @CommandLine.Option(names = "--password", description = "For an encrypted wallet, the password is provided here.")
    private String password = null;
    @CommandLine.Option(names = "--no-pki", description = "Disables pki verification for payment requests.")
    private boolean noPki = false;
    @CommandLine.Option(names = "--dump-privkeys", description = "Private keys and seed are printed.")
    private boolean dumpPrivKeys = false;
    @CommandLine.Option(names = "--dump-lookahead", description = "Show pregenerated but not yet issued keys.")
    private boolean dumpLookAhead = false;
    @CommandLine.Option(names = "--help", usageHelp = true, description = "Displays program options.")
    private boolean help;

    private static final Logger log = LoggerFactory.getLogger(WalletTool.class);

    private static NetworkParameters params;
    private static BlockStore store;
    private static AbstractBlockChain chain;
    private static PeerGroup peerGroup;
    private static Wallet wallet;

    public class Descriptions {
        public static final String OPTION_NET = "Specifies the Bitcoin network to use. Valid values: mainnet, testnet, regtest.";
        public static final String OPTION_SEED = "Specifies a mnemonic code or raw seed in hex/base58 raw seed bytes.";
        public static final String OPTION_WATCHKEY = "If present, creates a watching wallet using the specified base58 xpub.";
        public static final String OPTION_DATE = "Wallet creation date formatted as YYYY-MM-DD.";
        public static final String OPTION_UNIXTIME = "Wallet creation time in Unix timestamp format.";
        public static final String OPTION_OUTPUT_SCRIPT_TYPE = "Use this for deriving addresses. Valid values: P2PKH, P2WPKH. Default: P2WPKH.";
        public static final String OPTION_FORCE = "Overwrites any existing wallet file.";
        public static final String OPTION_DEBUGLOG = "Enable debug logging.";
        public static final String OPTION_CHAIN = "Path to the chain file.";
        public static final String OPTION_CONDITION = "Additional conditions to apply.";
        public static final String PARAMETER_WALLET_FILE = "Path to the wallet file to create.";

        //SUBCOMMAND DESCRIPTIONS
        public static final String SUBCOMMAND_CREATE = "Makes a new wallet in the file specified by --wallet. Will complain and require --force if the wallet already exists.Creates a new wallet in the specified file. This command supports deterministic wallet seeds, watch-only wallets, and various configurations like timestamps and address derivation types. If `--seed` or `--watchkey` is combined with either `--date` or `--unixtime`, use that as a birthdate for the wallet. If neither `--seed` nor `--watchkey` is provided, create will generate a wallet with a newly generated random seed.";
    }

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
        ENCRYPT,
        DECRYPT,
        UPGRADE,
        ROTATE,
        SET_CREATION_TIME,
    }

    public enum WaitForEnum {
        EVER,
        WALLET_TX,
        BLOCK,
        BALANCE
    }

    public enum Filter {
        NONE,
        SERVER, // bloom filter
    }

    public static void main(String[] args) {
        int exitCode = new CommandLine(new WalletTool()).execute(args);
        System.exit(exitCode);
    }

    public static void initLogger(boolean debugLog){
        if (debugLog) {
            BriefLogFormatter.init();
            log.info("Starting up ...");
        } else {
            // Disable logspam unless there is a flag.
            java.util.logging.Logger logger = LogManager.getLogManager().getLogger("");
            logger.setLevel(Level.SEVERE);
        }
    }

    private static int initWallet(boolean forceReset, File walletFile){
        try {
            wallet = Wallet.loadFromFile(walletFile, WalletProtobufSerializer.WalletFactory.DEFAULT, forceReset, ignoreMandatoryExtensions);
        } catch (UnreadableWalletException e) {
            System.err.println("Failed to load wallet '" + walletFile + "': " + e.getMessage());
            e.printStackTrace();
            return 1;
        }
        return 0;
    }

    private static void initNetworkParameter(BitcoinNetwork net) {
        if (net != null){
            params = NetworkParameters.of(net);
            WalletTool.net = net;
        }else{
            WalletTool.net = (BitcoinNetwork) wallet.network();
            params = NetworkParameters.of(WalletTool.net);
        }
    }

    private static void initChainFile(File chainFile) {
        String fileName = String.format("%s.chain", WalletTool.net);
        if (chainFile == null) {
            WalletTool.chainFile = new File(fileName);
        }
    }

    private static void initCondition(String conditionStr) {
        if (conditionStr != null) {
            condition = new Condition(conditionStr);
        }
    }

    private static int checkWalletFileExists(){
        if (!walletFile.exists()) {
            System.err.println("Specified wallet file " + walletFile + " does not exist. Try wallet-tool --wallet=" + walletFile + " create");
            return 1;
        }
        return 0;
    }

    @Override
    public Integer call() throws IOException, BlockStoreException {


       return 0;
    }

    private int cleanUp(){
        if (!wallet.isConsistent()) {
            System.err.println("************** WALLET IS INCONSISTENT *****************");
            return 10;
        }

        saveWallet(walletFile);

        if (waitFor != null) {
            try {
                setup();
            } catch (BlockStoreException e) {
                throw new RuntimeException(e);
            }
            CompletableFuture<String> futureMessage = wait(waitFor, condition);
            if (!peerGroup.isRunning())
                peerGroup.startAsync();
            System.out.println(futureMessage.join());
            if (!wallet.isConsistent()) {
                System.err.println("************** WALLET IS INCONSISTENT *****************");
                return 10;
            }
            saveWallet(walletFile);
        }
        shutdown();

        return 0;
    }

    private static Protos.Wallet attemptHexConversion(Protos.Wallet proto) {
        // Try to convert any raw hashes and such to textual equivalents for easier debugging. This makes it a bit
        // less "raw" but we will just abort on any errors.
        try {
            Protos.Wallet.Builder builder = proto.toBuilder();
            for (Protos.Transaction tx : builder.getTransactionList()) {
                Protos.Transaction.Builder txBuilder = tx.toBuilder();
                txBuilder.setHash(bytesToHex(txBuilder.getHash()));
                for (int i = 0; i < txBuilder.getBlockHashCount(); i++)
                    txBuilder.setBlockHash(i, bytesToHex(txBuilder.getBlockHash(i)));
                for (Protos.TransactionInput input : txBuilder.getTransactionInputList()) {
                    Protos.TransactionInput.Builder inputBuilder = input.toBuilder();
                    inputBuilder.setTransactionOutPointHash(bytesToHex(inputBuilder.getTransactionOutPointHash()));
                }
                for (Protos.TransactionOutput output : txBuilder.getTransactionOutputList()) {
                    Protos.TransactionOutput.Builder outputBuilder = output.toBuilder();
                    if (outputBuilder.hasSpentByTransactionHash())
                        outputBuilder.setSpentByTransactionHash(bytesToHex(outputBuilder.getSpentByTransactionHash()));
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
        return ByteString.copyFrom(ByteUtils.formatHex(bytes.toByteArray()).getBytes());
    }

    private int upgrade() {
        initLogger(debugLog);
        initChainFile(chainFile);

        Context.propagate(new Context());

        initCondition(conditionStr);
        checkWalletFileExists();
        initWallet(false, walletFile);
        initNetworkParameter(net);

        DeterministicKeyChain activeKeyChain = wallet.getActiveKeyChain();
        ScriptType currentOutputScriptType = activeKeyChain != null ? activeKeyChain.getOutputScriptType() : null;
        if (!wallet.isDeterministicUpgradeRequired(outputScriptType)) {
            System.err
                    .println("No upgrade from " + (currentOutputScriptType != null ? currentOutputScriptType : "basic")
                            + " to " + outputScriptType);
            return 1;
        }
        AesKey aesKey = null;
        if (wallet.isEncrypted()) {
            aesKey = passwordToKey(true);
            if (aesKey == null)
                return 1;
        }
        wallet.upgradeToDeterministic(outputScriptType, aesKey);
        System.out.println("Upgraded from " + (currentOutputScriptType != null ? currentOutputScriptType : "basic")
                + " to " + outputScriptType);
        cleanUp();
        return 0;
    }

    private int rotate() throws BlockStoreException {
        initLogger(debugLog);
        initNetworkParameter(net);
        initChainFile(chainFile);

        Context.propagate(new Context());

        initCondition(conditionStr);
        checkWalletFileExists();
        setup();
        peerGroup.start();
        // Set a key rotation time and possibly broadcast the resulting maintenance transactions.
        Instant rotationTime = TimeUtils.currentTime();
        if (date != null) {
            rotationTime = Instant.from(date);
        } else if (unixtime != null) {
            rotationTime = Instant.ofEpochSecond(unixtime);
        }
        log.info("Setting wallet key rotation time to {}", TimeUtils.dateTimeFormat(rotationTime));
        wallet.setKeyRotationTime(rotationTime);
        AesKey aesKey = null;
        if (wallet.isEncrypted()) {
            aesKey = passwordToKey(true);
            if (aesKey == null)
                return 1;
        }
        wallet.doMaintenance(aesKey, true).join();
        cleanUp();
        return 0;
    }

    private int encrypt() {
        initLogger(debugLog);
        initNetworkParameter(net);
        initChainFile(chainFile);

        Context.propagate(new Context());

        initCondition(conditionStr);
        checkWalletFileExists();
        if (password == null) {
            System.err.println("You must provide a --password");
            return 1;
        }
        if (wallet.isEncrypted()) {
            System.err.println("This wallet is already encrypted.");
            return 1;
        }
        wallet.encrypt(password);
        cleanUp();
        return 0;
    }

    private int decrypt() {
        initLogger(debugLog);
        initNetworkParameter(net);
        initChainFile(chainFile);

        Context.propagate(new Context());

        initCondition(conditionStr);
        checkWalletFileExists();
        if (password == null) {
            System.err.println("You must provide a --password");
            return 1;
        }
        if (!wallet.isEncrypted()) {
            System.err.println("This wallet is not encrypted.");
            return 1;
        }
        try {
            wallet.decrypt(password);
        } catch (KeyCrypterException e) {
            System.err.println("Password incorrect.");
            return 1;
        }
        cleanUp();
        return 0;
    }

    private int addAddr() {
        initLogger(debugLog);
        initNetworkParameter(net);
        initChainFile(chainFile);

        Context.propagate(new Context());

        initCondition(conditionStr);
        checkWalletFileExists();
        if (addrStr == null) {
            System.err.println("You must specify an --addr to watch.");
            return 1;
        }
        try {
            Address address = LegacyAddress.fromBase58(addrStr, net);
            // If no creation time is specified, assume genesis (zero).
            getCreationTime(date,unixtime).ifPresentOrElse(
                    creationTime -> wallet.addWatchedAddress(address, creationTime),
                    () -> wallet.addWatchedAddress(address));
        } catch (AddressFormatException e) {
            System.err.println("Could not parse given address, or wrong network: " + addrStr);
        }
        cleanUp();
        return 0;
    }

    private void send(CoinSelector coinSelector, List<String> outputs, Coin feePerVkb, String lockTimeStr,
                      boolean allowUnconfirmed)
            throws VerificationException {
        Coin balance = coinSelector != null ? wallet.getBalance(coinSelector) : wallet.getBalance(allowUnconfirmed ?
                BalanceType.ESTIMATED : BalanceType.AVAILABLE);
        // Convert the input strings to outputs.
        Transaction tx = new Transaction();
        for (String spec : outputs) {
            try {
                OutputSpec outputSpec = new OutputSpec(spec);
                Coin value = outputSpec.value != null ? outputSpec.value : balance;
                if (outputSpec.isAddress())
                    tx.addOutput(value, outputSpec.addr);
                else
                    tx.addOutput(value, outputSpec.key);
            } catch (AddressFormatException.WrongNetwork e) {
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
        boolean emptyWallet = tx.getOutputs().size() == 1 && tx.getOutput(0).getValue().equals(balance);
        if (emptyWallet) {
            log.info("Emptying out wallet, recipient may get less than what you expect");
        }

        AesKey aesKey;
        if (password != null) {
            aesKey = passwordToKey(true);
            if (aesKey == null)
                return;  // Error message already printed.
        } else {
            aesKey = null;
        }

        SendRequest req = buildSendRequest(tx, emptyWallet, allowUnconfirmed, coinSelector, feePerVkb, aesKey);

        try {
            wallet.completeTx(req);
        } catch (InsufficientMoneyException e) {
            System.err.println("Insufficient funds: have " + balance.toFriendlyString());
        }

        try {
            if (lockTimeStr != null) {
                tx.setLockTime(parseLockTimeStr(lockTimeStr));
                // For lock times to take effect, at least one output must have a non-final sequence number.
                tx.replaceInput(0, tx.getInput(0).withSequence(0));
                // And because we modified the transaction after it was completed, we must re-sign the inputs.
                wallet.signTransaction(req);
            }
        } catch (ParseException e) {
            System.err.println("Could not understand --locktime of " + lockTimeStr);
            return;
        } catch (ScriptException e) {
            throw new RuntimeException(e);
        }
        System.out.println("id: " + tx.getTxId());
        System.out.println("tx: " + ByteUtils.formatHex(tx.serialize()));
        if (offline) {
            wallet.commitTx(tx);
            return;
        }

        try {
            setup();
            peerGroup.start();
        } catch (BlockStoreException e) {
            throw new RuntimeException(e);
        }

        try {
            // Wait for peers to connect, the tx to be sent to one of them and for it to be propagated across the
            // network. Once propagation is complete and we heard the transaction back from all our peers, it will
            // be committed to the wallet.
            peerGroup.broadcastTransaction(tx).awaitRelayed().get();
            // Hack for regtest/single peer mode, as we're about to shut down and won't get an ACK from the remote end.
            List<Peer> peerList = peerGroup.getConnectedPeers();
            if (peerList.size() == 1)
                peerList.get(0).sendPing().get();
        } catch (ExecutionException | InterruptedException e) {
            throw new RuntimeException(e);
        }
    }

    // "Atomically" create a SendRequest. In the future SendRequest may be immutable and this method will be updated
    private SendRequest buildSendRequest(Transaction tx, boolean emptyWallet, boolean allowUnconfirmed, @Nullable CoinSelector coinSelector, @Nullable Coin feePerVkb, @Nullable AesKey aesKey) {
        SendRequest req = SendRequest.forTx(tx);
        req.emptyWallet = emptyWallet;
        if (coinSelector != null) {
            req.coinSelector = coinSelector;
            req.recipientsPayFees = true;
        }
        if (allowUnconfirmed) {
            // Note that this will overwrite the CoinSelector set above
            req.allowUnconfirmed();
        }
        if (feePerVkb != null)
            req.setFeePerVkb(feePerVkb);
        req.aesKey = aesKey;
        return req;
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
                value = null;
            else
                value = parseCoin(parts[1]);
            if (destination.startsWith("0")) {
                // Treat as a raw public key.
                byte[] pubKey = new BigInteger(destination, 16).toByteArray();
                key = ECKey.fromPublicOnly(pubKey);
                addr = null;
            } else {
                // Treat as an address.
                addr = wallet.parseAddress(destination);
                key = null;
            }
        }

        public boolean isAddress() {
            return addr != null;
        }
    }

    /**
     * Parses the string either as a whole number of blocks, or if it contains slashes as a YYYY/MM/DD format date
     * and returns the lock time in wire format.
     */
    private static long parseLockTimeStr(String lockTimeStr) throws ParseException {
        if (lockTimeStr.contains("/")) {
            Instant time = Instant.from(DateTimeFormatter.ofPattern("yyyy/MM/dd").parse(lockTimeStr));
            return time.getEpochSecond();
        }
        return Long.parseLong(lockTimeStr);
    }

    /**
     * Wait for a condition to be satisfied
     *
     * @param waitFor   condition type to wait for
     * @param condition balance condition to wait for
     * @return A (future) human-readable message (txId, block hash, or balance) to display when wait is complete
     */
    private CompletableFuture<String> wait(WaitForEnum waitFor, Condition condition) {
        CompletableFuture<String> future = new CompletableFuture<>();
        switch (waitFor) {
            case EVER:
                break;  // Future will never complete

            case WALLET_TX:
                // Future will complete with a transaction ID string
                Consumer<Transaction> txListener = tx -> future.complete(tx.getTxId().toString());
                // Both listeners run in a peer thread
                wallet.addCoinsReceivedEventListener((wallet, tx, prevBalance, newBalance) -> txListener.accept(tx));
                wallet.addCoinsSentEventListener((wallet, tx, prevBalance, newBalance) -> txListener.accept(tx));
                break;

            case BLOCK:
                // Future will complete with a Block hash string
                peerGroup.addBlocksDownloadedEventListener((peer, block, filteredBlock, blocksLeft) ->
                    future.complete(block.getHashAsString())
                );
                break;

            case BALANCE:
                // Future will complete with a balance amount string
                // Check if the balance already meets the given condition.
                Coin existingBalance = wallet.getBalance(Wallet.BalanceType.ESTIMATED);
                if (condition.matchBitcoins(existingBalance)) {
                    future.complete(existingBalance.toFriendlyString());
                } else {
                    Runnable onChange = () -> {
                        synchronized (this) {
                            saveWallet(walletFile);
                            Coin balance = wallet.getBalance(Wallet.BalanceType.ESTIMATED);
                            if (condition.matchBitcoins(balance)) {
                                future.complete(balance.toFriendlyString());
                            }
                        }
                    };
                    wallet.addCoinsReceivedEventListener((w, t, p, n) -> onChange.run());
                    wallet.addCoinsSentEventListener((w, t, p, n) -> onChange.run());
                    wallet.addChangeEventListener(w -> onChange.run());
                    wallet.addReorganizeEventListener(w -> onChange.run());
                }
                break;
        }
        return future;
    }

    private int reset() {
        initLogger(debugLog);

        initChainFile(chainFile);

        Context.propagate(new Context());

        initCondition(conditionStr);
        checkWalletFileExists();
        initWallet(true, walletFile);
        initNetworkParameter(net); // TODO : we want to initialize wallet before we derive network for all other subcommands.
        // Delete the transactions and save. In future, reset the chain head pointer.
        wallet.clearTransactions(0);
        saveWallet(walletFile);
        cleanUp();
        return 0;
    }

    // Sets up all objects needed for network communication but does not bring up the peers.
    private void setup() throws BlockStoreException {
        if (store != null) return;  // Already done.
        // Will create a fresh chain if one doesn't exist or there is an issue with this one.
        boolean reset = !chainFile.exists();
        if (reset) {
            // No chain, so reset the wallet as we will be downloading from scratch.
            System.out.println("Chain file is missing so resetting the wallet.");
            reset();
        }
        store = new SPVBlockStore(params, chainFile);
        if (reset) {
            try {
                CheckpointManager.checkpoint(params, CheckpointManager.openStream(params), store,
                        wallet.earliestKeyCreationTime());
                StoredBlock head = store.getChainHead();
                System.out.println("Skipped to checkpoint " + head.getHeight() + " at "
                        + TimeUtils.dateTimeFormat(head.getHeader().time()));
            } catch (IOException x) {
                System.out.println("Could not load checkpoints: " + x.getMessage());
            }
        }
        chain = new BlockChain(net, wallet, store);
        // This will ensure the wallet is saved when it changes.
        wallet.autosaveToFile(walletFile, Duration.ofSeconds(5), null);
        if (peerGroup == null) {
            peerGroup = new PeerGroup(net, chain);
        }
        peerGroup.setUserAgent("WalletTool", "1.0");
        if (net == BitcoinNetwork.REGTEST) {
            peerGroup.addAddress(PeerAddress.localhost(params));
            peerGroup.setMinBroadcastConnections(1);
            peerGroup.setMaxConnections(1);
        }
        peerGroup.addWallet(wallet);
        peerGroup.setBloomFilteringEnabled(filter == Filter.SERVER);
        if (peersStr != null) {
            String[] peerAddrs = peersStr.split(",");
            for (String peer : peerAddrs) {
                try {
                    peerGroup.addAddress(PeerAddress.simple(InetAddress.getByName(peer), params.getPort()));
                } catch (UnknownHostException e) {
                    System.err.println("Could not understand peer domain name/IP address: " + peer + ": " + e.getMessage());
                    System.exit(1);
                }
            }
        } else {
            peerGroup.setRequiredServices(0);
        }
    }

    private int syncChain() {
        initLogger(debugLog);
        initNetworkParameter(net);
        initChainFile(chainFile);

        Context.propagate(new Context());

        initCondition(conditionStr);
        checkWalletFileExists();
        initWallet(force, walletFile);

        try {
            setup();
            int startTransactions = wallet.getTransactions(true).size();
            DownloadProgressTracker listener = new DownloadProgressTracker();
            peerGroup.start();
            peerGroup.startBlockChainDownload(listener);
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
            System.err.println("Error reading block chain file " + chainFile + ": " + e.getMessage());
            e.printStackTrace();
            return 1;
        }
        cleanUp();
        return 0;
    }

    private void shutdown() {
        try {
            if (peerGroup == null) return;  // setup() never called so nothing to do.
            if (peerGroup.isRunning())
                peerGroup.stop();
            saveWallet(walletFile);
            store.close();
            wallet = null;
        } catch (BlockStoreException e) {
            throw new RuntimeException(e);
        }
    }

    @CommandLine.Command(name = "create" , description=Descriptions.SUBCOMMAND_CREATE)
    private int createWallet(
            @CommandLine.Option(names = "--net", description = Descriptions.OPTION_NET, defaultValue = "testnet") BitcoinNetwork network,
            @CommandLine.Option(names = "--seed", description = Descriptions.OPTION_SEED) String seedStr,
            @CommandLine.Option(names = "--watchkey", description = Descriptions.OPTION_WATCHKEY) String watchKeyStr,
            @CommandLine.Option(names = "--date", description = Descriptions.OPTION_DATE) LocalDate date,
            @CommandLine.Option(names = "--unixtime", description = Descriptions.OPTION_UNIXTIME) Long unixtime,
            @CommandLine.Option(names = "--output-script-type", description = Descriptions.OPTION_OUTPUT_SCRIPT_TYPE, defaultValue = "P2PKH") ScriptType outputScriptType,
            @CommandLine.Option(names = "--force", description = Descriptions.OPTION_FORCE) boolean force,
            @CommandLine.Option(names = "--debuglog", description = Descriptions.OPTION_DEBUGLOG) boolean debugLog,
            @CommandLine.Option(names = "--chain", description = Descriptions.OPTION_CHAIN) File chainFile,
            @CommandLine.Option(names = "--condition", description = Descriptions.OPTION_CONDITION) String conditionStr,
            @CommandLine.Parameters(index = "0", paramLabel = "<wallet-file>", description = Descriptions.PARAMETER_WALLET_FILE) File walletFile) throws IOException {
        initLogger(debugLog);
        initNetworkParameter(network);
        initChainFile(chainFile);

        Context.propagate(new Context());

        initCondition(conditionStr);

        KeyChainGroupStructure keyChainGroupStructure = KeyChainGroupStructure.BIP32;

        if (walletFile.exists() && !force) {
            System.err.println("Wallet creation requested but " + walletFile + " already exists, use --force");
            return 1;
        }
        Instant creationTime = getCreationTime(date,unixtime).orElse(MnemonicCode.BIP39_STANDARDISATION_TIME);
        if (seedStr != null) {
            DeterministicSeed seed;
            // Parse as mnemonic code.
            final List<String> split = splitMnemonic(seedStr);
            String passphrase = ""; // TODO allow user to specify a passphrase
            seed = DeterministicSeed.ofMnemonic(split, passphrase, creationTime);
            try {
                seed.check();
            } catch (MnemonicException.MnemonicLengthException e) {
                System.err.println("The seed did not have 12 words in, perhaps you need quotes around it?");
                return 1;
            } catch (MnemonicException.MnemonicWordException e) {
                System.err.println("The seed contained an unrecognised word: " + e.badWord);
                return 1;
            } catch (MnemonicException.MnemonicChecksumException e) {
                System.err.println("The seed did not pass checksumming, perhaps one of the words is wrong?");
                return 1;
            } catch (MnemonicException e) {
                // not reached - all subclasses handled above
                throw new RuntimeException(e);
            }
            wallet = Wallet.fromSeed(network, seed, outputScriptType, keyChainGroupStructure);
        } else if (watchKeyStr != null) {
            wallet = Wallet.fromWatchingKeyB58(network, watchKeyStr, creationTime);
        } else {
            wallet = Wallet.createDeterministic(network, outputScriptType, keyChainGroupStructure);
        }
        if (password != null)
            wallet.encrypt(password);
        wallet.saveToFile(walletFile);
        return 0;
    }

    private List<String> splitMnemonic(String seedStr) {
        return Stream.of(seedStr.split("[ :;,]")) // anyOf(" :;,")
                .filter(s -> !s.isEmpty())
                .collect(Collectors.toUnmodifiableList());
    }

    private void saveWallet(File walletFile) {
        try {
            // This will save the new state of the wallet to a temp file then rename, in case anything goes wrong.
            wallet.saveToFile(walletFile);
        } catch (IOException e) {
            System.err.println("Failed to save wallet! Old wallet should be left untouched.");
            e.printStackTrace();
            System.exit(1);
        }
    }

    private int addKey() {
        initLogger(debugLog);
        initNetworkParameter(net);
        initChainFile(chainFile);

        Context.propagate(new Context());

        initCondition(conditionStr);
        checkWalletFileExists();

        ECKey key;
        Optional<Instant> creationTime = getCreationTime(date,unixtime);
        if (privKeyStr != null) {
            try {
                DumpedPrivateKey dpk = DumpedPrivateKey.fromBase58(net, privKeyStr); // WIF
                key = dpk.getKey();
            } catch (AddressFormatException e) {
                byte[] decode = parseAsHexOrBase58(privKeyStr);
                if (decode == null) {
                    System.err.println("Could not understand --privkey as either WIF, hex or base58: " + privKeyStr);
                    return 1;
                }
                key = ECKey.fromPrivate(ByteUtils.bytesToBigInteger(decode));
            }
            if (pubKeyStr != null) {
                // Give the user a hint.
                System.out.println("You don't have to specify --pubkey when a private key is supplied.");
            }
            creationTime.ifPresentOrElse(key::setCreationTime, key::clearCreationTime);
        } else if (pubKeyStr != null) {
            byte[] pubkey = parseAsHexOrBase58(pubKeyStr);
            key = ECKey.fromPublicOnly(pubkey);
            creationTime.ifPresentOrElse(key::setCreationTime, key::clearCreationTime);
        } else {
            System.err.println("Either --privkey or --pubkey must be specified.");
            return 1;
        }
        if (wallet.hasKey(key)) {
            System.err.println("That key already exists in this wallet.");
            return 1;
        }
        try {
            if (wallet.isEncrypted()) {
                AesKey aesKey = passwordToKey(true);
                if (aesKey == null)
                    return 1;   // Error message already printed.
                key = key.encrypt(Objects.requireNonNull(wallet.getKeyCrypter()), aesKey);
            }
        } catch (KeyCrypterException kce) {
            System.err.println("There was an encryption related error when adding the key. The error was '"
                    + kce.getMessage() + "'.");
            return 1;
        }
        if (!key.isCompressed())
            System.out.println("WARNING: Importing an uncompressed key");
        wallet.importKey(key);
        System.out.print("Addresses: " + key.toAddress(ScriptType.P2PKH, net));
        if (key.isCompressed())
            System.out.print("," + key.toAddress(ScriptType.P2WPKH, net));
        System.out.println();
        cleanUp();
        return 0;
    }

    @Nullable
    private AesKey passwordToKey(boolean printError) {
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
        return Objects.requireNonNull(wallet.getKeyCrypter()).deriveKey(password);
    }

    /**
     * Attempts to parse the given string as arbitrary-length hex or base58 and then return the results, or null if
     * neither parse was successful.
     */
    private byte[] parseAsHexOrBase58(String data) {
        try {
            return ByteUtils.parseHex(data);
        } catch (Exception e) {
            // Didn't decode as hex, try base58.
            try {
                return Base58.decodeChecked(data);
            } catch (AddressFormatException e1) {
                return null;
            }
        }
    }

    private Optional<Instant> getCreationTime(LocalDate date, Long unixtime) {
        if (unixtime != null)
            return Optional.of(Instant.ofEpochSecond(unixtime));
        else if (date != null)
            return Optional.of(date.atStartOfDay(ZoneId.systemDefault()).toInstant());
        else
            return Optional.empty();
    }

    private int deleteKey() {
        initLogger(debugLog);
        initNetworkParameter(net);
        initChainFile(chainFile);

        Context.propagate(new Context());

        initCondition(conditionStr);
        checkWalletFileExists();
        if (pubKeyStr == null && addrStr == null) {
            System.err.println("One of --pubkey or --addr must be specified.");
            return 1;
        }
        ECKey key;
        if (pubKeyStr != null) {
            key = wallet.findKeyFromPubKey(ByteUtils.parseHex(pubKeyStr));
        } else {
            try {
                Address address = wallet.parseAddress(addrStr);
                key = wallet.findKeyFromAddress(address);
            } catch (AddressFormatException e) {
                System.err.println(addrStr + " does not parse as a Bitcoin address of the right network parameters.");
                return 1;
            }
        }
        if (key == null) {
            System.err.println("Wallet does not seem to contain that key.");
            return 1;
        }
        boolean removed = wallet.removeKey(key);
        if (removed)
            System.out.println("Key " + key + " was removed");
        else
            System.err.println("Key " + key + " could not be removed");
        cleanUp();
        return 0;
    }

    private int currentReceiveAddr() {
        initLogger(debugLog);
        initNetworkParameter(net);
        initChainFile(chainFile);

        Context.propagate(new Context());

        initCondition(conditionStr);
        checkWalletFileExists();
        Address address = wallet.currentReceiveAddress();
        System.out.println(address);
        cleanUp();
        return 0;
    }

    private int dumpWallet() throws BlockStoreException {
        initLogger(debugLog);
        initNetworkParameter(net);
        initChainFile(chainFile);

        Context.propagate(new Context());

        initCondition(conditionStr);
        checkWalletFileExists();
        // Setup to get the chain height so we can estimate lock times, but don't wipe the transactions if it's not
        // there just for the dump case.
        if (chainFile.exists())
            setup();

        if (dumpPrivKeys && wallet.isEncrypted()) {
            if (password != null) {
                final AesKey aesKey = passwordToKey(true);
                if (aesKey == null)
                    return 1; // Error message already printed.
                printWallet(aesKey);
            } else {
                System.err.println("Can't dump privkeys, wallet is encrypted.");
                return 1;
            }
        } else {
            printWallet(null);
        }
        cleanUp();
        return 0;
    }

    private static int rawDumpWallet(File walletFile) throws IOException {
        initLogger(debugLog);
        initNetworkParameter(net);
        initChainFile(chainFile);

        Context.propagate(new Context());

        initCondition(conditionStr);
        checkWalletFileExists();
        // Just parse the protobuf and print, then bail out. Don't try and do a real deserialization. This is
        // useful mostly for investigating corrupted wallets.
        try (FileInputStream stream = new FileInputStream(walletFile)) {
            Protos.Wallet proto = WalletProtobufSerializer.parseToProto(stream);
            proto = attemptHexConversion(proto);
            System.out.println(proto.toString());
            return 0;
        }
    }

    private int send() {
        initLogger(debugLog);
        initNetworkParameter(net);
        initChainFile(chainFile);

        Context.propagate(new Context());

        initCondition(conditionStr);
        checkWalletFileExists();
        if (feePerVkbStr != null && feeSatPerVbyteStr != null) {
            System.err.println("--fee-per-kb and --fee-sat-per-byte cannot be used together.");
            return 1;
        } else if (outputsStr != null) {
            Coin feePerVkb;
            if (feePerVkbStr != null)
                feePerVkb = parseCoin(feePerVkbStr);
            else if (feeSatPerVbyteStr != null)
                feePerVkb = Coin.valueOf(Long.parseLong(feeSatPerVbyteStr) * 1000);
            else
                feePerVkb = null;
            if (selectAddrStr != null && selectOutputStr != null) {
                System.err.println("--select-addr and --select-output cannot be used together.");
                return 1;
            }
            CoinSelector coinSelector;
            if (selectAddrStr != null) {
                Address selectAddr;
                try {
                    selectAddr = wallet.parseAddress(selectAddrStr);
                } catch (AddressFormatException x) {
                    System.err.println("Could not parse given address, or wrong network: " + selectAddrStr);
                    return 1;
                }
                final Address validSelectAddr = selectAddr;
                coinSelector = CoinSelector.fromPredicate(candidate -> {
                    try {
                        return candidate.getScriptPubKey().getToAddress(net).equals(validSelectAddr);
                    } catch (ScriptException x) {
                        return false;
                    }
                });
            } else if (selectOutputStr != null) {
                String[] parts = selectOutputStr.split(":", 2);
                Sha256Hash selectTransactionHash = Sha256Hash.wrap(parts[0]);
                int selectIndex = Integer.parseInt(parts[1]);
                coinSelector = CoinSelector.fromPredicate(candidate ->
                    candidate.getIndex() == selectIndex && candidate.getParentTransactionHash().equals(selectTransactionHash)
                );
            } else {
                coinSelector = null;
            }
            send(coinSelector, outputsStr, feePerVkb, lockTimeStr, allowUnconfirmed);
        } else {
            System.err.println("You must specify at least one --output=addr:value.");
            return 1;
        }
        cleanUp();
        return 0;
    }

    private void printWallet(@Nullable AesKey aesKey) {
        System.out.println(wallet.toString(dumpLookAhead, dumpPrivKeys, aesKey, true, true, chain));
    }

    private int setCreationTime() {
        initLogger(debugLog);
        initNetworkParameter(net);
        initChainFile(chainFile);

        Context.propagate(new Context());

        initCondition(conditionStr);
        checkWalletFileExists();
        Optional<Instant> creationTime = getCreationTime(date,unixtime);
        for (DeterministicKeyChain chain : wallet.getActiveKeyChains()) {
            DeterministicSeed seed = chain.getSeed();
            if (seed == null)
                System.out.println("Active chain does not have a seed: " + chain);
            else
                creationTime.ifPresentOrElse(seed::setCreationTime, seed::clearCreationTime);

        }
        System.out.println(creationTime
                .map(time -> "Setting creation time to: " + TimeUtils.dateTimeFormat(time))
                .orElse("Clearing creation time."));
        cleanUp();
        return 0;
    }
}
