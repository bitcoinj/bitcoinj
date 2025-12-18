package org.bitcoinj.wallettool;


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

    public static final String OPTION_IGNORE_MANDATORY_EXTENSION = "If a wallet has unknown required extensions that would otherwise cause load failures, this overrides that.\")";
    public static final String PARAMETER_WALLET_FILE = "Path to the wallet file to create.";
    public static final String OPTION_DUMP_PRIVKEYS = "Displays wallet seed and private keys (password required for an encrypted wallet).";
    public static final String OPTION_DUMP_LOOKAHEAD = "Includes lookahead keys (pregenerated but unused).";
    public static final String OPTION_PASSWORD = "Password to decrypt and access private keys. For an encrypted wallet, the password is provided here.";

    public static final String OPTION_OUTPUT = "Target address and amount. If specified, a transaction is created from the provided output from this wallet and broadcast. (e.g., 1GthXFQMktFLWdh5EPNGqbq3H6WdG8zsWj:1.245). You can repeat --output=address:value multiple times. There is a magic value ALL which empties the wallet to that address, e.g., --output=1GthXFQMktFLWdh5EPNGqbq3H6WdG8zsWj:ALL. The output destination can also be a native segwit address. If the output destination starts with 04 and is 65 or 33 bytes long it will be treated as a public key instead of an address and the send will use <key> CHECKSIG as the script.";
    public static final String OPTION_FEE_PER_KB = "Sets the network fee in Bitcoin per kilobyte when sending, e.g. --fee-per-kb=0.0005";
    public static final String OPTION_FEE_SAT_PER_VBYTE = "Sets the network fee in satoshi per byte when sending, e.g. --fee-sat-per-vbyte=50";

    public static final String OPTION_LOCKTIME_STR = "Specifies a lock-time either by date or by block number.";
    public static final String OPTION_SELECT_ADDR = "When sending, only pick coins from this address.";
    public static final String OPTION_SELECT_OUTPUT = "When sending, only pick coins from this output.";
    public static final String OPTION_WAIT_FOR = "Waits for a specific number of confirmations.";
    public static final String OPTION_ALLOW_UNCONFIRMED = "Allows you to create spends of pending non-change outputs.";

    public static final String OPTION_ADDR = "If specified when sending, don't try and connect, just write the tx to the wallet.";
    public static final String OPTION_PUBKEY_STR = "Specifies a hex/base58 encoded non-compressed public key.";

    //SUBCOMMAND DESCRIPTIONS
    public static final String SUBCOMMAND_CREATE = "Makes a new wallet in the file specified by --wallet. Will complain and require --force if the wallet already exists.Creates a new wallet in the specified file. This command supports deterministic wallet seeds, watch-only wallets, and various configurations like timestamps and address derivation types. If `--seed` or `--watchkey` is combined with either `--date` or `--unixtime`, use that as a birthdate for the wallet. If neither `--seed` nor `--watchkey` is provided, create will generate a wallet with a newly generated random seed.";
    public static final String SUBCOMMAND_DUMP = "Loads and prints the given wallet in textual form to stdout. Allows printing private keys, seeds, and unused lookahead keys if specified.";
    public static final String SUBCOMMAND_RAW_DUMP = "Prints the wallet as a raw protobuf with no parsing or sanity checking applied.";
    public static final String SUBCOMMAND_SEND = "Creates and broadcasts a transaction from the given wallet. Requires --output to be specified.";
    public static final String SUBCOMMAND_SET_CREATION_TIME = "Modify the creation time of the active chains of this wallet. This is useful for repairing wallets that accidentally have been created in the future. Currently, watching wallets are not supported. If you omit both options (`--date` and `--unixtime`), the creation time is cleared (set to 0).";
    public static final String SUBCOMMAND_ADD_KEY = "Adds a key (private or public) to the wallet. Appropriate formats such as WIF, hex, or base58 are supported for private and public keys.";
    public static final String SUBCOMMAND_ADD_ADDR = "Adds a Bitcoin address as a watching-only address. The `--addr` option is required.";
    public static final String SUBCOMMAND_DELETE_KEY = "Removes a key specified by --pubkey or --addr from the wallet. Deletes a key (private or public) from the wallet.";
    public static final String SUBCOMMAND_CURR_RECIEVING_ADDR = "Prints the current receive address of the wallet. If no address exists, a new one will be derived and set automatically. Addresses derived using this action are independent of addresses derived with the `add-key` action.";
    public static final String SUBCOMMAND_SYNC = "Syncs the wallet with the latest blockchain to download new transactions. If the chain data file does not exist, or if the --force option is specified, the wallet will reset and sync from the beginning.";
    public static final String SUBCOMMAND_DECRYPT = "Decrypts the wallet using the provided password. Requires --password";
    public static final String SUBCOMMAND_ENCRYPT = "Encrypts the wallet using the specified password. Requires --password.";
    public static final String SUBCOMMAND_RESET = "Deletes all wallet transactions to allow you to replay the chain.";
    public static final String SUBCOMMAND_ROTATE = "Takes --date and sets that as the key rotation time. Any coins controlled by keys or HD chains created before this date will be re-spent to a key (from an HD tree) that was created after it. If --date is missing, the current time is assumed. If the time covers all keys, a new HD tree will be created from a new random seed.";

    public static final String SUBCOMMAND_UPGRADE = "Upgrade deterministic wallets to the given script type. If specified, uses a target script type for deriving new addresses.";

}