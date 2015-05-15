package org.bitcoinj.core;

import java.math.BigInteger;
import java.util.Map;

import static org.bitcoinj.core.Coin.COIN;

public class CoinDefinition {


    public static final String coinName = "UnionPlusCoin";
    public static final String coinTicker = "UPC";
    public static final String coinURIScheme = "UnionPlusCoin";
    public static final String cryptsyMarketId = "155";
    public static final String cryptsyMarketCurrency = "BTC";
    public static final String PATTERN_PRIVATE_KEY_START = "[7X]";


    public static final String BLOCKEXPLORER_BASE_URL_PROD = "http://explorer.darkcoin.io/";    //blockr.io
    public static final String BLOCKEXPLORER_ADDRESS_PATH = "address/";             //blockr.io path
    public static final String BLOCKEXPLORER_TRANSACTION_PATH = "tx/";              //blockr.io path
    public static final String BLOCKEXPLORER_BLOCK_PATH = "block/";                 //blockr.io path
    public static final String BLOCKEXPLORER_BASE_URL_TEST = BLOCKEXPLORER_BASE_URL_PROD;

    public static final String DONATION_ADDRESS = "UiMKDgW6t6NrbSpQtgihYKJ7hGMZ1k47io";
    public static final String DONATION_ADDRESS_TESTNET = "";

    enum CoinHash {
        SHA256,
        scrypt,
        x11
    };
    public static final int nMaxBlockHeight = 4207680;
    public static final int nPremineBlockHeight = 1;
    public static final Coin nLastCoinBlockValue = COIN.multiply(Coin.parseCoin("58.11334").getValue());
    public static final Coin nNormalBlockValue = COIN.multiply(71);
    public static final Coin nPremineBlockValue = COIN.multiply(COIN.multiply(7).getValue());

    public static final CoinHash coinPOWHash = CoinHash.x11;

    public static boolean checkpointFileSupport = true;

    public static final int TARGET_TIMESPAN = 60; // UnionPlusCoin: 1 minute retarget
    public static final int TARGET_SPACING = 60; // UnionPlusCoin: 1 minute block time
    public static final int INTERVAL = TARGET_TIMESPAN / TARGET_SPACING;


    public static int spendableCoinbaseDepth = 100; //main.h: static const int COINBASE_MATURITY
    /**
     * The maximum number of coins to be generated
     */
    public static final long MAX_COINS = 999000000;

    /**
     * The maximum money to be generated
     */
    public static final Coin MAX_MONEY = COIN.multiply(MAX_COINS);                //main.h:  MAX_MONEY

    public static final Coin DEFAULT_MIN_TX_FEE = Coin.valueOf(100000);   // MIN_TX_FEE
    public static final Coin DUST_LIMIT = Coin.valueOf(1000); //main.h CTransaction::GetMinFee        0.01 coins

    public static final int PROTOCOL_VERSION = 70075;          //version.h PROTOCOL_VERSION
    public static final int MIN_PROTOCOL_VERSION = 70066;        //version.h MIN_PROTO_VERSION
    public static final int BIP0031_VERSION = 60000;

    public static final int BLOCK_CURRENTVERSION = 2;   //CBlock::CURRENT_VERSION
    public static final int MAX_BLOCK_SIZE = 1 * 1000 * 1000;

    public static final int Port    = 35648;       //protocol.h GetDefaultPort(testnet=false)
    public static final int TestPort = 35658;     //protocol.h GetDefaultPort(testnet=true)

    //
    //  Production
    //
    public static final int AddressHeader = 68;             //base58.h CBitcoinAddress::PUBKEY_ADDRESS
    public static final int p2shHeader = 5;             //base58.h CBitcoinAddress::SCRIPT_ADDRESS
    public static final int dumpedPrivateKeyHeader = 128;   //common to all coins
    public static final long PacketMagic = 0xef3cbaedL;

    //Genesis Block Information from main.cpp: LoadBlockIndex
    static public long genesisBlockDifficultyTarget = (0x1e0ffff0L);         //main.cpp: LoadBlockIndex
    static public long genesisBlockTime = 1428630860L;                       //main.cpp: LoadBlockIndex
    static public long genesisBlockNonce = (1930860243);                         //main.cpp: LoadBlockIndex
    static public String genesisHash = "0000060fea0bd344a174eeb71f3f6a06a1eb91b037c8f3c10825354df11674c8"; //main.cpp: hashGenesisBlock
    static public String genesisMerkleRoot = "5f3e27b6e054cd733163aecd4297760c560612bbd8bb78bab41ca14518281066";
    static public Coin genesisBlockValue = nNormalBlockValue;                                                              //main.cpp: LoadBlockIndex
    //taken from the raw data of the block explorer
    static public String genesisTxInBytes = "04ffff001d010420556e696f6e506c7573436f696e204d61696e4e657420417072696c2032303135";
    static public String genesisTxOutBytes = "040184710fa689ad5023690c80f3a49c8f13f8d45b8c857fbcbc8bc4a8e4d3eb4b10f4d4604fa08dce601aaf0f470216fe1b51850b4acf21b179c45070ac7b03a9";

    //net.cpp strDNSSeed
    static public String[] dnsSeeds = new String[] {
            "dnsseed.unionpluscoin.org",

    };

    public static int minBroadcastConnections = 0;   //0 for default; we need more peers.

    //
    // TestNet - not tested
    //
    public static final int testnetAddressHeader = 125;             //base58.h CBitcoinAddress::PUBKEY_ADDRESS_TEST
    public static final int testnetp2shHeader = 196;             //base58.h CBitcoinAddress::SCRIPT_ADDRESS_TEST
    public static final long testnetPacketMagic = 0xef4ccaedL;      //
    public static final String testnetGenesisHash = "00000220ae9f6f4b878a6b2550e94148e78fa66b49846a9e447637d37af49a96";
    static public String testnetGenesisMerkleRoot = "dd5c9c97f242247dd7c7be9fba1f71c4f267860f845826092a3bed8836ff4d7b";
    static public long testnetGenesisBlockDifficultyTarget = (0x1e0ffff0L);         //main.cpp: LoadBlockIndex
    static public long testnetGenesisBlockTime = 1428871136L;                       //main.cpp: LoadBlockIndex
    static public long testnetGenesisBlockNonce = (1184424033);                         //main.cpp: LoadBlockIndex



    //main.cpp GetBlockValue(height, fee)
    public static final BigInteger GetBlockReward(int height)
    {
        BigInteger nSubsidy = BigInteger.valueOf(nNormalBlockValue.getValue());

        if (height == nPremineBlockHeight) {
            nSubsidy = BigInteger.valueOf(nPremineBlockValue.getValue());
        }
        else if (height < nMaxBlockHeight) {
            nSubsidy = BigInteger.valueOf(nNormalBlockValue.getValue());
        }
        else if (height == nMaxBlockHeight) {
            nSubsidy = BigInteger.valueOf(nLastCoinBlockValue.getValue());
        }
        else if (height > nMaxBlockHeight) {
            nSubsidy = BigInteger.valueOf(0);
        }
        return nSubsidy;
    }


    public static int subsidyDecreaseBlockCount = 4730400;     //main.cpp GetBlockValue(height, fee)

    public static BigInteger proofOfWorkLimit = Utils.decodeCompactBits(0x1e0fffffL);  //main.cpp bnProofOfWorkLimit (~uint256(0) >> 20); // unionpluscoin: starting difficulty is 1 / 2^12

    static public String[] testnetDnsSeeds = new String[] {
            "testnet-seed.unionpluscoin.org",
    };
    //from main.h: CAlert::CheckSignature
    public static final String SATOSHI_KEY = "047cf0b8c8bedb12f7acdd39b7399a079ab2f59adf6fff80b087601b213c34a3b4e2359e26de96c36296a8950b228c76e920846ac04081fb050b73b16936c58355";
    public static final String TESTNET_SATOSHI_KEY = "042d14223715f8df6b44389e9804bc6bb02ea9568e626645e4362c9acbf0d564d7f317c95467614a7a8b3f50d358413f32ea958a13c52b5150db5be12d4d432043";

    /** The string returned by getId() for the main, production network where people trade things. */
    public static final String ID_MAINNET = "org.unionpluscoin.production";
    /** The string returned by getId() for the testnet. */
    public static final String ID_TESTNET = "org.unionpluscoin.test";
    /** Unit test network. */
    public static final String ID_UNITTESTNET = "org.unionpluscoin.unittest";
    /** Reg test network. */
    public static final String ID_REGTEST = "org.unionpluscoin.regtest";

    //checkpoints.cpp Checkpoints::mapCheckpoints
    public static void initCheckpoints(Map<Integer, Sha256Hash> checkpoints)
    {
        checkpoints.put( 0, new Sha256Hash("0000060fea0bd344a174eeb71f3f6a06a1eb91b037c8f3c10825354df11674c8"));

    }
    public static void testnetInitCheckpoints(Map<Integer, Sha256Hash> checkpoints)
    {
        checkpoints.put( 0, new Sha256Hash("00000220ae9f6f4b878a6b2550e94148e78fa66b49846a9e447637d37af49a96"));

    }

    //Unit Test Information
    public static final String UNITTEST_ADDRESS = "UiMKDgW6t6NrbSpQtgihYKJ7hGMZ1k47io";
    public static final String UNITTEST_ADDRESS_PRIVATE_KEY = "W1xemx6mj6Lp8VzZkXQPtpKyZ7UGsDHQqEFoFUA27j2MvZzaTC3B";

}
