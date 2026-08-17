package org.bitcoinj.base;

public enum LitecoinNetwork implements Network {
    MAINNET(
            "litecoin.mainnet",
            48,   // 'L' prefix
            50,   // 'M' prefix
            "ltc",
            "litecoin",
            Coin.valueOf(84000000_00000000L)
    ),
    TESTNET(
            "litecoin.testnet",
            111,  // 'm' or 'n' prefix
            58,   // 'Q' prefix
            "tltc",
            "litecoin",
            Coin.valueOf(84000000_00000000L)
    );

    private final String id;
    private final int legacyAddressHeader;
    private final int legacyP2SHHeader;
    private final String segwitAddressHrp;
    private final String uriScheme;
    private final Monetary maxMoney;

    LitecoinNetwork(String id, int legacyAddressHeader, int legacyP2SHHeader,
                    String segwitAddressHrp, String uriScheme, Monetary maxMoney) {
        this.id = id;
        this.legacyAddressHeader = legacyAddressHeader;
        this.legacyP2SHHeader = legacyP2SHHeader;
        this.segwitAddressHrp = segwitAddressHrp;
        this.uriScheme = uriScheme;
        this.maxMoney = maxMoney;
    }

    @Override public String id() { return id; }
    @Override public int legacyAddressHeader() { return legacyAddressHeader; }
    @Override public int legacyP2SHHeader() { return legacyP2SHHeader; }
    @Override public String segwitAddressHrp() { return segwitAddressHrp; }
    @Override public String uriScheme() { return uriScheme; }
    @Override public boolean hasMaxMoney() { return true; }
    @Override public Monetary maxMoney() { return maxMoney; }

    @Override
    public boolean exceedsMaxMoney(Monetary monetary) {
        return monetary.getValue() > maxMoney.getValue();
    }

    @Override
    public String messageSigningPrefix() {
        return "Litecoin Signed Message:\n";
    }
}
