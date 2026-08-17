package org.bitcoinj.base;

public enum BitcoinCashNetwork implements Network {
    MAINNET(
            "bitcoincash.mainnet",
            0,    // 0x00 - Legacy P2PKH addresses starting with '1'
            5,    // 0x05 - Legacy P2SH addresses starting with '3'
            "",   // BCH does NOT use SegWit/Bech32 (it replaced it with CashAddr)
            "bitcoincash",
            Coin.valueOf(21000000_00000000L) // 21 Million Max Supply
    ),
    TESTNET(
            "bitcoincash.testnet",
            111,  // 0x6F - Legacy Testnet P2PKH ('m' or 'n')
            196,  // 0xC4 - Legacy Testnet P2SH ('2')
            "",
            "bchtest",
            Coin.valueOf(21000000_00000000L)
    );

    private final String id;
    private final int legacyAddressHeader;
    private final int legacyP2SHHeader;
    private final String segwitAddressHrp;
    private final String uriScheme;
    private final Monetary maxMoney;

    BitcoinCashNetwork(String id, int legacyAddressHeader, int legacyP2SHHeader,
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
    @Override public String segwitAddressHrp() { return segwitAddressHrp; } // Must remain empty string
    @Override public String uriScheme() { return uriScheme; }
    @Override public boolean hasMaxMoney() { return true; }
    @Override public Monetary maxMoney() { return maxMoney; }

    @Override
    public boolean exceedsMaxMoney(Monetary monetary) {
        return monetary.getValue() > maxMoney.getValue();
    }

    @Override
    public String messageSigningPrefix() {
        return "Bitcoin Cash Signed Message:\n";
    }
}
