package org.bitcoinj.base;

public enum DogecoinNetwork implements Network {
    MAINNET(
            "dogecoin.mainnet",
            30,   // 0x1E - Standard Legacy P2PKH addresses starting with 'D'
            22,   // 0x16 - P2SH addresses starting with '9' or 'A'
            "",   // Dogecoin does not natively use SegWit/Bech32 on mainnet
            "dogecoin"
    ),
    TESTNET(
            "dogecoin.testnet",
            113,  // 0x71 - Addresses starting with 'n'
            196,  // 0xC4 - Addresses starting with '2'
            "",
            "dogecoin"
    );

    private final String id;
    private final int legacyAddressHeader;
    private final int legacyP2SHHeader;
    private final String segwitAddressHrp;
    private final String uriScheme;

    DogecoinNetwork(String id, int legacyAddressHeader, int legacyP2SHHeader,
                    String segwitAddressHrp, String uriScheme) {
        this.id = id;
        this.legacyAddressHeader = legacyAddressHeader;
        this.legacyP2SHHeader = legacyP2SHHeader;
        this.segwitAddressHrp = segwitAddressHrp;
        this.uriScheme = uriScheme;
    }

    @Override public String id() { return id; }
    @Override public int legacyAddressHeader() { return legacyAddressHeader; }
    @Override public int legacyP2SHHeader() { return legacyP2SHHeader; }
    @Override public String segwitAddressHrp() { return segwitAddressHrp; }
    @Override public String uriScheme() { return uriScheme; }

    @Override public boolean hasMaxMoney() { return false; }
    @Override public Monetary maxMoney() { return Coin.valueOf(Long.MAX_VALUE); }

    @Override
    public boolean exceedsMaxMoney(Monetary monetary) {
        return false; // Dogecoin supply is uncapped
    }

    @Override
    public String messageSigningPrefix() {
        return "Dogecoin Signed Message:\n";
    }
}
