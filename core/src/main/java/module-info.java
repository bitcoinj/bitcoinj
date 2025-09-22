module org.bitcoinj.core {
    requires java.logging;
    
    requires org.bitcoinj.base;
    
    requires org.jspecify;
    requires org.slf4j;

    requires org.bouncycastle.provider;
    requires com.google.common;
    requires com.google.protobuf;

    exports org.bitcoinj.core;
    exports org.bitcoinj.core.listeners;
    exports org.bitcoinj.crypto;
    exports org.bitcoinj.kits;
    exports org.bitcoinj.protobuf.wallet;
    exports org.bitcoinj.uri;
    exports org.bitcoinj.utils;
    exports org.bitcoinj.wallet;
    exports org.bitcoinj.wallet.listeners;
}