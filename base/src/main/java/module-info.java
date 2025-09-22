module org.bitcoinj.base {
    requires org.jspecify;
    requires org.slf4j;

    exports org.bitcoinj.base;
    exports org.bitcoinj.base.exceptions;
    exports org.bitcoinj.base.utils;
    exports org.bitcoinj.base.internal;  // Use by core
}