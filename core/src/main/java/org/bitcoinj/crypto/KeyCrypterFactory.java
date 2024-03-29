package org.bitcoinj.crypto;

import org.bitcoinj.protobuf.wallet.Protos;

public interface KeyCrypterFactory {
    KeyCrypter createKeyCrypter();
}
