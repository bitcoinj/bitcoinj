package org.bitcoinj.examples;

import org.bitcoinj.core.Context;
import org.bitcoinj.core.ECKey;
import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.signers.LocalTransactionSigner;
import org.bitcoinj.wallet.Wallet;

public class NoPrivateKeyInWallet {

    public static void main(String[] args) {
    }

    static class PubKeyWallet extends Wallet {

        public PubKeyWallet(NetworkParameters params) {
            super(params);
        }

        @Override
        protected boolean canSignWith(ECKey key) {
            return true;
        }
    }

    static class SeparateKeySigner extends LocalTransactionSigner {
    }
}
