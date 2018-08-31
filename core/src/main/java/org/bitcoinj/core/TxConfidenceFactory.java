package org.bitcoinj.core;

class TxConfidenceFactory {
    TransactionConfidence createConfidence(Sha256Hash hash) {
        return new TransactionConfidence(hash);
    }
}
