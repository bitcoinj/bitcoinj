package org.bitcoinj.core;

import org.bitcoinj.base.Address;
import org.bitcoinj.base.Coin;
import org.bitcoinj.base.Sha256Hash;
import org.bitcoinj.crypto.ECKey;
import org.bitcoinj.script.Script;
import org.bitcoinj.script.ScriptException;

/**
 *
 */
public class SignedTransaction extends Transaction {


    SignedTransaction(Transaction tx) {
        super(tx);
    }

    public TransactionInput addInput(TransactionOutput from) {
        throw new UnsupportedOperationException();
    }

    public TransactionInput addInput(TransactionInput input) {
        throw new UnsupportedOperationException();
    }

    public TransactionInput addInput(Sha256Hash spendTxHash, long outputIndex, Script script) {
        throw new UnsupportedOperationException();
    }

    public TransactionInput addSignedInput(TransactionOutPoint prevOut, Script scriptPubKey, Coin amount, ECKey sigKey,
                                           SigHash sigHash, boolean anyoneCanPay) throws ScriptException {
        throw new UnsupportedOperationException();
    }

    public TransactionInput addSignedInput(TransactionOutPoint prevOut, Script scriptPubKey, ECKey sigKey,
                                           SigHash sigHash, boolean anyoneCanPay) throws ScriptException {
        throw new UnsupportedOperationException();
    }

    public TransactionInput addSignedInput(TransactionOutPoint prevOut, Script scriptPubKey, Coin amount, ECKey sigKey) throws ScriptException {
        throw new UnsupportedOperationException();
    }

    public TransactionInput addSignedInput(TransactionOutPoint prevOut, Script scriptPubKey, ECKey sigKey) throws ScriptException {
        throw new UnsupportedOperationException();
    }

    public TransactionInput addSignedInput(TransactionOutput output, ECKey sigKey) {
        throw new UnsupportedOperationException();
    }

    public TransactionInput addSignedInput(TransactionOutput output, ECKey sigKey, SigHash sigHash, boolean anyoneCanPay) {
        throw new UnsupportedOperationException();
    }

    public void replaceInput(int index, TransactionInput input) {
        throw new UnsupportedOperationException();
    }

    public void clearOutputs() {
        throw new UnsupportedOperationException();
    }

    public TransactionOutput addOutput(TransactionOutput to) {
        throw new UnsupportedOperationException();
    }

    public void replaceOutput(int index, TransactionOutput output) {
        throw new UnsupportedOperationException();
    }

    public TransactionOutput addOutput(Coin value, Address address) {
        throw new UnsupportedOperationException();
    }

    /**
     * Creates an output that pays to the given pubkey directly (no address) with the given value, adds it to this
     * transaction, and returns the new output.
     */
    public TransactionOutput addOutput(Coin value, ECKey pubkey) {
        throw new UnsupportedOperationException();
    }

    /**
     * Creates an output that pays to the given script. The address and key forms are specialisations of this method,
     * you won't normally need to use it unless you're doing unusual things.
     */
    public TransactionOutput addOutput(Coin value, Script script) {
        throw new UnsupportedOperationException();
    }

    public void setLockTime(long lockTime) {
        throw new UnsupportedOperationException();
    }

    public void setVersion(int version) {
        throw new UnsupportedOperationException();
    }

    public void shuffleOutputs() {
        throw new UnsupportedOperationException();
    }

//    public void setPurpose(Purpose purpose) {
//        throw new UnsupportedOperationException();
//    }
//
//    public void setExchangeRate(ExchangeRate exchangeRate) {
//        throw new UnsupportedOperationException();
//    }
//
//    public void setMemo(String memo) {
//        throw new UnsupportedOperationException();
//    }

}
