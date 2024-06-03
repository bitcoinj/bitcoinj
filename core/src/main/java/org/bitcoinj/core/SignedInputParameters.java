package org.bitcoinj.core;


import org.bitcoinj.base.Coin;
import org.bitcoinj.core.Transaction.SigHash;
import org.bitcoinj.crypto.ECKey;
import org.bitcoinj.script.Script;

public class SignedInputParameters extends TransactionInputParameters {
    private final TransactionOutPoint prevOut;
    private final Coin amount;
    private final ECKey sigKey;
    private final SigHash sigHash;
    private final boolean anyoneCanPay;

    public SignedInputParameters(TransactionOutPoint prevOut, Script scriptPubKey, Coin amount, ECKey sigKey,
                                 SigHash sigHash, boolean anyoneCanPay) {
        super(prevOut.getHash(), prevOut.getIndex(), scriptPubKey);
        this.prevOut = prevOut;
        this.amount = amount;
        this.sigKey = sigKey;
        this.sigHash = sigHash;
        this.anyoneCanPay = anyoneCanPay;
    }

    public TransactionOutPoint getPrevOut() { return prevOut; }
    public Coin getAmount() { return amount; }
    public ECKey getSigKey() { return sigKey; }
    public SigHash getSigHash() { return sigHash; }
    public boolean isAnyoneCanPay() { return anyoneCanPay; }
}
