package org.bitcoinj.core;

import org.bitcoinj.base.Sha256Hash;
import org.bitcoinj.script.Script;

public class TransactionInputParameters {
    private final Sha256Hash spendTxHash;
    private final long outputIndex;
    private final Script script;

    public TransactionInputParameters(Sha256Hash spendTxHash, long outputIndex, Script script) {
        this.spendTxHash = spendTxHash;
        this.outputIndex = outputIndex;
        this.script = script;
    }

    public Sha256Hash getSpendTxHash() { return spendTxHash; }
    public long getOutputIndex() { return outputIndex; }
    public Script getScript() { return script; }
}
