package org.bitcoinj.core;

public class TransactionWitness {
    static TransactionWitness empty = new TransactionWitness(0);

    public static TransactionWitness getEmpty() {
        return empty;
    }

    byte[][] pushes;

    public TransactionWitness(int pushCount) {
        pushes = new byte[pushCount][];
    }

    public byte[] getPush(int i) {
        return pushes[i];
    }

    public int getPushCount() {
        return pushes.length;
    }

    void setPush(int i, byte[] value) {
        pushes[i] = value;
    }
}
