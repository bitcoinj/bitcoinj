package org.bitcoinj.core;

import org.bitcoinj.crypto.TransactionSignature;

import javax.annotation.Nullable;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class TransactionWitness {
    static TransactionWitness empty = new TransactionWitness(0);

    public static TransactionWitness getEmpty() {
        return empty;
    }

    private byte[][] pushes;

    public TransactionWitness(int pushCount) {
        pushes = new byte[pushCount][];
    }

    public byte[] getPush(int i) {
        return pushes[i];
    }

    public int getPushCount() {
        return pushes.length;
    }

    public void setPush(int i, byte[] value) {
        pushes[i] = value;
    }

    /**
     * Create a witness that can redeem a pay-to-witness-pubkey-hash output.
     */
    public static TransactionWitness createWitness(@Nullable final TransactionSignature signature, final ECKey pubKey) {
        final byte[] sigBytes = signature != null ? signature.encodeToBitcoin() : new byte[]{};
        final byte[] pubKeyBytes = pubKey.getPubKey();
        final TransactionWitness witness = new TransactionWitness(2);
        witness.setPush(0, sigBytes);
        witness.setPush(1, pubKeyBytes);
        return witness;
    }

    public byte[] getScriptBytes() {
        if (getPushCount() == 0)
            return new byte[0];
        else
            return pushes[pushes.length - 1];
    }

    @Override
    public String toString() {
        List<String> stringPushes = new ArrayList<>();
        for (int j = 0; j < this.getPushCount(); j++) {
            byte[] push = this.getPush(j);
            if (push != null) {
                stringPushes.add(Utils.HEX.encode(push));
            } else {
                stringPushes.add("NULL");
            }
        }
        return Utils.SPACE_JOINER.join(stringPushes);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        TransactionWitness other = (TransactionWitness) o;
        return Arrays.deepEquals(pushes, other.pushes);
    }

    @Override
    public int hashCode() {
        return Arrays.deepHashCode(pushes);
    }
}
