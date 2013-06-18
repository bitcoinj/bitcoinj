/*
 * Copyright 2013 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.google.bitcoin.crypto;

import com.google.bitcoin.core.ECKey;
import com.google.bitcoin.core.Transaction;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;

/**
 * A TransactionSignature wraps an {@link com.google.bitcoin.core.ECKey.ECDSASignature} and adds methods for handling
 * the additional SIGHASH mode byte that is used.
 */
public class TransactionSignature extends ECKey.ECDSASignature {
    /**
     * A byte that controls which parts of a transaction are signed. This is exposed because signatures
     * parsed off the wire may have sighash flags that aren't "normal" serializations of the enum values.
     * Because Satoshi's code works via bit testing, we must not lose the exact value when round-tripping
     * otherwise we'll fail to verify signature hashes.
     */
    public int sighashFlags = Transaction.SigHash.ALL.ordinal() + 1;

    /** Constructs a signature with the given components and SIGHASH_ALL. */
    public TransactionSignature(BigInteger r, BigInteger s) {
        super(r, s);
    }

    /** Constructs a transaction signature based on the ECDSA signature. */
    public TransactionSignature(ECKey.ECDSASignature signature, Transaction.SigHash mode, boolean anyoneCanPay) {
        super(signature.r, signature.s);
        setSigHash(mode, anyoneCanPay);
    }

    /** Calculates the byte used in the protocol to represent the combination of mode and anyoneCanPay. */
    public static int calcSigHashValue(Transaction.SigHash mode, boolean anyoneCanPay) {
        int sighashFlags = mode.ordinal() + 1;
        if (anyoneCanPay)
            sighashFlags |= Transaction.SIGHASH_ANYONECANPAY_VALUE;
        return sighashFlags;
    }

    /** Configures the sighashFlags field as appropriate. */
    public void setSigHash(Transaction.SigHash mode, boolean anyoneCanPay) {
        sighashFlags = calcSigHashValue(mode, anyoneCanPay);
    }

    public boolean anyoneCanPay() {
        return (sighashFlags & Transaction.SIGHASH_ANYONECANPAY_VALUE) != 0;
    }

    public Transaction.SigHash sigHashMode() {
        final int mode = sighashFlags & 0x1f;
        if (mode == Transaction.SigHash.NONE.ordinal() + 1)
            return Transaction.SigHash.NONE;
        else if (mode == Transaction.SigHash.SINGLE.ordinal() + 1)
            return Transaction.SigHash.SINGLE;
        else
            return Transaction.SigHash.ALL;
    }

    /**
     * What we get back from the signer are the two components of a signature, r and s. To get a flat byte stream
     * of the type used by Bitcoin we have to encode them using DER encoding, which is just a way to pack the two
     * components into a structure, and then we append a byte to the end for the sighash flags.
     */
    public byte[] encodeToBitcoin() {
        try {
            ByteArrayOutputStream bos = derByteStream();
            bos.write(sighashFlags);
            return bos.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException(e);  // Cannot happen.
        }
    }

    /**
     * Returns a decoded signature.
     * @throws RuntimeException if the signature is invalid or unparseable in some way.
     */
    public static TransactionSignature decodeFromBitcoin(byte[] bytes) {
        // Bitcoin encoding is DER signature + sighash byte.
        ECKey.ECDSASignature sig = ECKey.ECDSASignature.decodeFromDER(bytes);
        if (sig == null)
            throw new RuntimeException("Could not DER decode signature.");
        TransactionSignature tsig = new TransactionSignature(sig.r, sig.s);
        // In Bitcoin, any value of the final byte is valid unfortunately. However it may not be "canonical".
        tsig.sighashFlags = bytes[bytes.length - 1];
        return tsig;
    }
}
