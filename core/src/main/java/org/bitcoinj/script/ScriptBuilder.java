/*
 * Copyright 2013 Google Inc.
 * Copyright 2018 Nicola Atzei
 * Copyright 2019 Andreas Schildbach
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

package org.bitcoinj.script;

import org.bitcoinj.core.Address;
import org.bitcoinj.core.LegacyAddress;
import org.bitcoinj.core.ECKey;
import org.bitcoinj.core.SegwitAddress;
import org.bitcoinj.core.Sha256Hash;
import org.bitcoinj.core.Transaction;
import org.bitcoinj.core.Utils;
import org.bitcoinj.crypto.TransactionSignature;
import org.bitcoinj.script.Script.ScriptType;

import javax.annotation.Nullable;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.Stack;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkState;
import static org.bitcoinj.script.ScriptOpCodes.*;

/**
 * <p>Tools for the construction of commonly used script types. You don't normally need this as it's hidden behind
 * convenience methods on {@link Transaction}, but they are useful when working with the
 * protocol at a lower level.</p>
 */
public class ScriptBuilder {
    private final List<ScriptChunk> chunks;

    /** Creates a fresh ScriptBuilder with an empty program. */
    public ScriptBuilder() {
        chunks = new LinkedList<>();
    }

    /** Creates a fresh ScriptBuilder with the given program as the starting point. */
    public ScriptBuilder(Script template) {
        chunks = new ArrayList<>(template.getChunks());
    }

    /** Adds the given chunk to the end of the program */
    public ScriptBuilder addChunk(ScriptChunk chunk) {
        return addChunk(chunks.size(), chunk);
    }

    /** Adds the given chunk at the given index in the program */
    public ScriptBuilder addChunk(int index, ScriptChunk chunk) {
        chunks.add(index, chunk);
        return this;
    }

    /** Adds the given opcode to the end of the program. */
    public ScriptBuilder op(int opcode) {
        return op(chunks.size(), opcode);
    }

    /** Adds the given opcode to the given index in the program */
    public ScriptBuilder op(int index, int opcode) {
        checkArgument(opcode > OP_PUSHDATA4);
        return addChunk(index, new ScriptChunk(opcode, null));
    }

    /** Adds a copy of the given byte array as a data element (i.e. PUSHDATA) at the end of the program. */
    public ScriptBuilder data(byte[] data) {
        if (data.length == 0)
            return smallNum(0);
        else
            return data(chunks.size(), data);
    }

    /** Adds a copy of the given byte array as a data element (i.e. PUSHDATA) at the given index in the program. */
    public ScriptBuilder data(int index, byte[] data) {
        // implements BIP62
        byte[] copy = Arrays.copyOf(data, data.length);
        int opcode;
        if (data.length == 0) {
            opcode = OP_0;
        } else if (data.length == 1) {
            byte b = data[0];
            if (b >= 1 && b <= 16)
                opcode = Script.encodeToOpN(b);
            else
                opcode = 1;
        } else if (data.length < OP_PUSHDATA1) {
            opcode = data.length;
        } else if (data.length < 256) {
            opcode = OP_PUSHDATA1;
        } else if (data.length < 65536) {
            opcode = OP_PUSHDATA2;
        } else {
            throw new RuntimeException("Unimplemented");
        }
        return addChunk(index, new ScriptChunk(opcode, copy));
    }

    /**
     * Adds the given number to the end of the program. Automatically uses
     * shortest encoding possible.
     */
    public ScriptBuilder number(long num) {
        return number(chunks.size(), num);
    }

    /**
     * Adds the given number to the given index in the program. Automatically
     * uses shortest encoding possible.
     */
    public ScriptBuilder number(int index, long num) {
        if (num == -1) {
            return op(index, OP_1NEGATE);
        } else if (num >= 0 && num <= 16) {
            return smallNum(index, (int) num);
        } else {
            return bigNum(index, num);
        }
    }

    /**
     * Adds the given number as a OP_N opcode to the end of the program.
     * Only handles values 0-16 inclusive.
     * 
     * @see #number(long)
     */
    public ScriptBuilder smallNum(int num) {
        return smallNum(chunks.size(), num);
    }

    /** Adds the given number as a push data chunk.
     * This is intended to use for negative numbers or values greater than 16, and although
     * it will accept numbers in the range 0-16 inclusive, the encoding would be
     * considered non-standard.
     * 
     * @see #number(long)
     */
    protected ScriptBuilder bigNum(long num) {
        return bigNum(chunks.size(), num);
    }

    /**
     * Adds the given number as a OP_N opcode to the given index in the program.
     * Only handles values 0-16 inclusive.
     * 
     * @see #number(long)
     */
    public ScriptBuilder smallNum(int index, int num) {
        checkArgument(num >= 0, "Cannot encode negative numbers with smallNum");
        checkArgument(num <= 16, "Cannot encode numbers larger than 16 with smallNum");
        return addChunk(index, new ScriptChunk(Script.encodeToOpN(num), null));
    }

    /**
     * Adds the given number as a push data chunk to the given index in the program.
     * This is intended to use for negative numbers or values greater than 16, and although
     * it will accept numbers in the range 0-16 inclusive, the encoding would be
     * considered non-standard.
     * 
     * @see #number(long)
     */
    protected ScriptBuilder bigNum(int index, long num) {
        final byte[] data;

        if (num == 0) {
            data = new byte[0];
        } else {
            Stack<Byte> result = new Stack<>();
            final boolean neg = num < 0;
            long absvalue = Math.abs(num);

            while (absvalue != 0) {
                result.push((byte) (absvalue & 0xff));
                absvalue >>= 8;
            }

            if ((result.peek() & 0x80) != 0) {
                // The most significant byte is >= 0x80, so push an extra byte that
                // contains just the sign of the value.
                result.push((byte) (neg ? 0x80 : 0));
            } else if (neg) {
                // The most significant byte is < 0x80 and the value is negative,
                // set the sign bit so it is subtracted and interpreted as a
                // negative when converting back to an integral.
                result.push((byte) (result.pop() | 0x80));
            }

            data = new byte[result.size()];
            for (int byteIdx = 0; byteIdx < data.length; byteIdx++) {
                data[byteIdx] = result.get(byteIdx);
            }
        }

        // At most the encoded value could take up to 8 bytes, so we don't need
        // to use OP_PUSHDATA opcodes
        return addChunk(index, new ScriptChunk(data.length, data));
    }

    /**
     * Adds true to the end of the program.
     * @return this
     */
    public ScriptBuilder opTrue() {
        return number(1); // it push OP_1/OP_TRUE
    }

    /**
     * Adds true to the given index in the program.
     * @param index at which insert true
     * @return this
     */
    public ScriptBuilder opTrue(int index) {
        return number(index, 1); // push OP_1/OP_TRUE
    }

    /**
     * Adds false to the end of the program.
     * @return this
     */
    public ScriptBuilder opFalse() {
        return number(0); // push OP_0/OP_FALSE
    }

    /**
     * Adds false to the given index in the program.
     * @param index at which insert true
     * @return this
     */
    public ScriptBuilder opFalse(int index) {
        return number(index, 0); // push OP_0/OP_FALSE
    }

    /** Creates a new immutable Script based on the state of the builder. */
    public Script build() {
        return new Script(chunks);
    }

    /** Creates an empty script. */
    public static Script createEmpty() {
        return new ScriptBuilder().build();
    }

    /** Creates a scriptPubKey that encodes payment to the given address. */
    public static Script createOutputScript(Address to) {
        if (to instanceof LegacyAddress) {
            ScriptType scriptType = to.getOutputScriptType();
            if (scriptType == ScriptType.P2PKH)
                return createP2PKHOutputScript(to.getHash());
            else if (scriptType == ScriptType.P2SH)
                return createP2SHOutputScript(to.getHash());
            else
                throw new IllegalStateException("Cannot handle " + scriptType);
        } else if (to instanceof SegwitAddress) {
            ScriptBuilder builder = new ScriptBuilder();
            // OP_0 <pubKeyHash|scriptHash>
            SegwitAddress toSegwit = (SegwitAddress) to;
            builder.smallNum(toSegwit.getWitnessVersion());
            builder.data(toSegwit.getWitnessProgram());
            return builder.build();
        } else {
            throw new IllegalStateException("Cannot handle " + to);
        }
    }

    /**
     * Creates a scriptSig that can redeem a P2PKH output.
     * If given signature is null, incomplete scriptSig will be created with OP_0 instead of signature
     */
    public static Script createInputScript(@Nullable TransactionSignature signature, ECKey pubKey) {
        byte[] pubkeyBytes = pubKey.getPubKey();
        byte[] sigBytes = signature != null ? signature.encodeToBitcoin() : new byte[]{};
        return new ScriptBuilder().data(sigBytes).data(pubkeyBytes).build();
    }

    /**
     * Creates a scriptSig that can redeem a P2PK output.
     * If given signature is null, incomplete scriptSig will be created with OP_0 instead of signature
     */
    public static Script createInputScript(@Nullable TransactionSignature signature) {
        byte[] sigBytes = signature != null ? signature.encodeToBitcoin() : new byte[]{};
        return new ScriptBuilder().data(sigBytes).build();
    }

    /** Creates a program that requires at least N of the given keys to sign, using OP_CHECKMULTISIG. */
    public static Script createMultiSigOutputScript(int threshold, List<ECKey> pubkeys) {
        checkArgument(threshold > 0);
        checkArgument(threshold <= pubkeys.size());
        checkArgument(pubkeys.size() <= 16);  // That's the max we can represent with a single opcode.
        ScriptBuilder builder = new ScriptBuilder();
        builder.smallNum(threshold);
        for (ECKey key : pubkeys) {
            builder.data(key.getPubKey());
        }
        builder.smallNum(pubkeys.size());
        builder.op(OP_CHECKMULTISIG);
        return builder.build();
    }

    /** Create a program that satisfies an OP_CHECKMULTISIG program. */
    public static Script createMultiSigInputScript(List<TransactionSignature> signatures) {
        List<byte[]> sigs = new ArrayList<>(signatures.size());
        for (TransactionSignature signature : signatures) {
            sigs.add(signature.encodeToBitcoin());
        }

        return createMultiSigInputScriptBytes(sigs, null);
    }

    /** Create a program that satisfies an OP_CHECKMULTISIG program. */
    public static Script createMultiSigInputScript(TransactionSignature... signatures) {
        return createMultiSigInputScript(Arrays.asList(signatures));
    }

    /** Create a program that satisfies an OP_CHECKMULTISIG program, using pre-encoded signatures. */
    public static Script createMultiSigInputScriptBytes(List<byte[]> signatures) {
        return createMultiSigInputScriptBytes(signatures, null);
    }

    /**
     * Create a program that satisfies a P2SH OP_CHECKMULTISIG program.
     * If given signature list is null, incomplete scriptSig will be created with OP_0 instead of signatures
     */
    public static Script createP2SHMultiSigInputScript(@Nullable List<TransactionSignature> signatures,
                                                       Script multisigProgram) {
        List<byte[]> sigs = new ArrayList<>();
        if (signatures == null) {
            // create correct number of empty signatures
            int numSigs = multisigProgram.getNumberOfSignaturesRequiredToSpend();
            for (int i = 0; i < numSigs; i++)
                sigs.add(new byte[]{});
        } else {
            for (TransactionSignature signature : signatures) {
                sigs.add(signature.encodeToBitcoin());
            }
        }
        return createMultiSigInputScriptBytes(sigs, multisigProgram.getProgram());
    }

    /**
     * Create a program that satisfies an OP_CHECKMULTISIG program, using pre-encoded signatures. 
     * Optionally, appends the script program bytes if spending a P2SH output.
     */
    public static Script createMultiSigInputScriptBytes(List<byte[]> signatures, @Nullable byte[] multisigProgramBytes) {
        checkArgument(signatures.size() <= 16);
        ScriptBuilder builder = new ScriptBuilder();
        builder.smallNum(0);  // Work around a bug in CHECKMULTISIG that is now a required part of the protocol.
        for (byte[] signature : signatures)
            builder.data(signature);
        if (multisigProgramBytes!= null)
            builder.data(multisigProgramBytes);
        return builder.build();
    }

    /**
     * Returns a copy of the given scriptSig with the signature inserted in the given position.
     *
     * This function assumes that any missing sigs have OP_0 placeholders. If given scriptSig already has all the signatures
     * in place, IllegalArgumentException will be thrown.
     *
     * @param targetIndex where to insert the signature
     * @param sigsPrefixCount how many items to copy verbatim (e.g. initial OP_0 for multisig)
     * @param sigsSuffixCount how many items to copy verbatim at end (e.g. redeemScript for P2SH)
     */
    public static Script updateScriptWithSignature(Script scriptSig, byte[] signature, int targetIndex,
                                                   int sigsPrefixCount, int sigsSuffixCount) {
        ScriptBuilder builder = new ScriptBuilder();
        List<ScriptChunk> inputChunks = scriptSig.getChunks();
        int totalChunks = inputChunks.size();

        // Check if we have a place to insert, otherwise just return given scriptSig unchanged.
        // We assume here that OP_0 placeholders always go after the sigs, so
        // to find if we have sigs missing, we can just check the chunk in latest sig position
        boolean hasMissingSigs = inputChunks.get(totalChunks - sigsSuffixCount - 1).equalsOpCode(OP_0);
        checkArgument(hasMissingSigs, "ScriptSig is already filled with signatures");

        // copy the prefix
        for (ScriptChunk chunk: inputChunks.subList(0, sigsPrefixCount))
            builder.addChunk(chunk);

        // copy the sigs
        int pos = 0;
        boolean inserted = false;
        for (ScriptChunk chunk: inputChunks.subList(sigsPrefixCount, totalChunks - sigsSuffixCount)) {
            if (pos == targetIndex) {
                inserted = true;
                builder.data(signature);
                pos++;
            }
            if (!chunk.equalsOpCode(OP_0)) {
                builder.addChunk(chunk);
                pos++;
            }
        }

        // add OP_0's if needed, since we skipped them in the previous loop
        while (pos < totalChunks - sigsPrefixCount - sigsSuffixCount) {
            if (pos == targetIndex) {
                inserted = true;
                builder.data(signature);
            }
            else {
                builder.addChunk(new ScriptChunk(OP_0, null));
            }
            pos++;
        }

        // copy the suffix
        for (ScriptChunk chunk: inputChunks.subList(totalChunks - sigsSuffixCount, totalChunks))
            builder.addChunk(chunk);

        checkState(inserted);
        return builder.build();
    }

    /** Creates a scriptPubKey that encodes payment to the given raw public key. */
    public static Script createP2PKOutputScript(byte[] pubKey) {
        return new ScriptBuilder().data(pubKey).op(OP_CHECKSIG).build();
    }

    /** Creates a scriptPubKey that encodes payment to the given raw public key. */
    public static Script createP2PKOutputScript(ECKey pubKey) {
        return createP2PKOutputScript(pubKey.getPubKey());
    }

    /**
     * Creates a scriptPubKey that sends to the given public key hash.
     */
    public static Script createP2PKHOutputScript(byte[] hash) {
        checkArgument(hash.length == LegacyAddress.LENGTH);
        ScriptBuilder builder = new ScriptBuilder();
        builder.op(OP_DUP);
        builder.op(OP_HASH160);
        builder.data(hash);
        builder.op(OP_EQUALVERIFY);
        builder.op(OP_CHECKSIG);
        return builder.build();
    }

    /**
     * Creates a scriptPubKey that sends to the given public key.
     */
    public static Script createP2PKHOutputScript(ECKey key) {
        checkArgument(key.isCompressed());
        return createP2PKHOutputScript(key.getPubKeyHash());
    }

    /**
     * Creates a segwit scriptPubKey that sends to the given public key hash.
     */
    public static Script createP2WPKHOutputScript(byte[] hash) {
        checkArgument(hash.length == SegwitAddress.WITNESS_PROGRAM_LENGTH_PKH);
        return new ScriptBuilder().smallNum(0).data(hash).build();
    }

    /**
     * Creates a segwit scriptPubKey that sends to the given public key.
     */
    public static Script createP2WPKHOutputScript(ECKey key) {
        checkArgument(key.isCompressed());
        return createP2WPKHOutputScript(key.getPubKeyHash());
    }

    /**
     * Creates a scriptPubKey that sends to the given script hash. Read
     * <a href="https://github.com/bitcoin/bips/blob/master/bip-0016.mediawiki">BIP 16</a> to learn more about this
     * kind of script.
     *
     * @param hash The hash of the redeem script
     * @return an output script that sends to the redeem script
     */
    public static Script createP2SHOutputScript(byte[] hash) {
        checkArgument(hash.length == 20);
        return new ScriptBuilder().op(OP_HASH160).data(hash).op(OP_EQUAL).build();
    }

    /**
     * Creates a scriptPubKey for a given redeem script.
     *
     * @param redeemScript The redeem script
     * @return an output script that sends to the redeem script
     */
    public static Script createP2SHOutputScript(Script redeemScript) {
        byte[] hash = Utils.sha256hash160(redeemScript.getProgram());
        return ScriptBuilder.createP2SHOutputScript(hash);
    }

    /**
     * Creates a segwit scriptPubKey that sends to the given script hash.
     */
    public static Script createP2WSHOutputScript(byte[] hash) {
        checkArgument(hash.length == SegwitAddress.WITNESS_PROGRAM_LENGTH_SH);
        return new ScriptBuilder().smallNum(0).data(hash).build();
    }

    /**
     * Creates a segwit scriptPubKey for the given redeem script.
     */
    public static Script createP2WSHOutputScript(Script redeemScript) {
        byte[] hash = Sha256Hash.hash(redeemScript.getProgram());
        return ScriptBuilder.createP2WSHOutputScript(hash);
    }

    /**
     * Creates a P2SH output script for n-of-m multisig with given public keys and threshold. Given public keys will
     * be placed in redeem script in the lexicographical sorting order.
     *
     * @param threshold The threshold number of keys that must sign (n)
     * @param pubkeys A list of m public keys
     * @return The P2SH multisig output script
     */
    public static Script createP2SHOutputScript(int threshold, List<ECKey> pubkeys) {
        Script redeemScript = createRedeemScript(threshold, pubkeys);
        return createP2SHOutputScript(redeemScript);
    }

    /**
     * Creates an n-of-m multisig redeem script with given public keys and threshold. Given public keys will be placed in
     * redeem script in the lexicographical sorting order.
     *
     * @param threshold The threshold number of keys that must sign (n)
     * @param pubkeys A list of m public keys
     * @return The P2SH multisig redeem script
     */
    public static Script createRedeemScript(int threshold, List<ECKey> pubkeys) {
        pubkeys = new ArrayList<>(pubkeys);
        Collections.sort(pubkeys, ECKey.PUBKEY_COMPARATOR);
        return ScriptBuilder.createMultiSigOutputScript(threshold, pubkeys);
    }

    /**
     * Creates a script of the form OP_RETURN [data]. This feature allows you to attach a small piece of data (like
     * a hash of something stored elsewhere) to a zero valued output which can never be spent and thus does not pollute
     * the ledger.
     */
    public static Script createOpReturnScript(byte[] data) {
        checkArgument(data.length <= 80);
        return new ScriptBuilder().op(OP_RETURN).data(data).build();
    }
}
