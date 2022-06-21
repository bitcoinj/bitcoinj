/*
 * Copyright 2011 Google Inc.
 * Copyright 2012 Matt Corallo.
 * Copyright 2014 Andreas Schildbach
 * Copyright 2017 Nicola Atzei
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

import org.bitcoinj.base.ScriptType;
import org.bitcoinj.base.utils.ByteUtils;
import org.bitcoinj.core.Address;
import org.bitcoinj.base.Coin;
import org.bitcoinj.core.ECKey;
import org.bitcoinj.core.LegacyAddress;
import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.core.ProtocolException;
import org.bitcoinj.core.SegwitAddress;
import org.bitcoinj.base.Sha256Hash;
import org.bitcoinj.core.SignatureDecodeException;
import org.bitcoinj.core.Transaction;
import org.bitcoinj.core.TransactionInput;
import org.bitcoinj.core.TransactionOutput;
import org.bitcoinj.core.TransactionWitness;
import org.bitcoinj.core.UnsafeByteArrayOutputStream;
import org.bitcoinj.core.Utils;
import org.bitcoinj.core.VarInt;
import org.bitcoinj.core.VerificationException;
import org.bitcoinj.core.internal.InternalUtils;
import org.bitcoinj.crypto.TransactionSignature;
import org.bouncycastle.crypto.digests.RIPEMD160Digest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.EnumSet;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.base.Preconditions.checkState;
import static org.bitcoinj.script.ScriptOpCodes.OP_0;
import static org.bitcoinj.script.ScriptOpCodes.OP_0NOTEQUAL;
import static org.bitcoinj.script.ScriptOpCodes.OP_1;
import static org.bitcoinj.script.ScriptOpCodes.OP_10;
import static org.bitcoinj.script.ScriptOpCodes.OP_11;
import static org.bitcoinj.script.ScriptOpCodes.OP_12;
import static org.bitcoinj.script.ScriptOpCodes.OP_13;
import static org.bitcoinj.script.ScriptOpCodes.OP_14;
import static org.bitcoinj.script.ScriptOpCodes.OP_15;
import static org.bitcoinj.script.ScriptOpCodes.OP_16;
import static org.bitcoinj.script.ScriptOpCodes.OP_1ADD;
import static org.bitcoinj.script.ScriptOpCodes.OP_1NEGATE;
import static org.bitcoinj.script.ScriptOpCodes.OP_1SUB;
import static org.bitcoinj.script.ScriptOpCodes.OP_2;
import static org.bitcoinj.script.ScriptOpCodes.OP_2DIV;
import static org.bitcoinj.script.ScriptOpCodes.OP_2DROP;
import static org.bitcoinj.script.ScriptOpCodes.OP_2DUP;
import static org.bitcoinj.script.ScriptOpCodes.OP_2MUL;
import static org.bitcoinj.script.ScriptOpCodes.OP_2OVER;
import static org.bitcoinj.script.ScriptOpCodes.OP_2ROT;
import static org.bitcoinj.script.ScriptOpCodes.OP_2SWAP;
import static org.bitcoinj.script.ScriptOpCodes.OP_3;
import static org.bitcoinj.script.ScriptOpCodes.OP_3DUP;
import static org.bitcoinj.script.ScriptOpCodes.OP_4;
import static org.bitcoinj.script.ScriptOpCodes.OP_5;
import static org.bitcoinj.script.ScriptOpCodes.OP_6;
import static org.bitcoinj.script.ScriptOpCodes.OP_7;
import static org.bitcoinj.script.ScriptOpCodes.OP_8;
import static org.bitcoinj.script.ScriptOpCodes.OP_9;
import static org.bitcoinj.script.ScriptOpCodes.OP_ABS;
import static org.bitcoinj.script.ScriptOpCodes.OP_ADD;
import static org.bitcoinj.script.ScriptOpCodes.OP_AND;
import static org.bitcoinj.script.ScriptOpCodes.OP_BOOLAND;
import static org.bitcoinj.script.ScriptOpCodes.OP_BOOLOR;
import static org.bitcoinj.script.ScriptOpCodes.OP_CAT;
import static org.bitcoinj.script.ScriptOpCodes.OP_CHECKLOCKTIMEVERIFY;
import static org.bitcoinj.script.ScriptOpCodes.OP_CHECKMULTISIG;
import static org.bitcoinj.script.ScriptOpCodes.OP_CHECKMULTISIGVERIFY;
import static org.bitcoinj.script.ScriptOpCodes.OP_CHECKSEQUENCEVERIFY;
import static org.bitcoinj.script.ScriptOpCodes.OP_CHECKSIG;
import static org.bitcoinj.script.ScriptOpCodes.OP_CHECKSIGVERIFY;
import static org.bitcoinj.script.ScriptOpCodes.OP_CODESEPARATOR;
import static org.bitcoinj.script.ScriptOpCodes.OP_DEPTH;
import static org.bitcoinj.script.ScriptOpCodes.OP_DIV;
import static org.bitcoinj.script.ScriptOpCodes.OP_DROP;
import static org.bitcoinj.script.ScriptOpCodes.OP_DUP;
import static org.bitcoinj.script.ScriptOpCodes.OP_ELSE;
import static org.bitcoinj.script.ScriptOpCodes.OP_ENDIF;
import static org.bitcoinj.script.ScriptOpCodes.OP_EQUAL;
import static org.bitcoinj.script.ScriptOpCodes.OP_EQUALVERIFY;
import static org.bitcoinj.script.ScriptOpCodes.OP_FROMALTSTACK;
import static org.bitcoinj.script.ScriptOpCodes.OP_GREATERTHAN;
import static org.bitcoinj.script.ScriptOpCodes.OP_GREATERTHANOREQUAL;
import static org.bitcoinj.script.ScriptOpCodes.OP_HASH160;
import static org.bitcoinj.script.ScriptOpCodes.OP_HASH256;
import static org.bitcoinj.script.ScriptOpCodes.OP_IF;
import static org.bitcoinj.script.ScriptOpCodes.OP_IFDUP;
import static org.bitcoinj.script.ScriptOpCodes.OP_INVALIDOPCODE;
import static org.bitcoinj.script.ScriptOpCodes.OP_INVERT;
import static org.bitcoinj.script.ScriptOpCodes.OP_LEFT;
import static org.bitcoinj.script.ScriptOpCodes.OP_LESSTHAN;
import static org.bitcoinj.script.ScriptOpCodes.OP_LESSTHANOREQUAL;
import static org.bitcoinj.script.ScriptOpCodes.OP_LSHIFT;
import static org.bitcoinj.script.ScriptOpCodes.OP_MAX;
import static org.bitcoinj.script.ScriptOpCodes.OP_MIN;
import static org.bitcoinj.script.ScriptOpCodes.OP_MOD;
import static org.bitcoinj.script.ScriptOpCodes.OP_MUL;
import static org.bitcoinj.script.ScriptOpCodes.OP_NEGATE;
import static org.bitcoinj.script.ScriptOpCodes.OP_NIP;
import static org.bitcoinj.script.ScriptOpCodes.OP_NOP;
import static org.bitcoinj.script.ScriptOpCodes.OP_NOP1;
import static org.bitcoinj.script.ScriptOpCodes.OP_NOP10;
import static org.bitcoinj.script.ScriptOpCodes.OP_NOP4;
import static org.bitcoinj.script.ScriptOpCodes.OP_NOP5;
import static org.bitcoinj.script.ScriptOpCodes.OP_NOP6;
import static org.bitcoinj.script.ScriptOpCodes.OP_NOP7;
import static org.bitcoinj.script.ScriptOpCodes.OP_NOP8;
import static org.bitcoinj.script.ScriptOpCodes.OP_NOP9;
import static org.bitcoinj.script.ScriptOpCodes.OP_NOT;
import static org.bitcoinj.script.ScriptOpCodes.OP_NOTIF;
import static org.bitcoinj.script.ScriptOpCodes.OP_NUMEQUAL;
import static org.bitcoinj.script.ScriptOpCodes.OP_NUMEQUALVERIFY;
import static org.bitcoinj.script.ScriptOpCodes.OP_NUMNOTEQUAL;
import static org.bitcoinj.script.ScriptOpCodes.OP_OR;
import static org.bitcoinj.script.ScriptOpCodes.OP_OVER;
import static org.bitcoinj.script.ScriptOpCodes.OP_PICK;
import static org.bitcoinj.script.ScriptOpCodes.OP_PUSHDATA1;
import static org.bitcoinj.script.ScriptOpCodes.OP_PUSHDATA2;
import static org.bitcoinj.script.ScriptOpCodes.OP_PUSHDATA4;
import static org.bitcoinj.script.ScriptOpCodes.OP_RETURN;
import static org.bitcoinj.script.ScriptOpCodes.OP_RIGHT;
import static org.bitcoinj.script.ScriptOpCodes.OP_RIPEMD160;
import static org.bitcoinj.script.ScriptOpCodes.OP_ROLL;
import static org.bitcoinj.script.ScriptOpCodes.OP_ROT;
import static org.bitcoinj.script.ScriptOpCodes.OP_RSHIFT;
import static org.bitcoinj.script.ScriptOpCodes.OP_SHA1;
import static org.bitcoinj.script.ScriptOpCodes.OP_SHA256;
import static org.bitcoinj.script.ScriptOpCodes.OP_SIZE;
import static org.bitcoinj.script.ScriptOpCodes.OP_SUB;
import static org.bitcoinj.script.ScriptOpCodes.OP_SUBSTR;
import static org.bitcoinj.script.ScriptOpCodes.OP_SWAP;
import static org.bitcoinj.script.ScriptOpCodes.OP_TOALTSTACK;
import static org.bitcoinj.script.ScriptOpCodes.OP_TUCK;
import static org.bitcoinj.script.ScriptOpCodes.OP_VERIFY;
import static org.bitcoinj.script.ScriptOpCodes.OP_WITHIN;
import static org.bitcoinj.script.ScriptOpCodes.OP_XOR;

// TODO: Redesign this entire API to be more type safe and organised.

/**
 * <p>Programs embedded inside transactions that control redemption of payments.</p>
 *
 * <p>Bitcoin transactions don't specify what they do directly. Instead <a href="https://en.bitcoin.it/wiki/Script">a
 * small binary stack language</a> is used to define programs that when evaluated return whether the transaction
 * "accepts" or rejects the other transactions connected to it.</p>
 *
 * <p>In SPV mode, scripts are not run, because that would require all transactions to be available and lightweight
 * clients don't have that data. In full mode, this class is used to run the interpreted language. It also has
 * static methods for building scripts.</p>
 */
public class Script {

    /** Flags to pass to {@link Script#correctlySpends(Transaction, int, TransactionWitness, Coin, Script, Set)}.
     * Note currently only P2SH, DERSIG and NULLDUMMY are actually supported.
     */
    public enum VerifyFlag {
        P2SH, // Enable BIP16-style subscript evaluation.
        STRICTENC, // Passing a non-strict-DER signature or one with undefined hashtype to a checksig operation causes script failure.
        DERSIG, // Passing a non-strict-DER signature to a checksig operation causes script failure (softfork safe, BIP66 rule 1)
        LOW_S, // Passing a non-strict-DER signature or one with S > order/2 to a checksig operation causes script failure
        NULLDUMMY, // Verify dummy stack item consumed by CHECKMULTISIG is of zero-length.
        SIGPUSHONLY, // Using a non-push operator in the scriptSig causes script failure (softfork safe, BIP62 rule 2).
        MINIMALDATA, // Require minimal encodings for all push operations
        DISCOURAGE_UPGRADABLE_NOPS, // Discourage use of NOPs reserved for upgrades (NOP1-10)
        CLEANSTACK, // Require that only a single stack element remains after evaluation.
        CHECKLOCKTIMEVERIFY, // Enable CHECKLOCKTIMEVERIFY operation
        CHECKSEQUENCEVERIFY // Enable CHECKSEQUENCEVERIFY operation
    }
    public static final EnumSet<VerifyFlag> ALL_VERIFY_FLAGS = EnumSet.allOf(VerifyFlag.class);

    private static final Logger log = LoggerFactory.getLogger(Script.class);
    public static final long MAX_SCRIPT_ELEMENT_SIZE = 520;  // bytes
    private static final int MAX_OPS_PER_SCRIPT = 201;
    private static final int MAX_STACK_SIZE = 1000;
    private static final int MAX_PUBKEYS_PER_MULTISIG = 20;
    private static final int MAX_SCRIPT_SIZE = 10000;
    public static final int SIG_SIZE = 75;
    /** Max number of sigops allowed in a standard p2sh redeem script */
    public static final int MAX_P2SH_SIGOPS = 15;

    // The program is a set of chunks where each element is either [opcode] or [data, data, data ...]
    protected List<ScriptChunk> chunks;
    // Unfortunately, scripts are not ever re-serialized or canonicalized when used in signature hashing. Thus we
    // must preserve the exact bytes that we read off the wire, along with the parsed form.
    protected byte[] program;

    // Creation time of the associated keys in seconds since the epoch.
    private long creationTimeSeconds;

    /** Creates an empty script that serializes to nothing. */
    private Script() {
        chunks = new ArrayList<>();
    }

    // Used from ScriptBuilder.
    Script(List<ScriptChunk> chunks) {
        this.chunks = Collections.unmodifiableList(new ArrayList<>(chunks));
        creationTimeSeconds = Utils.currentTimeSeconds();
    }

    /**
     * Construct a Script that copies and wraps the programBytes array. The array is parsed and checked for syntactic
     * validity.
     * @param programBytes Array of program bytes from a transaction.
     */
    public Script(byte[] programBytes) throws ScriptException {
        program = programBytes;
        parse(programBytes);
        creationTimeSeconds = 0;
    }

    public Script(byte[] programBytes, long creationTimeSeconds) throws ScriptException {
        program = programBytes;
        parse(programBytes);
        this.creationTimeSeconds = creationTimeSeconds;
    }

    public long getCreationTimeSeconds() {
        return creationTimeSeconds;
    }

    public void setCreationTimeSeconds(long creationTimeSeconds) {
        this.creationTimeSeconds = creationTimeSeconds;
    }

    /**
     * Returns the program opcodes as a string, for example "[1234] DUP HASH160", or "&lt;empty&gt;".
     */
    @Override
    public String toString() {
        if (!chunks.isEmpty())
            return InternalUtils.SPACE_JOINER.join(chunks);
        else
            return "<empty>";
    }

    /** Returns the serialized program as a newly created byte array. */
    public byte[] getProgram() {
        try {
            // Don't round-trip as Bitcoin Core doesn't and it would introduce a mismatch.
            if (program != null)
                return Arrays.copyOf(program, program.length);
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            for (ScriptChunk chunk : chunks) {
                chunk.write(bos);
            }
            program = bos.toByteArray();
            return program;
        } catch (IOException e) {
            throw new RuntimeException(e);  // Cannot happen.
        }
    }

    /** Returns an immutable list of the scripts parsed form. Each chunk is either an opcode or data element. */
    public List<ScriptChunk> getChunks() {
        return Collections.unmodifiableList(chunks);
    }

    private static final ScriptChunk[] STANDARD_TRANSACTION_SCRIPT_CHUNKS = {
        new ScriptChunk(ScriptOpCodes.OP_DUP, null),
        new ScriptChunk(ScriptOpCodes.OP_HASH160, null),
        new ScriptChunk(ScriptOpCodes.OP_EQUALVERIFY, null),
        new ScriptChunk(ScriptOpCodes.OP_CHECKSIG, null),
    };

    /**
     * <p>To run a script, first we parse it which breaks it up into chunks representing pushes of data or logical
     * opcodes. Then we can run the parsed chunks.</p>
     *
     * <p>The reason for this split, instead of just interpreting directly, is to make it easier
     * to reach into a programs structure and pull out bits of data without having to run it.
     * This is necessary to render the to addresses of transactions in a user interface.
     * Bitcoin Core does something similar.</p>
     */
    private void parse(byte[] program) throws ScriptException {
        chunks = new ArrayList<>(5);   // Common size.
        ByteArrayInputStream bis = new ByteArrayInputStream(program);
        while (bis.available() > 0) {
            int opcode = bis.read();

            long dataToRead = -1;
            if (opcode >= 0 && opcode < OP_PUSHDATA1) {
                // Read some bytes of data, where how many is the opcode value itself.
                dataToRead = opcode;
            } else if (opcode == OP_PUSHDATA1) {
                if (bis.available() < 1) throw new ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "Unexpected end of script");
                dataToRead = bis.read();
            } else if (opcode == OP_PUSHDATA2) {
                // Read a short, then read that many bytes of data.
                if (bis.available() < 2) throw new ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "Unexpected end of script");
                dataToRead = ByteUtils.readUint16FromStream(bis);
            } else if (opcode == OP_PUSHDATA4) {
                // Read a uint32, then read that many bytes of data.
                // Though this is allowed, because its value cannot be > 520, it should never actually be used
                if (bis.available() < 4) throw new ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "Unexpected end of script");
                dataToRead = ByteUtils.readUint32FromStream(bis);
            }

            ScriptChunk chunk;
            if (dataToRead == -1) {
                chunk = new ScriptChunk(opcode, null);
            } else {
                if (dataToRead > bis.available())
                    throw new ScriptException(ScriptError.SCRIPT_ERR_BAD_OPCODE, "Push of data element that is larger than remaining data: " + dataToRead + " vs " + bis.available());
                byte[] data = new byte[(int)dataToRead];
                checkState(dataToRead == 0 || bis.read(data, 0, (int)dataToRead) == dataToRead);
                chunk = new ScriptChunk(opcode, data);
            }
            // Save some memory by eliminating redundant copies of the same chunk objects.
            for (ScriptChunk c : STANDARD_TRANSACTION_SCRIPT_CHUNKS) {
                if (c.equals(chunk)) chunk = c;
            }
            chunks.add(chunk);
        }
    }

    /** @deprecated use {@link ScriptPattern#isP2PK(Script)} */
    @Deprecated
    public boolean isSentToRawPubKey() {
        return ScriptPattern.isP2PK(this);
    }

    /** @deprecated use {@link ScriptPattern#isP2PKH(Script)} */
    @Deprecated
    public boolean isSentToAddress() {
        return ScriptPattern.isP2PKH(this);
    }

    /**
     * <p>If the program somehow pays to a hash, returns the hash.</p>
     * 
     * <p>Otherwise this method throws a ScriptException.</p>
     */
    public byte[] getPubKeyHash() throws ScriptException {
        if (ScriptPattern.isP2PKH(this))
            return ScriptPattern.extractHashFromP2PKH(this);
        else if (ScriptPattern.isP2SH(this))
            return ScriptPattern.extractHashFromP2SH(this);
        else if (ScriptPattern.isP2WH(this))
            return ScriptPattern.extractHashFromP2WH(this);
        else
            throw new ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "Script not in the standard scriptPubKey form");
    }

    /**
     * Gets the destination address from this script, if it's in the required form.
     */
    public Address getToAddress(NetworkParameters params) throws ScriptException {
        return getToAddress(params, false);
    }

    /**
     * Gets the destination address from this script, if it's in the required form.
     * 
     * @param forcePayToPubKey
     *            If true, allow payToPubKey to be casted to the corresponding address. This is useful if you prefer
     *            showing addresses rather than pubkeys.
     */
    public Address getToAddress(NetworkParameters params, boolean forcePayToPubKey) throws ScriptException {
        if (ScriptPattern.isP2PKH(this))
            return LegacyAddress.fromPubKeyHash(params, ScriptPattern.extractHashFromP2PKH(this));
        else if (ScriptPattern.isP2SH(this))
            return LegacyAddress.fromScriptHash(params, ScriptPattern.extractHashFromP2SH(this));
        else if (forcePayToPubKey && ScriptPattern.isP2PK(this))
            return LegacyAddress.fromKey(params, ECKey.fromPublicOnly(ScriptPattern.extractKeyFromP2PK(this)));
        else if (ScriptPattern.isP2WH(this))
            return SegwitAddress.fromHash(params, ScriptPattern.extractHashFromP2WH(this));
        else if (ScriptPattern.isP2TR(this))
            return SegwitAddress.fromProgram(params, 1, ScriptPattern.extractOutputKeyFromP2TR(this));
        else
            throw new ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "Cannot cast this script to an address");
    }

    ////////////////////// Interface for writing scripts from scratch ////////////////////////////////

    /**
     * Writes out the given byte buffer to the output stream with the correct opcode prefix
     * To write an integer call writeBytes(out, Utils.reverseBytes(Utils.encodeMPI(val, false)));
     */
    public static void writeBytes(OutputStream os, byte[] buf) throws IOException {
        if (buf.length < OP_PUSHDATA1) {
            os.write(buf.length);
            os.write(buf);
        } else if (buf.length < 256) {
            os.write(OP_PUSHDATA1);
            os.write(buf.length);
            os.write(buf);
        } else if (buf.length < 65536) {
            os.write(OP_PUSHDATA2);
            ByteUtils.uint16ToByteStreamLE(buf.length, os);
            os.write(buf);
        } else {
            throw new RuntimeException("Unimplemented");
        }
    }

    /** Creates a program that requires at least N of the given keys to sign, using OP_CHECKMULTISIG. */
    public static byte[] createMultiSigOutputScript(int threshold, List<ECKey> pubkeys) {
        checkArgument(threshold > 0);
        checkArgument(threshold <= pubkeys.size());
        checkArgument(pubkeys.size() <= 16);  // That's the max we can represent with a single opcode.
        if (pubkeys.size() > 3) {
            log.warn("Creating a multi-signature output that is non-standard: {} pubkeys, should be <= 3", pubkeys.size());
        }
        try {
            ByteArrayOutputStream bits = new ByteArrayOutputStream();
            bits.write(encodeToOpN(threshold));
            for (ECKey key : pubkeys) {
                writeBytes(bits, key.getPubKey());
            }
            bits.write(encodeToOpN(pubkeys.size()));
            bits.write(OP_CHECKMULTISIG);
            return bits.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException(e);  // Cannot happen.
        }
    }

    public static byte[] createInputScript(byte[] signature, byte[] pubkey) {
        try {
            // TODO: Do this by creating a Script *first* then having the script reassemble itself into bytes.
            ByteArrayOutputStream bits = new UnsafeByteArrayOutputStream(signature.length + pubkey.length + 2);
            writeBytes(bits, signature);
            writeBytes(bits, pubkey);
            return bits.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static byte[] createInputScript(byte[] signature) {
        try {
            // TODO: Do this by creating a Script *first* then having the script reassemble itself into bytes.
            ByteArrayOutputStream bits = new UnsafeByteArrayOutputStream(signature.length + 2);
            writeBytes(bits, signature);
            return bits.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Creates an incomplete scriptSig that, once filled with signatures, can redeem output containing this scriptPubKey.
     * Instead of the signatures resulting script has OP_0.
     * Having incomplete input script allows to pass around partially signed tx.
     * It is expected that this program later on will be updated with proper signatures.
     */
    public Script createEmptyInputScript(@Nullable ECKey key, @Nullable Script redeemScript) {
        if (ScriptPattern.isP2PKH(this)) {
            checkArgument(key != null, "Key required to create P2PKH input script");
            return ScriptBuilder.createInputScript(null, key);
        } else if (ScriptPattern.isP2WPKH(this)) {
            return ScriptBuilder.createEmpty();
        } else if (ScriptPattern.isP2PK(this)) {
            return ScriptBuilder.createInputScript(null);
        } else if (ScriptPattern.isP2SH(this)) {
            checkArgument(redeemScript != null, "Redeem script required to create P2SH input script");
            return ScriptBuilder.createP2SHMultiSigInputScript(null, redeemScript);
        } else {
            throw new ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "Do not understand script type: " + this);
        }
    }

    public TransactionWitness createEmptyWitness(ECKey key) {
        if (ScriptPattern.isP2WPKH(this)) {
            checkArgument(key != null, "Key required to create P2WPKH witness");
            return TransactionWitness.EMPTY;
        } else if (ScriptPattern.isP2PK(this) || ScriptPattern.isP2PKH(this)
                || ScriptPattern.isP2SH(this)) {
            return null; // no witness
        } else {
            throw new ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "Do not understand script type: " + this);
        }
    }

    /**
     * Returns a copy of the given scriptSig with the signature inserted in the given position.
     */
    public Script getScriptSigWithSignature(Script scriptSig, byte[] sigBytes, int index) {
        int sigsPrefixCount = 0;
        int sigsSuffixCount = 0;
        if (ScriptPattern.isP2SH(this)) {
            sigsPrefixCount = 1; // OP_0 <sig>* <redeemScript>
            sigsSuffixCount = 1;
        } else if (ScriptPattern.isSentToMultisig(this)) {
            sigsPrefixCount = 1; // OP_0 <sig>*
        } else if (ScriptPattern.isP2PKH(this)) {
            sigsSuffixCount = 1; // <sig> <pubkey>
        }
        return ScriptBuilder.updateScriptWithSignature(scriptSig, sigBytes, index, sigsPrefixCount, sigsSuffixCount);
    }


    /**
     * Returns the index where a signature by the key should be inserted.  Only applicable to
     * a P2SH scriptSig.
     */
    public int getSigInsertionIndex(Sha256Hash hash, ECKey signingKey) {
        // Iterate over existing signatures, skipping the initial OP_0, the final redeem script
        // and any placeholder OP_0 sigs.
        List<ScriptChunk> existingChunks = chunks.subList(1, chunks.size() - 1);
        ScriptChunk redeemScriptChunk = chunks.get(chunks.size() - 1);
        checkNotNull(redeemScriptChunk.data);
        Script redeemScript = new Script(redeemScriptChunk.data);

        int sigCount = 0;
        int myIndex = redeemScript.findKeyInRedeem(signingKey);
        for (ScriptChunk chunk : existingChunks) {
            if (chunk.opcode == OP_0) {
                // OP_0, skip
            } else {
                checkNotNull(chunk.data);
                try {
                    if (myIndex < redeemScript.findSigInRedeem(chunk.data, hash))
                        return sigCount;
                } catch (SignatureDecodeException e) {
                    // ignore
                }
                sigCount++;
            }
        }
        return sigCount;
    }

    private int findKeyInRedeem(ECKey key) {
        checkArgument(chunks.get(0).isOpCode()); // P2SH scriptSig
        int numKeys = Script.decodeFromOpN(chunks.get(chunks.size() - 2).opcode);
        for (int i = 0 ; i < numKeys ; i++) {
            if (Arrays.equals(chunks.get(1 + i).data, key.getPubKey())) {
                return i;
            }
        }

        throw new IllegalStateException("Could not find matching key " + key.toString() + " in script " + this);
    }

    /**
     * Returns a list of the keys required by this script, assuming a multi-sig script.
     *
     * @throws ScriptException if the script type is not understood or is pay to address or is P2SH (run this method on the "Redeem script" instead).
     */
    public List<ECKey> getPubKeys() {
        if (!ScriptPattern.isSentToMultisig(this))
            throw new ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "Only usable for multisig scripts.");

        ArrayList<ECKey> result = new ArrayList<>();
        int numKeys = Script.decodeFromOpN(chunks.get(chunks.size() - 2).opcode);
        for (int i = 0 ; i < numKeys ; i++)
            result.add(ECKey.fromPublicOnly(chunks.get(1 + i).data));
        return result;
    }

    private int findSigInRedeem(byte[] signatureBytes, Sha256Hash hash) throws SignatureDecodeException {
        checkArgument(chunks.get(0).isOpCode()); // P2SH scriptSig
        int numKeys = Script.decodeFromOpN(chunks.get(chunks.size() - 2).opcode);
        TransactionSignature signature = TransactionSignature.decodeFromBitcoin(signatureBytes, true, false);
        for (int i = 0 ; i < numKeys ; i++) {
            if (ECKey.fromPublicOnly(chunks.get(i + 1).data).verify(hash, signature)) {
                return i;
            }
        }

        throw new IllegalStateException("Could not find matching key for signature on " + hash.toString() + " sig " + ByteUtils.HEX.encode(signatureBytes));
    }



    ////////////////////// Interface used during verification of transactions/blocks ////////////////////////////////

    private static int getSigOpCount(List<ScriptChunk> chunks, boolean accurate) throws ScriptException {
        int sigOps = 0;
        int lastOpCode = OP_INVALIDOPCODE;
        for (ScriptChunk chunk : chunks) {
            if (chunk.isOpCode()) {
                switch (chunk.opcode) {
                case OP_CHECKSIG:
                case OP_CHECKSIGVERIFY:
                    sigOps++;
                    break;
                case OP_CHECKMULTISIG:
                case OP_CHECKMULTISIGVERIFY:
                    if (accurate && lastOpCode >= OP_1 && lastOpCode <= OP_16)
                        sigOps += decodeFromOpN(lastOpCode);
                    else
                        sigOps += 20;
                    break;
                default:
                    break;
                }
                lastOpCode = chunk.opcode;
            }
        }
        return sigOps;
    }

    public static int decodeFromOpN(int opcode) {
        checkArgument((opcode == OP_0 || opcode == OP_1NEGATE) || (opcode >= OP_1 && opcode <= OP_16),
                "decodeFromOpN called on non OP_N opcode: %s", ScriptOpCodes.getOpCodeName(opcode));
        if (opcode == OP_0)
            return 0;
        else if (opcode == OP_1NEGATE)
            return -1;
        else
            return opcode + 1 - OP_1;
    }

    public static int encodeToOpN(int value) {
        checkArgument(value >= -1 && value <= 16, "encodeToOpN called for " + value + " which we cannot encode in an opcode.");
        if (value == 0)
            return OP_0;
        else if (value == -1)
            return OP_1NEGATE;
        else
            return value - 1 + OP_1;
    }

    /**
     * Gets the count of regular SigOps in the script program (counting multisig ops as 20)
     */
    public static int getSigOpCount(byte[] program) throws ScriptException {
        Script script = new Script();
        try {
            script.parse(program);
        } catch (ScriptException e) {
            // Ignore errors and count up to the parse-able length
        }
        return getSigOpCount(script.chunks, false);
    }
    
    /**
     * Gets the count of P2SH Sig Ops in the Script scriptSig
     */
    public static long getP2SHSigOpCount(byte[] scriptSig) throws ScriptException {
        Script script = new Script();
        try {
            script.parse(scriptSig);
        } catch (ScriptException e) {
            // Ignore errors and count up to the parse-able length
        }
        for (int i = script.chunks.size() - 1; i >= 0; i--)
            if (!script.chunks.get(i).isOpCode()) {
                Script subScript =  new Script();
                subScript.parse(script.chunks.get(i).data);
                return getSigOpCount(subScript.chunks, true);
            }
        return 0;
    }

    /**
     * Returns number of signatures required to satisfy this script.
     */
    public int getNumberOfSignaturesRequiredToSpend() {
        if (ScriptPattern.isSentToMultisig(this)) {
            // for N of M CHECKMULTISIG script we will need N signatures to spend
            ScriptChunk nChunk = chunks.get(0);
            return Script.decodeFromOpN(nChunk.opcode);
        } else if (ScriptPattern.isP2PKH(this) || ScriptPattern.isP2PK(this)) {
            // P2PKH and P2PK require single sig
            return 1;
        } else if (ScriptPattern.isP2SH(this)) {
            throw new IllegalStateException("For P2SH number of signatures depends on redeem script");
        } else {
            throw new IllegalStateException("Unsupported script type");
        }
    }

    /**
     * Returns number of bytes required to spend this script. It accepts optional ECKey and redeemScript that may
     * be required for certain types of script to estimate target size.
     */
    public int getNumberOfBytesRequiredToSpend(@Nullable ECKey pubKey, @Nullable Script redeemScript) {
        if (ScriptPattern.isP2SH(this)) {
            // scriptSig: <sig> [sig] [sig...] <redeemscript>
            checkArgument(redeemScript != null, "P2SH script requires redeemScript to be spent");
            return redeemScript.getNumberOfSignaturesRequiredToSpend() * SIG_SIZE + redeemScript.getProgram().length;
        } else if (ScriptPattern.isSentToMultisig(this)) {
            // scriptSig: OP_0 <sig> [sig] [sig...]
            return getNumberOfSignaturesRequiredToSpend() * SIG_SIZE + 1;
        } else if (ScriptPattern.isP2PK(this)) {
            // scriptSig: <sig>
            return SIG_SIZE;
        } else if (ScriptPattern.isP2PKH(this)) {
            // scriptSig: <sig> <pubkey>
            int uncompressedPubKeySize = 65; // very conservative
            return SIG_SIZE + (pubKey != null ? pubKey.getPubKey().length : uncompressedPubKeySize);
        } else if (ScriptPattern.isP2WPKH(this)) {
            // scriptSig is empty
            // witness: <sig> <pubKey>
            int compressedPubKeySize = 33;
            int publicKeyLength = pubKey != null ? pubKey.getPubKey().length : compressedPubKeySize;
            return VarInt.sizeOf(2) // number of witness pushes
                    + VarInt.sizeOf(SIG_SIZE) // size of signature push
                    + SIG_SIZE // signature push
                    + VarInt.sizeOf(publicKeyLength) // size of pubKey push
                    + publicKeyLength; // pubKey push
        } else {
            throw new IllegalStateException("Unsupported script type");
        }
    }

    /** @deprecated use {@link ScriptPattern#isP2SH(Script)} */
    @Deprecated
    public boolean isPayToScriptHash() {
        return ScriptPattern.isP2SH(this);
    }

    /** @deprecated use {@link ScriptPattern#isSentToMultisig(Script)} */
    @Deprecated
    public boolean isSentToMultiSig() {
        return ScriptPattern.isSentToMultisig(this);
    }

    private static boolean equalsRange(byte[] a, int start, byte[] b) {
        if (start + b.length > a.length)
            return false;
        for (int i = 0; i < b.length; i++)
            if (a[i + start] != b[i])
                return false;
        return true;
    }
    
    /**
     * Returns the script bytes of inputScript with all instances of the specified script object removed
     */
    public static byte[] removeAllInstancesOf(byte[] inputScript, byte[] chunkToRemove) {
        // We usually don't end up removing anything
        UnsafeByteArrayOutputStream bos = new UnsafeByteArrayOutputStream(inputScript.length);

        int cursor = 0;
        while (cursor < inputScript.length) {
            boolean skip = equalsRange(inputScript, cursor, chunkToRemove);
            
            int opcode = inputScript[cursor++] & 0xFF;
            int additionalBytes = 0;
            if (opcode >= 0 && opcode < OP_PUSHDATA1) {
                additionalBytes = opcode;
            } else if (opcode == OP_PUSHDATA1) {
                additionalBytes = (0xFF & inputScript[cursor]) + 1;
            } else if (opcode == OP_PUSHDATA2) {
                additionalBytes = ByteUtils.readUint16(inputScript, cursor) + 2;
            } else if (opcode == OP_PUSHDATA4) {
                additionalBytes = (int) ByteUtils.readUint32(inputScript, cursor) + 4;
            }
            if (!skip) {
                try {
                    bos.write(opcode);
                    bos.write(Arrays.copyOfRange(inputScript, cursor, cursor + additionalBytes));
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            }
            cursor += additionalBytes;
        }
        return bos.toByteArray();
    }
    
    /**
     * Returns the script bytes of inputScript with all instances of the given op code removed
     */
    public static byte[] removeAllInstancesOfOp(byte[] inputScript, int opCode) {
        return removeAllInstancesOf(inputScript, new byte[] {(byte)opCode});
    }
    
    ////////////////////// Script verification and helpers ////////////////////////////////
    
    private static boolean castToBool(byte[] data) {
        for (int i = 0; i < data.length; i++)
        {
            // "Can be negative zero" - Bitcoin Core (see OpenSSL's BN_bn2mpi)
            if (data[i] != 0)
                return !(i == data.length - 1 && (data[i] & 0xFF) == 0x80);
        }
        return false;
    }

    /**
     * Cast a script chunk to a BigInteger.
     *
     * @see #castToBigInteger(byte[], int, boolean) for values with different maximum
     * sizes.
     * @throws ScriptException if the chunk is longer than 4 bytes.
     */
    private static BigInteger castToBigInteger(byte[] chunk, final boolean requireMinimal) throws ScriptException {
        return castToBigInteger(chunk, 4, requireMinimal);
    }

    /**
     * Cast a script chunk to a BigInteger. Normally you would want
     * {@link #castToBigInteger(byte[], boolean)} instead, this is only for cases where
     * the normal maximum length does not apply (i.e. CHECKLOCKTIMEVERIFY, CHECKSEQUENCEVERIFY).
     *
     * @param maxLength the maximum length in bytes.
     * @param requireMinimal check if the number is encoded with the minimum possible number of bytes
     * @throws ScriptException if the chunk is longer than the specified maximum.
     */
    /* package private */ static BigInteger castToBigInteger(final byte[] chunk, final int maxLength, final boolean requireMinimal) throws ScriptException {
        if (chunk.length > maxLength)
            throw new ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "Script attempted to use an integer larger than " + maxLength + " bytes");

        if (requireMinimal && chunk.length > 0) {
            // Check that the number is encoded with the minimum possible
            // number of bytes.
            //
            // If the most-significant-byte - excluding the sign bit - is zero
            // then we're not minimal. Note how this test also rejects the
            // negative-zero encoding, 0x80.
            if ((chunk[chunk.length - 1] & 0x7f) == 0) {
                // One exception: if there's more than one byte and the most
                // significant bit of the second-most-significant-byte is set
                // it would conflict with the sign bit. An example of this case
                // is +-255, which encode to 0xff00 and 0xff80 respectively.
                // (big-endian).
                if (chunk.length <= 1 || (chunk[chunk.length - 2] & 0x80) == 0) {
                    throw  new ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "non-minimally encoded script number");
                }
            }
        }

        return ByteUtils.decodeMPI(ByteUtils.reverseBytes(chunk), false);
    }

    /** @deprecated use {@link ScriptPattern#isOpReturn(Script)} */
    @Deprecated
    public boolean isOpReturn() {
        return ScriptPattern.isOpReturn(this);
    }

    /**
     * Exposes the script interpreter. Normally you should not use this directly, instead use
     * {@link TransactionInput#verify(TransactionOutput)} or
     * {@link Script#correctlySpends(Transaction, int, TransactionWitness, Coin, Script, Set)}. This method
     * is useful if you need more precise control or access to the final state of the stack. This interface is very
     * likely to change in future.
     *
     * @deprecated Use {@link #executeScript(Transaction, long, Script, LinkedList, Set)}
     * instead.
     */
    @Deprecated
    public static void executeScript(@Nullable Transaction txContainingThis, long index,
                                     Script script, LinkedList<byte[]> stack, boolean enforceNullDummy) throws ScriptException {
        final EnumSet<VerifyFlag> flags = enforceNullDummy
            ? EnumSet.of(VerifyFlag.NULLDUMMY)
            : EnumSet.noneOf(VerifyFlag.class);

        executeScript(txContainingThis, index, script, stack, flags);
    }

    /**
     * Exposes the script interpreter. Normally you should not use this directly, instead use
     * {@link TransactionInput#verify(TransactionOutput)} or
     * {@link Script#correctlySpends(Transaction, int, TransactionWitness, Coin, Script, Set)}. This method
     * is useful if you need more precise control or access to the final state of the stack. This interface is very
     * likely to change in future.
     */
    public static void executeScript(@Nullable Transaction txContainingThis, long index,
                                     Script script, LinkedList<byte[]> stack, Set<VerifyFlag> verifyFlags) throws ScriptException {
        int opCount = 0;
        int lastCodeSepLocation = 0;
        
        LinkedList<byte[]> altstack = new LinkedList<>();
        LinkedList<Boolean> ifStack = new LinkedList<>();

        int nextLocationInScript = 0;
        for (ScriptChunk chunk : script.chunks) {
            boolean shouldExecute = !ifStack.contains(false);
            int opcode = chunk.opcode;
            nextLocationInScript += chunk.size();

            // Check stack element size
            if (chunk.data != null && chunk.data.length > MAX_SCRIPT_ELEMENT_SIZE)
                throw new ScriptException(ScriptError.SCRIPT_ERR_PUSH_SIZE, "Attempted to push a data string larger than 520 bytes");

            // Note how OP_RESERVED does not count towards the opcode limit.
            if (opcode > OP_16) {
                opCount++;
                if (opCount > MAX_OPS_PER_SCRIPT)
                    throw new ScriptException(ScriptError.SCRIPT_ERR_OP_COUNT, "More script operations than is allowed");
            }

            // Disabled opcodes.
            if (opcode == OP_CAT || opcode == OP_SUBSTR || opcode == OP_LEFT || opcode == OP_RIGHT ||
                    opcode == OP_INVERT || opcode == OP_AND || opcode == OP_OR || opcode == OP_XOR ||
                    opcode == OP_2MUL || opcode == OP_2DIV || opcode == OP_MUL || opcode == OP_DIV ||
                    opcode == OP_MOD || opcode == OP_LSHIFT || opcode == OP_RSHIFT)
                throw new ScriptException(ScriptError.SCRIPT_ERR_DISABLED_OPCODE,
                        "Script included disabled Script Op " + ScriptOpCodes.getOpCodeName(opcode));

            if (shouldExecute && OP_0 <= opcode && opcode <= OP_PUSHDATA4) {
                // Check minimal push
                if (verifyFlags.contains(VerifyFlag.MINIMALDATA) && !chunk.isShortestPossiblePushData())
                    throw new ScriptException(ScriptError.SCRIPT_ERR_MINIMALDATA, "Script included a not minimal push operation.");

                if (opcode == OP_0)
                    stack.add(new byte[]{});
                else
                    stack.add(chunk.data);
            } else if (shouldExecute || (OP_IF <= opcode && opcode <= OP_ENDIF)){

                switch (opcode) {
                case OP_IF:
                    if (!shouldExecute) {
                        ifStack.add(false);
                        continue;
                    }
                    if (stack.size() < 1)
                        throw new ScriptException(ScriptError.SCRIPT_ERR_UNBALANCED_CONDITIONAL, "Attempted OP_IF on an empty stack");
                    ifStack.add(castToBool(stack.pollLast()));
                    continue;
                case OP_NOTIF:
                    if (!shouldExecute) {
                        ifStack.add(false);
                        continue;
                    }
                    if (stack.size() < 1)
                        throw new ScriptException(ScriptError.SCRIPT_ERR_UNBALANCED_CONDITIONAL, "Attempted OP_NOTIF on an empty stack");
                    ifStack.add(!castToBool(stack.pollLast()));
                    continue;
                case OP_ELSE:
                    if (ifStack.isEmpty())
                        throw new ScriptException(ScriptError.SCRIPT_ERR_UNBALANCED_CONDITIONAL, "Attempted OP_ELSE without OP_IF/NOTIF");
                    ifStack.add(!ifStack.pollLast());
                    continue;
                case OP_ENDIF:
                    if (ifStack.isEmpty())
                        throw new ScriptException(ScriptError.SCRIPT_ERR_UNBALANCED_CONDITIONAL, "Attempted OP_ENDIF without OP_IF/NOTIF");
                    ifStack.pollLast();
                    continue;

                // OP_0 is no opcode
                case OP_1NEGATE:
                    stack.add(ByteUtils.reverseBytes(ByteUtils.encodeMPI(BigInteger.ONE.negate(), false)));
                    break;
                case OP_1:
                case OP_2:
                case OP_3:
                case OP_4:
                case OP_5:
                case OP_6:
                case OP_7:
                case OP_8:
                case OP_9:
                case OP_10:
                case OP_11:
                case OP_12:
                case OP_13:
                case OP_14:
                case OP_15:
                case OP_16:
                    stack.add(ByteUtils.reverseBytes(ByteUtils.encodeMPI(BigInteger.valueOf(decodeFromOpN(opcode)), false)));
                    break;
                case OP_NOP:
                    break;
                case OP_VERIFY:
                    if (stack.size() < 1)
                        throw new ScriptException(ScriptError.SCRIPT_ERR_INVALID_STACK_OPERATION, "Attempted OP_VERIFY on an empty stack");
                    if (!castToBool(stack.pollLast()))
                        throw new ScriptException(ScriptError.SCRIPT_ERR_VERIFY, "OP_VERIFY failed");
                    break;
                case OP_RETURN:
                    throw new ScriptException(ScriptError.SCRIPT_ERR_OP_RETURN, "Script called OP_RETURN");
                case OP_TOALTSTACK:
                    if (stack.size() < 1)
                        throw new ScriptException(ScriptError.SCRIPT_ERR_INVALID_STACK_OPERATION, "Attempted OP_TOALTSTACK on an empty stack");
                    altstack.add(stack.pollLast());
                    break;
                case OP_FROMALTSTACK:
                    if (altstack.size() < 1)
                        throw new ScriptException(ScriptError.SCRIPT_ERR_INVALID_ALTSTACK_OPERATION, "Attempted OP_FROMALTSTACK on an empty altstack");
                    stack.add(altstack.pollLast());
                    break;
                case OP_2DROP:
                    if (stack.size() < 2)
                        throw new ScriptException(ScriptError.SCRIPT_ERR_INVALID_STACK_OPERATION, "Attempted OP_2DROP on a stack with size < 2");
                    stack.pollLast();
                    stack.pollLast();
                    break;
                case OP_2DUP:
                    if (stack.size() < 2)
                        throw new ScriptException(ScriptError.SCRIPT_ERR_INVALID_STACK_OPERATION, "Attempted OP_2DUP on a stack with size < 2");
                    Iterator<byte[]> it2DUP = stack.descendingIterator();
                    byte[] OP2DUPtmpChunk2 = it2DUP.next();
                    stack.add(it2DUP.next());
                    stack.add(OP2DUPtmpChunk2);
                    break;
                case OP_3DUP:
                    if (stack.size() < 3)
                        throw new ScriptException(ScriptError.SCRIPT_ERR_INVALID_STACK_OPERATION, "Attempted OP_3DUP on a stack with size < 3");
                    Iterator<byte[]> it3DUP = stack.descendingIterator();
                    byte[] OP3DUPtmpChunk3 = it3DUP.next();
                    byte[] OP3DUPtmpChunk2 = it3DUP.next();
                    stack.add(it3DUP.next());
                    stack.add(OP3DUPtmpChunk2);
                    stack.add(OP3DUPtmpChunk3);
                    break;
                case OP_2OVER:
                    if (stack.size() < 4)
                        throw new ScriptException(ScriptError.SCRIPT_ERR_INVALID_STACK_OPERATION, "Attempted OP_2OVER on a stack with size < 4");
                    Iterator<byte[]> it2OVER = stack.descendingIterator();
                    it2OVER.next();
                    it2OVER.next();
                    byte[] OP2OVERtmpChunk2 = it2OVER.next();
                    stack.add(it2OVER.next());
                    stack.add(OP2OVERtmpChunk2);
                    break;
                case OP_2ROT:
                    if (stack.size() < 6)
                        throw new ScriptException(ScriptError.SCRIPT_ERR_INVALID_STACK_OPERATION, "Attempted OP_2ROT on a stack with size < 6");
                    byte[] OP2ROTtmpChunk6 = stack.pollLast();
                    byte[] OP2ROTtmpChunk5 = stack.pollLast();
                    byte[] OP2ROTtmpChunk4 = stack.pollLast();
                    byte[] OP2ROTtmpChunk3 = stack.pollLast();
                    byte[] OP2ROTtmpChunk2 = stack.pollLast();
                    byte[] OP2ROTtmpChunk1 = stack.pollLast();
                    stack.add(OP2ROTtmpChunk3);
                    stack.add(OP2ROTtmpChunk4);
                    stack.add(OP2ROTtmpChunk5);
                    stack.add(OP2ROTtmpChunk6);
                    stack.add(OP2ROTtmpChunk1);
                    stack.add(OP2ROTtmpChunk2);
                    break;
                case OP_2SWAP:
                    if (stack.size() < 4)
                        throw new ScriptException(ScriptError.SCRIPT_ERR_INVALID_STACK_OPERATION, "Attempted OP_2SWAP on a stack with size < 4");
                    byte[] OP2SWAPtmpChunk4 = stack.pollLast();
                    byte[] OP2SWAPtmpChunk3 = stack.pollLast();
                    byte[] OP2SWAPtmpChunk2 = stack.pollLast();
                    byte[] OP2SWAPtmpChunk1 = stack.pollLast();
                    stack.add(OP2SWAPtmpChunk3);
                    stack.add(OP2SWAPtmpChunk4);
                    stack.add(OP2SWAPtmpChunk1);
                    stack.add(OP2SWAPtmpChunk2);
                    break;
                case OP_IFDUP:
                    if (stack.size() < 1)
                        throw new ScriptException(ScriptError.SCRIPT_ERR_INVALID_STACK_OPERATION, "Attempted OP_IFDUP on an empty stack");
                    if (castToBool(stack.getLast()))
                        stack.add(stack.getLast());
                    break;
                case OP_DEPTH:
                    stack.add(ByteUtils.reverseBytes(ByteUtils.encodeMPI(BigInteger.valueOf(stack.size()), false)));
                    break;
                case OP_DROP:
                    if (stack.size() < 1)
                        throw new ScriptException(ScriptError.SCRIPT_ERR_INVALID_STACK_OPERATION, "Attempted OP_DROP on an empty stack");
                    stack.pollLast();
                    break;
                case OP_DUP:
                    if (stack.size() < 1)
                        throw new ScriptException(ScriptError.SCRIPT_ERR_INVALID_STACK_OPERATION, "Attempted OP_DUP on an empty stack");
                    stack.add(stack.getLast());
                    break;
                case OP_NIP:
                    if (stack.size() < 2)
                        throw new ScriptException(ScriptError.SCRIPT_ERR_INVALID_STACK_OPERATION, "Attempted OP_NIP on a stack with size < 2");
                    byte[] OPNIPtmpChunk = stack.pollLast();
                    stack.pollLast();
                    stack.add(OPNIPtmpChunk);
                    break;
                case OP_OVER:
                    if (stack.size() < 2)
                        throw new ScriptException(ScriptError.SCRIPT_ERR_INVALID_STACK_OPERATION, "Attempted OP_OVER on a stack with size < 2");
                    Iterator<byte[]> itOVER = stack.descendingIterator();
                    itOVER.next();
                    stack.add(itOVER.next());
                    break;
                case OP_PICK:
                case OP_ROLL:
                    if (stack.size() < 1)
                        throw new ScriptException(ScriptError.SCRIPT_ERR_INVALID_STACK_OPERATION, "Attempted OP_PICK/OP_ROLL on an empty stack");
                    long val = castToBigInteger(stack.pollLast(), verifyFlags.contains(VerifyFlag.MINIMALDATA)).longValue();
                    if (val < 0 || val >= stack.size())
                        throw new ScriptException(ScriptError.SCRIPT_ERR_INVALID_STACK_OPERATION, "OP_PICK/OP_ROLL attempted to get data deeper than stack size");
                    Iterator<byte[]> itPICK = stack.descendingIterator();
                    for (long i = 0; i < val; i++)
                        itPICK.next();
                    byte[] OPROLLtmpChunk = itPICK.next();
                    if (opcode == OP_ROLL)
                        itPICK.remove();
                    stack.add(OPROLLtmpChunk);
                    break;
                case OP_ROT:
                    if (stack.size() < 3)
                        throw new ScriptException(ScriptError.SCRIPT_ERR_INVALID_STACK_OPERATION, "Attempted OP_ROT on a stack with size < 3");
                    byte[] OPROTtmpChunk3 = stack.pollLast();
                    byte[] OPROTtmpChunk2 = stack.pollLast();
                    byte[] OPROTtmpChunk1 = stack.pollLast();
                    stack.add(OPROTtmpChunk2);
                    stack.add(OPROTtmpChunk3);
                    stack.add(OPROTtmpChunk1);
                    break;
                case OP_SWAP:
                case OP_TUCK:
                    if (stack.size() < 2)
                        throw new ScriptException(ScriptError.SCRIPT_ERR_INVALID_STACK_OPERATION, "Attempted OP_SWAP on a stack with size < 2");
                    byte[] OPSWAPtmpChunk2 = stack.pollLast();
                    byte[] OPSWAPtmpChunk1 = stack.pollLast();
                    stack.add(OPSWAPtmpChunk2);
                    stack.add(OPSWAPtmpChunk1);
                    if (opcode == OP_TUCK)
                        stack.add(OPSWAPtmpChunk2);
                    break;
                case OP_SIZE:
                    if (stack.size() < 1)
                        throw new ScriptException(ScriptError.SCRIPT_ERR_INVALID_STACK_OPERATION, "Attempted OP_SIZE on an empty stack");
                    stack.add(ByteUtils.reverseBytes(ByteUtils.encodeMPI(BigInteger.valueOf(stack.getLast().length), false)));
                    break;
                case OP_EQUAL:
                    if (stack.size() < 2)
                        throw new ScriptException(ScriptError.SCRIPT_ERR_INVALID_STACK_OPERATION, "Attempted OP_EQUAL on a stack with size < 2");
                    stack.add(Arrays.equals(stack.pollLast(), stack.pollLast()) ? new byte[] {1} : new byte[] {});
                    break;
                case OP_EQUALVERIFY:
                    if (stack.size() < 2)
                        throw new ScriptException(ScriptError.SCRIPT_ERR_INVALID_STACK_OPERATION, "Attempted OP_EQUALVERIFY on a stack with size < 2");
                    if (!Arrays.equals(stack.pollLast(), stack.pollLast()))
                        throw new ScriptException(ScriptError.SCRIPT_ERR_EQUALVERIFY, "OP_EQUALVERIFY: non-equal data");
                    break;
                case OP_1ADD:
                case OP_1SUB:
                case OP_NEGATE:
                case OP_ABS:
                case OP_NOT:
                case OP_0NOTEQUAL:
                    if (stack.size() < 1)
                        throw new ScriptException(ScriptError.SCRIPT_ERR_INVALID_STACK_OPERATION, "Attempted a numeric op on an empty stack");
                    BigInteger numericOPnum = castToBigInteger(stack.pollLast(), verifyFlags.contains(VerifyFlag.MINIMALDATA));
                                        
                    switch (opcode) {
                    case OP_1ADD:
                        numericOPnum = numericOPnum.add(BigInteger.ONE);
                        break;
                    case OP_1SUB:
                        numericOPnum = numericOPnum.subtract(BigInteger.ONE);
                        break;
                    case OP_NEGATE:
                        numericOPnum = numericOPnum.negate();
                        break;
                    case OP_ABS:
                        if (numericOPnum.signum() < 0)
                            numericOPnum = numericOPnum.negate();
                        break;
                    case OP_NOT:
                        if (numericOPnum.equals(BigInteger.ZERO))
                            numericOPnum = BigInteger.ONE;
                        else
                            numericOPnum = BigInteger.ZERO;
                        break;
                    case OP_0NOTEQUAL:
                        if (numericOPnum.equals(BigInteger.ZERO))
                            numericOPnum = BigInteger.ZERO;
                        else
                            numericOPnum = BigInteger.ONE;
                        break;
                    default:
                        throw new AssertionError("Unreachable");
                    }
                    
                    stack.add(ByteUtils.reverseBytes(ByteUtils.encodeMPI(numericOPnum, false)));
                    break;
                case OP_ADD:
                case OP_SUB:
                case OP_BOOLAND:
                case OP_BOOLOR:
                case OP_NUMEQUAL:
                case OP_NUMNOTEQUAL:
                case OP_LESSTHAN:
                case OP_GREATERTHAN:
                case OP_LESSTHANOREQUAL:
                case OP_GREATERTHANOREQUAL:
                case OP_MIN:
                case OP_MAX:
                    if (stack.size() < 2)
                        throw new ScriptException(ScriptError.SCRIPT_ERR_INVALID_STACK_OPERATION, "Attempted a numeric op on a stack with size < 2");
                    BigInteger numericOPnum2 = castToBigInteger(stack.pollLast(), verifyFlags.contains(VerifyFlag.MINIMALDATA));
                    BigInteger numericOPnum1 = castToBigInteger(stack.pollLast(), verifyFlags.contains(VerifyFlag.MINIMALDATA));

                    BigInteger numericOPresult;
                    switch (opcode) {
                    case OP_ADD:
                        numericOPresult = numericOPnum1.add(numericOPnum2);
                        break;
                    case OP_SUB:
                        numericOPresult = numericOPnum1.subtract(numericOPnum2);
                        break;
                    case OP_BOOLAND:
                        if (!numericOPnum1.equals(BigInteger.ZERO) && !numericOPnum2.equals(BigInteger.ZERO))
                            numericOPresult = BigInteger.ONE;
                        else
                            numericOPresult = BigInteger.ZERO;
                        break;
                    case OP_BOOLOR:
                        if (!numericOPnum1.equals(BigInteger.ZERO) || !numericOPnum2.equals(BigInteger.ZERO))
                            numericOPresult = BigInteger.ONE;
                        else
                            numericOPresult = BigInteger.ZERO;
                        break;
                    case OP_NUMEQUAL:
                        if (numericOPnum1.equals(numericOPnum2))
                            numericOPresult = BigInteger.ONE;
                        else
                            numericOPresult = BigInteger.ZERO;
                        break;
                    case OP_NUMNOTEQUAL:
                        if (!numericOPnum1.equals(numericOPnum2))
                            numericOPresult = BigInteger.ONE;
                        else
                            numericOPresult = BigInteger.ZERO;
                        break;
                    case OP_LESSTHAN:
                        if (numericOPnum1.compareTo(numericOPnum2) < 0)
                            numericOPresult = BigInteger.ONE;
                        else
                            numericOPresult = BigInteger.ZERO;
                        break;
                    case OP_GREATERTHAN:
                        if (numericOPnum1.compareTo(numericOPnum2) > 0)
                            numericOPresult = BigInteger.ONE;
                        else
                            numericOPresult = BigInteger.ZERO;
                        break;
                    case OP_LESSTHANOREQUAL:
                        if (numericOPnum1.compareTo(numericOPnum2) <= 0)
                            numericOPresult = BigInteger.ONE;
                        else
                            numericOPresult = BigInteger.ZERO;
                        break;
                    case OP_GREATERTHANOREQUAL:
                        if (numericOPnum1.compareTo(numericOPnum2) >= 0)
                            numericOPresult = BigInteger.ONE;
                        else
                            numericOPresult = BigInteger.ZERO;
                        break;
                    case OP_MIN:
                        if (numericOPnum1.compareTo(numericOPnum2) < 0)
                            numericOPresult = numericOPnum1;
                        else
                            numericOPresult = numericOPnum2;
                        break;
                    case OP_MAX:
                        if (numericOPnum1.compareTo(numericOPnum2) > 0)
                            numericOPresult = numericOPnum1;
                        else
                            numericOPresult = numericOPnum2;
                        break;
                    default:
                        throw new RuntimeException("Opcode switched at runtime?");
                    }
                    
                    stack.add(ByteUtils.reverseBytes(ByteUtils.encodeMPI(numericOPresult, false)));
                    break;
                case OP_NUMEQUALVERIFY:
                    if (stack.size() < 2)
                        throw new ScriptException(ScriptError.SCRIPT_ERR_INVALID_STACK_OPERATION, "Attempted OP_NUMEQUALVERIFY on a stack with size < 2");
                    BigInteger OPNUMEQUALVERIFYnum2 = castToBigInteger(stack.pollLast(), verifyFlags.contains(VerifyFlag.MINIMALDATA));
                    BigInteger OPNUMEQUALVERIFYnum1 = castToBigInteger(stack.pollLast(), verifyFlags.contains(VerifyFlag.MINIMALDATA));
                    
                    if (!OPNUMEQUALVERIFYnum1.equals(OPNUMEQUALVERIFYnum2))
                        throw new ScriptException(ScriptError.SCRIPT_ERR_NUMEQUALVERIFY, "OP_NUMEQUALVERIFY failed");
                    break;
                case OP_WITHIN:
                    if (stack.size() < 3)
                        throw new ScriptException(ScriptError.SCRIPT_ERR_INVALID_STACK_OPERATION, "Attempted OP_WITHIN on a stack with size < 3");
                    BigInteger OPWITHINnum3 = castToBigInteger(stack.pollLast(), verifyFlags.contains(VerifyFlag.MINIMALDATA));
                    BigInteger OPWITHINnum2 = castToBigInteger(stack.pollLast(), verifyFlags.contains(VerifyFlag.MINIMALDATA));
                    BigInteger OPWITHINnum1 = castToBigInteger(stack.pollLast(), verifyFlags.contains(VerifyFlag.MINIMALDATA));
                    if (OPWITHINnum2.compareTo(OPWITHINnum1) <= 0 && OPWITHINnum1.compareTo(OPWITHINnum3) < 0)
                        stack.add(ByteUtils.reverseBytes(ByteUtils.encodeMPI(BigInteger.ONE, false)));
                    else
                        stack.add(ByteUtils.reverseBytes(ByteUtils.encodeMPI(BigInteger.ZERO, false)));
                    break;
                case OP_RIPEMD160:
                    if (stack.size() < 1)
                        throw new ScriptException(ScriptError.SCRIPT_ERR_INVALID_STACK_OPERATION, "Attempted OP_RIPEMD160 on an empty stack");
                    RIPEMD160Digest digest = new RIPEMD160Digest();
                    byte[] dataToHash = stack.pollLast();
                    digest.update(dataToHash, 0, dataToHash.length);
                    byte[] ripmemdHash = new byte[20];
                    digest.doFinal(ripmemdHash, 0);
                    stack.add(ripmemdHash);
                    break;
                case OP_SHA1:
                    if (stack.size() < 1)
                        throw new ScriptException(ScriptError.SCRIPT_ERR_INVALID_STACK_OPERATION, "Attempted OP_SHA1 on an empty stack");
                    try {
                        stack.add(MessageDigest.getInstance("SHA-1").digest(stack.pollLast()));
                    } catch (NoSuchAlgorithmException e) {
                        throw new RuntimeException(e);  // Cannot happen.
                    }
                    break;
                case OP_SHA256:
                    if (stack.size() < 1)
                        throw new ScriptException(ScriptError.SCRIPT_ERR_INVALID_STACK_OPERATION, "Attempted OP_SHA256 on an empty stack");
                    stack.add(Sha256Hash.hash(stack.pollLast()));
                    break;
                case OP_HASH160:
                    if (stack.size() < 1)
                        throw new ScriptException(ScriptError.SCRIPT_ERR_INVALID_STACK_OPERATION, "Attempted OP_HASH160 on an empty stack");
                    stack.add(Utils.sha256hash160(stack.pollLast()));
                    break;
                case OP_HASH256:
                    if (stack.size() < 1)
                        throw new ScriptException(ScriptError.SCRIPT_ERR_INVALID_STACK_OPERATION, "Attempted OP_SHA256 on an empty stack");
                    stack.add(Sha256Hash.hashTwice(stack.pollLast()));
                    break;
                case OP_CODESEPARATOR:
                    lastCodeSepLocation = nextLocationInScript;
                    break;
                case OP_CHECKSIG:
                case OP_CHECKSIGVERIFY:
                    if (txContainingThis == null)
                        throw new IllegalStateException("Script attempted signature check but no tx was provided");
                    executeCheckSig(txContainingThis, (int) index, script, stack, lastCodeSepLocation, opcode, verifyFlags);
                    break;
                case OP_CHECKMULTISIG:
                case OP_CHECKMULTISIGVERIFY:
                    if (txContainingThis == null)
                        throw new IllegalStateException("Script attempted signature check but no tx was provided");
                    opCount = executeMultiSig(txContainingThis, (int) index, script, stack, opCount, lastCodeSepLocation, opcode, verifyFlags);
                    break;
                case OP_CHECKLOCKTIMEVERIFY:
                    if (!verifyFlags.contains(VerifyFlag.CHECKLOCKTIMEVERIFY)) {
                        // not enabled; treat as a NOP2
                        if (verifyFlags.contains(VerifyFlag.DISCOURAGE_UPGRADABLE_NOPS)) {
                            throw new ScriptException(ScriptError.SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS, "Script used a reserved opcode " + opcode);
                        }
                        break;
                    }
                    executeCheckLockTimeVerify(txContainingThis, (int) index, stack, verifyFlags);
                    break;
                case OP_CHECKSEQUENCEVERIFY:
                    if (!verifyFlags.contains(VerifyFlag.CHECKSEQUENCEVERIFY)) {
                        // not enabled; treat as a NOP3
                        if (verifyFlags.contains(VerifyFlag.DISCOURAGE_UPGRADABLE_NOPS)) {
                            throw new ScriptException(ScriptError.SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS, "Script used a reserved opcode " + opcode);
                        }
                        break;
                    }
                    executeCheckSequenceVerify(txContainingThis, (int) index, stack, verifyFlags);
                    break;
                case OP_NOP1:
                case OP_NOP4:
                case OP_NOP5:
                case OP_NOP6:
                case OP_NOP7:
                case OP_NOP8:
                case OP_NOP9:
                case OP_NOP10:
                    if (verifyFlags.contains(VerifyFlag.DISCOURAGE_UPGRADABLE_NOPS)) {
                        throw new ScriptException(ScriptError.SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS, "Script used a reserved opcode " + opcode);
                    }
                    break;
                    
                default:
                    throw new ScriptException(ScriptError.SCRIPT_ERR_BAD_OPCODE, "Script used a reserved or disabled opcode: " + opcode);
                }
            }
            
            if (stack.size() + altstack.size() > MAX_STACK_SIZE || stack.size() + altstack.size() < 0)
                throw new ScriptException(ScriptError.SCRIPT_ERR_STACK_SIZE, "Stack size exceeded range");
        }
        
        if (!ifStack.isEmpty())
            throw new ScriptException(ScriptError.SCRIPT_ERR_UNBALANCED_CONDITIONAL, "OP_IF/OP_NOTIF without OP_ENDIF");
    }

    // This is more or less a direct translation of the code in Bitcoin Core
    private static void executeCheckLockTimeVerify(Transaction txContainingThis, int index, LinkedList<byte[]> stack, Set<VerifyFlag> verifyFlags) throws ScriptException {
        if (stack.size() < 1)
            throw new ScriptException(ScriptError.SCRIPT_ERR_INVALID_STACK_OPERATION, "Attempted OP_CHECKLOCKTIMEVERIFY on a stack with size < 1");

        // Thus as a special case we tell CScriptNum to accept up
        // to 5-byte bignums to avoid year 2038 issue.
        final BigInteger nLockTime = castToBigInteger(stack.getLast(), 5, verifyFlags.contains(VerifyFlag.MINIMALDATA));

        if (nLockTime.compareTo(BigInteger.ZERO) < 0)
            throw new ScriptException(ScriptError.SCRIPT_ERR_NEGATIVE_LOCKTIME, "Negative locktime");

        // There are two kinds of nLockTime, need to ensure we're comparing apples-to-apples
        if (!(
            ((txContainingThis.getLockTime() <  Transaction.LOCKTIME_THRESHOLD) && (nLockTime.compareTo(Transaction.LOCKTIME_THRESHOLD_BIG)) < 0) ||
            ((txContainingThis.getLockTime() >= Transaction.LOCKTIME_THRESHOLD) && (nLockTime.compareTo(Transaction.LOCKTIME_THRESHOLD_BIG)) >= 0))
        )
            throw new ScriptException(ScriptError.SCRIPT_ERR_UNSATISFIED_LOCKTIME, "Locktime requirement type mismatch");

        // Now that we know we're comparing apples-to-apples, the
        // comparison is a simple numeric one.
        if (nLockTime.compareTo(BigInteger.valueOf(txContainingThis.getLockTime())) > 0)
            throw new ScriptException(ScriptError.SCRIPT_ERR_UNSATISFIED_LOCKTIME, "Locktime requirement not satisfied");

        // Finally the nLockTime feature can be disabled and thus
        // CHECKLOCKTIMEVERIFY bypassed if every txin has been
        // finalized by setting nSequence to maxint. The
        // transaction would be allowed into the blockchain, making
        // the opcode ineffective.
        //
        // Testing if this vin is not final is sufficient to
        // prevent this condition. Alternatively we could test all
        // inputs, but testing just this input minimizes the data
        // required to prove correct CHECKLOCKTIMEVERIFY execution.
        if (!txContainingThis.getInput(index).hasSequence())
            throw new ScriptException(ScriptError.SCRIPT_ERR_UNSATISFIED_LOCKTIME, "Transaction contains a final transaction input for a CHECKLOCKTIMEVERIFY script.");
    }

    private static void executeCheckSequenceVerify(Transaction txContainingThis, int index, LinkedList<byte[]> stack, Set<VerifyFlag> verifyFlags) throws ScriptException {
        if (stack.size() < 1)
            throw new ScriptException(ScriptError.SCRIPT_ERR_INVALID_STACK_OPERATION, "Attempted OP_CHECKSEQUENCEVERIFY on a stack with size < 1");

        // Note that elsewhere numeric opcodes are limited to
        // operands in the range -2**31+1 to 2**31-1, however it is
        // legal for opcodes to produce results exceeding that
        // range. This limitation is implemented by CScriptNum's
        // default 4-byte limit.
        //
        // Thus as a special case we tell CScriptNum to accept up
        // to 5-byte bignums, which are good until 2**39-1, well
        // beyond the 2**32-1 limit of the nSequence field itself.
        final long nSequence = castToBigInteger(stack.getLast(), 5, verifyFlags.contains(VerifyFlag.MINIMALDATA)).longValue();

        // In the rare event that the argument may be < 0 due to
        // some arithmetic being done first, you can always use
        // 0 MAX CHECKSEQUENCEVERIFY.
        if (nSequence < 0)
            throw new ScriptException(ScriptError.SCRIPT_ERR_NEGATIVE_LOCKTIME, "Negative sequence");

        // To provide for future soft-fork extensibility, if the
        // operand has the disabled lock-time flag set,
        // CHECKSEQUENCEVERIFY behaves as a NOP.
        if ((nSequence & TransactionInput.SEQUENCE_LOCKTIME_DISABLE_FLAG) != 0)
            return;

        // Compare the specified sequence number with the input.
        checkSequence(nSequence, txContainingThis, index);
    }

    private static void checkSequence(long nSequence, Transaction txContainingThis, int index) {
        // Relative lock times are supported by comparing the passed
        // in operand to the sequence number of the input.
        long txToSequence = txContainingThis.getInput(index).getSequenceNumber();

        // Fail if the transaction's version number is not set high
        // enough to trigger BIP 68 rules.
        if (txContainingThis.getVersion() < 2)
            throw new ScriptException(ScriptError.SCRIPT_ERR_UNSATISFIED_LOCKTIME, "Transaction version is < 2");

        // Sequence numbers with their most significant bit set are not
        // consensus constrained. Testing that the transaction's sequence
        // number do not have this bit set prevents using this property
        // to get around a CHECKSEQUENCEVERIFY check.
        if ((txToSequence & TransactionInput.SEQUENCE_LOCKTIME_DISABLE_FLAG) != 0)
            throw new ScriptException(ScriptError.SCRIPT_ERR_UNSATISFIED_LOCKTIME, "Sequence disable flag is set");

        // Mask off any bits that do not have consensus-enforced meaning
        // before doing the integer comparisons
        long nLockTimeMask =  TransactionInput.SEQUENCE_LOCKTIME_TYPE_FLAG | TransactionInput.SEQUENCE_LOCKTIME_MASK;
        long txToSequenceMasked = txToSequence & nLockTimeMask;
        long nSequenceMasked = nSequence & nLockTimeMask;

        // There are two kinds of nSequence: lock-by-blockheight
        // and lock-by-blocktime, distinguished by whether
        // nSequenceMasked < CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG.
        //
        // We want to compare apples to apples, so fail the script
        // unless the type of nSequenceMasked being tested is the same as
        // the nSequenceMasked in the transaction.
        if (!((txToSequenceMasked < TransactionInput.SEQUENCE_LOCKTIME_TYPE_FLAG && nSequenceMasked < TransactionInput.SEQUENCE_LOCKTIME_TYPE_FLAG) ||
              (txToSequenceMasked >= TransactionInput.SEQUENCE_LOCKTIME_TYPE_FLAG && nSequenceMasked >= TransactionInput.SEQUENCE_LOCKTIME_TYPE_FLAG))) {
            throw new ScriptException(ScriptError.SCRIPT_ERR_UNSATISFIED_LOCKTIME, "Relative locktime requirement type mismatch");
        }

        // Now that we know we're comparing apples-to-apples, the
        // comparison is a simple numeric one.
        if (nSequenceMasked > txToSequenceMasked)
            throw new ScriptException(ScriptError.SCRIPT_ERR_UNSATISFIED_LOCKTIME, "Relative locktime requirement not satisfied");
    }

    private static void executeCheckSig(Transaction txContainingThis, int index, Script script, LinkedList<byte[]> stack,
                                        int lastCodeSepLocation, int opcode, 
                                        Set<VerifyFlag> verifyFlags) throws ScriptException {
        final boolean requireCanonical = verifyFlags.contains(VerifyFlag.STRICTENC)
            || verifyFlags.contains(VerifyFlag.DERSIG)
            || verifyFlags.contains(VerifyFlag.LOW_S);
        if (stack.size() < 2)
            throw new ScriptException(ScriptError.SCRIPT_ERR_INVALID_STACK_OPERATION, "Attempted OP_CHECKSIG(VERIFY) on a stack with size < 2");
        byte[] pubKey = stack.pollLast();
        byte[] sigBytes = stack.pollLast();

        byte[] prog = script.getProgram();
        byte[] connectedScript = Arrays.copyOfRange(prog, lastCodeSepLocation, prog.length);

        UnsafeByteArrayOutputStream outStream = new UnsafeByteArrayOutputStream(sigBytes.length + 1);
        try {
            writeBytes(outStream, sigBytes);
        } catch (IOException e) {
            throw new RuntimeException(e); // Cannot happen
        }
        connectedScript = removeAllInstancesOf(connectedScript, outStream.toByteArray());

        // TODO: Use int for indexes everywhere, we can't have that many inputs/outputs
        boolean sigValid = false;
        try {
            TransactionSignature sig = TransactionSignature.decodeFromBitcoin(sigBytes, requireCanonical,
                verifyFlags.contains(VerifyFlag.LOW_S));

            // TODO: Should check hash type is known
            Sha256Hash hash = txContainingThis.hashForSignature(index, connectedScript, (byte) sig.sighashFlags);
            sigValid = ECKey.verify(hash.getBytes(), sig, pubKey);
        } catch (VerificationException.NoncanonicalSignature e) {
            throw new ScriptException(ScriptError.SCRIPT_ERR_SIG_DER, "Script contains non-canonical signature");
        } catch (SignatureDecodeException e) {
            // This exception occurs when signing as we run partial/invalid scripts to see if they need more
            // signing work to be done inside LocalTransactionSigner.signInputs.
            // FIXME don't rely on exception message
            if (e.getMessage() != null && !e.getMessage().contains("Reached past end of ASN.1 stream"))
                // Don't put critical code here; the above check is not reliable on HotSpot due to optimization:
                // http://jawspeak.com/2010/05/26/hotspot-caused-exceptions-to-lose-their-stack-traces-in-production-and-the-fix/
                log.warn("Signature parsing failed!", e);
        } catch (Exception e) {
            log.warn("Signature checking failed!", e);
        }

        if (opcode == OP_CHECKSIG)
            stack.add(sigValid ? new byte[] {1} : new byte[] {});
        else if (opcode == OP_CHECKSIGVERIFY)
            if (!sigValid)
                throw new ScriptException(ScriptError.SCRIPT_ERR_CHECKSIGVERIFY, "Script failed OP_CHECKSIGVERIFY");
    }

    private static int executeMultiSig(Transaction txContainingThis, int index, Script script, LinkedList<byte[]> stack,
                                       int opCount, int lastCodeSepLocation, int opcode, 
                                       Set<VerifyFlag> verifyFlags) throws ScriptException {
        final boolean requireCanonical = verifyFlags.contains(VerifyFlag.STRICTENC)
            || verifyFlags.contains(VerifyFlag.DERSIG)
            || verifyFlags.contains(VerifyFlag.LOW_S);
        if (stack.size() < 1)
            throw new ScriptException(ScriptError.SCRIPT_ERR_INVALID_STACK_OPERATION, "Attempted OP_CHECKMULTISIG(VERIFY) on a stack with size < 2");
        int pubKeyCount = castToBigInteger(stack.pollLast(), verifyFlags.contains(VerifyFlag.MINIMALDATA)).intValue();
        if (pubKeyCount < 0 || pubKeyCount > MAX_PUBKEYS_PER_MULTISIG)
            throw new ScriptException(ScriptError.SCRIPT_ERR_PUBKEY_COUNT, "OP_CHECKMULTISIG(VERIFY) with pubkey count out of range");
        opCount += pubKeyCount;
        if (opCount > MAX_OPS_PER_SCRIPT)
            throw new ScriptException(ScriptError.SCRIPT_ERR_OP_COUNT, "Total op count > 201 during OP_CHECKMULTISIG(VERIFY)");
        if (stack.size() < pubKeyCount + 1)
            throw new ScriptException(ScriptError.SCRIPT_ERR_INVALID_STACK_OPERATION, "Attempted OP_CHECKMULTISIG(VERIFY) on a stack with size < num_of_pubkeys + 2");

        LinkedList<byte[]> pubkeys = new LinkedList<>();
        for (int i = 0; i < pubKeyCount; i++) {
            byte[] pubKey = stack.pollLast();
            pubkeys.add(pubKey);
        }

        int sigCount = castToBigInteger(stack.pollLast(), verifyFlags.contains(VerifyFlag.MINIMALDATA)).intValue();
        if (sigCount < 0 || sigCount > pubKeyCount)
            throw new ScriptException(ScriptError.SCRIPT_ERR_SIG_COUNT, "OP_CHECKMULTISIG(VERIFY) with sig count out of range");
        if (stack.size() < sigCount + 1)
            throw new ScriptException(ScriptError.SCRIPT_ERR_INVALID_STACK_OPERATION, "Attempted OP_CHECKMULTISIG(VERIFY) on a stack with size < num_of_pubkeys + num_of_signatures + 3");

        LinkedList<byte[]> sigs = new LinkedList<>();
        for (int i = 0; i < sigCount; i++) {
            byte[] sig = stack.pollLast();
            sigs.add(sig);
        }

        byte[] prog = script.getProgram();
        byte[] connectedScript = Arrays.copyOfRange(prog, lastCodeSepLocation, prog.length);

        for (byte[] sig : sigs) {
            UnsafeByteArrayOutputStream outStream = new UnsafeByteArrayOutputStream(sig.length + 1);
            try {
                writeBytes(outStream, sig);
            } catch (IOException e) {
                throw new RuntimeException(e); // Cannot happen
            }
            connectedScript = removeAllInstancesOf(connectedScript, outStream.toByteArray());
        }

        boolean valid = true;
        while (sigs.size() > 0) {
            byte[] pubKey = pubkeys.pollFirst();
            // We could reasonably move this out of the loop, but because signature verification is significantly
            // more expensive than hashing, its not a big deal.
            try {
                TransactionSignature sig = TransactionSignature.decodeFromBitcoin(sigs.getFirst(), requireCanonical, false);
                Sha256Hash hash = txContainingThis.hashForSignature(index, connectedScript, (byte) sig.sighashFlags);
                if (ECKey.verify(hash.getBytes(), sig, pubKey))
                    sigs.pollFirst();
            } catch (Exception e) {
                // There is (at least) one exception that could be hit here (EOFException, if the sig is too short)
                // Because I can't verify there aren't more, we use a very generic Exception catch
            }

            if (sigs.size() > pubkeys.size()) {
                valid = false;
                break;
            }
        }

        // We uselessly remove a stack object to emulate a Bitcoin Core bug.
        byte[] nullDummy = stack.pollLast();
        if (verifyFlags.contains(VerifyFlag.NULLDUMMY) && nullDummy.length > 0)
            throw new ScriptException(ScriptError.SCRIPT_ERR_SIG_NULLFAIL, "OP_CHECKMULTISIG(VERIFY) with non-null nulldummy: " + Arrays.toString(nullDummy));

        if (opcode == OP_CHECKMULTISIG) {
            stack.add(valid ? new byte[] {1} : new byte[] {});
        } else if (opcode == OP_CHECKMULTISIGVERIFY) {
            if (!valid)
                throw new ScriptException(ScriptError.SCRIPT_ERR_SIG_NULLFAIL, "Script failed OP_CHECKMULTISIGVERIFY");
        }
        return opCount;
    }

    /**
     * Verifies that this script (interpreted as a scriptSig) correctly spends the given scriptPubKey.
     * @param txContainingThis The transaction in which this input scriptSig resides.
     *                         Accessing txContainingThis from another thread while this method runs results in undefined behavior.
     * @param scriptSigIndex The index in txContainingThis of the scriptSig (note: NOT the index of the scriptPubKey).
     * @param scriptPubKey The connected scriptPubKey containing the conditions needed to claim the value.
     * @param witness Transaction witness belonging to the transaction input containing this script. Needed for segwit.
     * @param value Value of the output. Needed for segwit scripts.
     * @param verifyFlags Each flag enables one validation rule.
     */
    public void correctlySpends(Transaction txContainingThis, int scriptSigIndex, @Nullable TransactionWitness witness, @Nullable Coin value,
            Script scriptPubKey, Set<VerifyFlag> verifyFlags) throws ScriptException {
        if (ScriptPattern.isP2WPKH(scriptPubKey)) {
            // For segwit, full validation isn't implemented. So we simply check the signature. P2SH_P2WPKH is handled
            // by the P2SH code for now.
            if (witness.getPushCount() < 2)
                throw new ScriptException(ScriptError.SCRIPT_ERR_WITNESS_PROGRAM_WITNESS_EMPTY, witness.toString());
            TransactionSignature signature;
            try {
                signature = TransactionSignature.decodeFromBitcoin(witness.getPush(0), true, true);
            } catch (SignatureDecodeException x) {
                throw new ScriptException(ScriptError.SCRIPT_ERR_SIG_DER, "Cannot decode", x);
            }
            ECKey pubkey = ECKey.fromPublicOnly(witness.getPush(1));
            Script scriptCode = ScriptBuilder.createP2PKHOutputScript(pubkey);
            Sha256Hash sigHash = txContainingThis.hashForWitnessSignature(scriptSigIndex, scriptCode, value,
                    signature.sigHashMode(), false);
            boolean validSig = pubkey.verify(sigHash, signature);
            if (!validSig)
                throw new ScriptException(ScriptError.SCRIPT_ERR_CHECKSIGVERIFY, "Invalid signature");
        } else if (ScriptPattern.isP2PKH(scriptPubKey)) {
            if (chunks.size() != 2)
                throw new ScriptException(ScriptError.SCRIPT_ERR_SCRIPT_SIZE, "Invalid size: " + chunks.size());
            TransactionSignature signature;
            try {
                signature = TransactionSignature.decodeFromBitcoin(chunks.get(0).data, true, true);
            } catch (SignatureDecodeException x) {
                throw new ScriptException(ScriptError.SCRIPT_ERR_SIG_DER, "Cannot decode", x);
            }
            ECKey pubkey = ECKey.fromPublicOnly(chunks.get(1).data);
            Sha256Hash sigHash = txContainingThis.hashForSignature(scriptSigIndex, scriptPubKey,
                    signature.sigHashMode(), false);
            boolean validSig = pubkey.verify(sigHash, signature);
            if (!validSig)
                throw new ScriptException(ScriptError.SCRIPT_ERR_CHECKSIGVERIFY, "Invalid signature");
        } else if (ScriptPattern.isP2PK(scriptPubKey)) {
            if (chunks.size() != 1)
                throw new ScriptException(ScriptError.SCRIPT_ERR_SCRIPT_SIZE, "Invalid size: " + chunks.size());
            TransactionSignature signature;
            try {
                signature = TransactionSignature.decodeFromBitcoin(chunks.get(0).data, false, false);
            } catch (SignatureDecodeException x) {
                throw new ScriptException(ScriptError.SCRIPT_ERR_SIG_DER, "Cannot decode", x);
            }
            ECKey pubkey = ECKey.fromPublicOnly(ScriptPattern.extractKeyFromP2PK(scriptPubKey));
            Sha256Hash sigHash = txContainingThis.hashForSignature(scriptSigIndex, scriptPubKey,
                    signature.sigHashMode(), false);
            boolean validSig = pubkey.verify(sigHash, signature);
            if (!validSig)
                throw new ScriptException(ScriptError.SCRIPT_ERR_CHECKSIGVERIFY, "Invalid signature");
        } else {
            correctlySpends(txContainingThis, scriptSigIndex, scriptPubKey, verifyFlags);
        }
    }

    /**
     * Verifies that this script (interpreted as a scriptSig) correctly spends the given scriptPubKey.
     * @param txContainingThis The transaction in which this input scriptSig resides.
     *                         Accessing txContainingThis from another thread while this method runs results in undefined behavior.
     * @param scriptSigIndex The index in txContainingThis of the scriptSig (note: NOT the index of the scriptPubKey).
     * @param scriptPubKey The connected scriptPubKey containing the conditions needed to claim the value.
     * @param verifyFlags Each flag enables one validation rule.
     * @deprecated Use {@link #correctlySpends(Transaction, int, TransactionWitness, Coin, Script, Set)} instead.
     */
    @Deprecated
    public void correctlySpends(Transaction txContainingThis, long scriptSigIndex, Script scriptPubKey,
                                Set<VerifyFlag> verifyFlags) throws ScriptException {
        // Clone the transaction because executing the script involves editing it, and if we die, we'll leave
        // the tx half broken (also it's not so thread safe to work on it directly.
        try {
            txContainingThis = txContainingThis.getParams().getDefaultSerializer().makeTransaction(txContainingThis.bitcoinSerialize());
        } catch (ProtocolException e) {
            throw new RuntimeException(e);   // Should not happen unless we were given a totally broken transaction.
        }
        if (getProgram().length > MAX_SCRIPT_SIZE || scriptPubKey.getProgram().length > MAX_SCRIPT_SIZE)
            throw new ScriptException(ScriptError.SCRIPT_ERR_SCRIPT_SIZE, "Script larger than 10,000 bytes");
        
        LinkedList<byte[]> stack = new LinkedList<>();
        LinkedList<byte[]> p2shStack = null;
        
        executeScript(txContainingThis, scriptSigIndex, this, stack, verifyFlags);
        if (verifyFlags.contains(VerifyFlag.P2SH))
            p2shStack = new LinkedList<>(stack);
        executeScript(txContainingThis, scriptSigIndex, scriptPubKey, stack, verifyFlags);
        
        if (stack.size() == 0)
            throw new ScriptException(ScriptError.SCRIPT_ERR_EVAL_FALSE, "Stack empty at end of script execution.");

        List<byte[]> stackCopy = new LinkedList<>(stack);
        if (!castToBool(stack.pollLast()))
            throw new ScriptException(ScriptError.SCRIPT_ERR_EVAL_FALSE,
                    "Script resulted in a non-true stack: " + Utils.toString(stackCopy));

        // P2SH is pay to script hash. It means that the scriptPubKey has a special form which is a valid
        // program but it has "useless" form that if evaluated as a normal program always returns true.
        // Instead, miners recognize it as special based on its template - it provides a hash of the real scriptPubKey
        // and that must be provided by the input. The goal of this bizarre arrangement is twofold:
        //
        // (1) You can sum up a large, complex script (like a CHECKMULTISIG script) with an address that's the same
        //     size as a regular address. This means it doesn't overload scannable QR codes/NFC tags or become
        //     un-wieldy to copy/paste.
        // (2) It allows the working set to be smaller: nodes perform best when they can store as many unspent outputs
        //     in RAM as possible, so if the outputs are made smaller and the inputs get bigger, then it's better for
        //     overall scalability and performance.

        // TODO: Check if we can take out enforceP2SH if there's a checkpoint at the enforcement block.
        if (verifyFlags.contains(VerifyFlag.P2SH) && ScriptPattern.isP2SH(scriptPubKey)) {
            for (ScriptChunk chunk : chunks)
                if (!chunk.isPushData())
                    throw new ScriptException(ScriptError.SCRIPT_ERR_SIG_PUSHONLY, "Attempted to spend a P2SH scriptPubKey with a script that contained the script op " + chunk);
            
            byte[] scriptPubKeyBytes = p2shStack.pollLast();
            Script scriptPubKeyP2SH = new Script(scriptPubKeyBytes);
            
            executeScript(txContainingThis, scriptSigIndex, scriptPubKeyP2SH, p2shStack, verifyFlags);
            
            if (p2shStack.size() == 0)
                throw new ScriptException(ScriptError.SCRIPT_ERR_EVAL_FALSE, "P2SH stack empty at end of script execution.");
            
            List<byte[]> p2shStackCopy = new LinkedList<>(p2shStack);
            if (!castToBool(p2shStack.pollLast()))
                throw new ScriptException(ScriptError.SCRIPT_ERR_EVAL_FALSE,
                        "P2SH script execution resulted in a non-true stack: " + Utils.toString(p2shStackCopy));
        }
    }

    // Utility that doesn't copy for internal use
    private byte[] getQuickProgram() {
        if (program != null)
            return program;
        return getProgram();
    }

    /**
     * Get the {@link ScriptType}.
     * @return The script type, or null if the script is of unknown type
     */
    public @Nullable ScriptType getScriptType() {
        if (ScriptPattern.isP2PKH(this))
            return ScriptType.P2PKH;
        if (ScriptPattern.isP2PK(this))
            return ScriptType.P2PK;
        if (ScriptPattern.isP2SH(this))
            return ScriptType.P2SH;
        if (ScriptPattern.isP2WPKH(this))
            return ScriptType.P2WPKH;
        if (ScriptPattern.isP2WSH(this))
            return ScriptType.P2WSH;
        if (ScriptPattern.isP2TR(this))
            return ScriptType.P2TR;
        return null;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        return Arrays.equals(getQuickProgram(), ((Script)o).getQuickProgram());
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(getQuickProgram());
    }
}
