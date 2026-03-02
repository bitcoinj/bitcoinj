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

import org.bitcoinj.base.Address;
import org.bitcoinj.base.LegacyAddress;
import org.bitcoinj.base.Network;
import org.bitcoinj.base.ScriptType;
import org.bitcoinj.base.SegwitAddress;
import org.bitcoinj.base.Sha256Hash;
import org.bitcoinj.base.VarInt;
import org.bitcoinj.base.internal.ByteUtils;
import org.bitcoinj.base.internal.InternalUtils;
import org.bitcoinj.base.internal.TimeUtils;
import org.bitcoinj.core.TransactionInput;
import org.bitcoinj.core.TransactionOutput;
import org.bitcoinj.crypto.ECKey;
import org.bitcoinj.crypto.SignatureDecodeException;
import org.bitcoinj.crypto.TransactionSignature;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.jspecify.annotations.Nullable;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

import static org.bitcoinj.base.internal.Preconditions.checkArgument;
import static org.bitcoinj.base.internal.Preconditions.checkState;
import static org.bitcoinj.script.ScriptOpCodes.OP_0;
import static org.bitcoinj.script.ScriptOpCodes.OP_1;
import static org.bitcoinj.script.ScriptOpCodes.OP_16;
import static org.bitcoinj.script.ScriptOpCodes.OP_1NEGATE;
import static org.bitcoinj.script.ScriptOpCodes.OP_CHECKMULTISIG;
import static org.bitcoinj.script.ScriptOpCodes.OP_CHECKMULTISIGVERIFY;
import static org.bitcoinj.script.ScriptOpCodes.OP_CHECKSIG;
import static org.bitcoinj.script.ScriptOpCodes.OP_CHECKSIGVERIFY;
import static org.bitcoinj.script.ScriptOpCodes.OP_INVALIDOPCODE;
import static org.bitcoinj.script.ScriptOpCodes.OP_PUSHDATA1;
import static org.bitcoinj.script.ScriptOpCodes.OP_PUSHDATA2;
import static org.bitcoinj.script.ScriptOpCodes.OP_PUSHDATA4;

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
    public static final int SIG_SIZE = 75;

    private static final Logger log = LoggerFactory.getLogger(Script.class);

    // The program is a set of chunks where each element is either [opcode] or [data, data, data ...]
    private final List<ScriptChunk> chunks;
    // Unfortunately, scripts are not ever re-serialized or canonicalized when used in signature hashing. Thus we
    // must preserve the exact bytes that we read off the wire, along with the parsed form.
    private final byte @Nullable [] program;

    /**
     * If this is set, the script is associated with a creation time. This is currently used in the context of
     * watching wallets only, where the scriptPubKeys being watched actually represent public keys and their addresses.
     */
    @Nullable
    private final Instant creationTime;

    /**
     * Wraps given script chunks.
     *
     * @param chunks chunks to wrap
     * @return script that wraps the chunks
     */
    public static Script of(List<ScriptChunk> chunks) {
        return of(chunks, null);
    }

    /**
     * Wraps given script chunks.
     *
     * @param chunks       chunks to wrap
     * @param creationTime creation time to associate the script with
     * @return script that wraps the chunks
     */
    public static Script of(List<ScriptChunk> chunks, Instant creationTime) {
        return new Script(chunks, creationTime);
    }

    /**
     * Construct a script that copies and wraps a given program. The array is parsed and checked for syntactic
     * validity. Programs like this are e.g. used in {@link TransactionInput} and {@link TransactionOutput}.
     *
     * @param program array of program bytes
     * @return parsed program
     * @throws ScriptException if the program could not be parsed
     */
    public static Script parse(byte[] program) throws ScriptException {
        return parse(program, null);
    }

    /**
     * Construct a script that copies and wraps a given program. The array is parsed and checked for syntactic
     * validity. Programs like this are e.g. used in {@link TransactionInput} and {@link TransactionOutput}.
     *
     * @param program      Array of program bytes from a transaction.
     * @param creationTime creation time to associate the script with
     * @return parsed program
     * @throws ScriptException if the program could not be parsed
     */
    public static Script parse(byte[] program, Instant creationTime) throws ScriptException {
        return new Script(program, creationTime);
    }

    /**
     * To run a script, first we parse it which breaks it up into chunks representing pushes of data or logical
     * opcodes. Then we can run the parsed chunks.
     * @param program program bytes to parse
     * @return An unmodifiable list of chunks
     */
    private static List<ScriptChunk> parseIntoChunks(byte[] program) throws ScriptException {
        List<ScriptChunk> chunks = new ArrayList<>();
        parseIntoChunksPartial(program, chunks);
        return Collections.unmodifiableList(chunks);
    }

    /**
     * Parse a script program into a mutable List of chunks. If an exception is thrown a partial parsing
     * will be present in the provided chunk list.
     * @param program The script program
     * @param chunks An empty, mutable array to fill with chunks
     */
    private static void parseIntoChunksPartial(byte[] program, List<ScriptChunk> chunks) throws ScriptException {
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
                dataToRead = ByteUtils.readUint16(bis);
            } else if (opcode == OP_PUSHDATA4) {
                // Read a uint32, then read that many bytes of data.
                // Though this is allowed, because its value cannot be > 520, it should never actually be used
                if (bis.available() < 4) throw new ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "Unexpected end of script");
                dataToRead = ByteUtils.readUint32(bis);
            }

            ScriptChunk chunk;
            if (dataToRead == -1) {
                chunk = new ScriptChunk(opcode, null);
            } else {
                if (dataToRead > bis.available())
                    throw new ScriptException(ScriptError.SCRIPT_ERR_BAD_OPCODE, "Push of data element that is larger than remaining data: " + dataToRead + " vs " + bis.available());
                byte[] data = new byte[(int)dataToRead];
                checkState(dataToRead == 0 || bis.read(data, 0, (int) dataToRead) == dataToRead);
                chunk = new ScriptChunk(opcode, data);
            }
            // Save some memory by eliminating redundant copies of the same chunk objects.
            for (ScriptChunk c : STANDARD_TRANSACTION_SCRIPT_CHUNKS) {
                if (c.equals(chunk)) chunk = c;
            }
            chunks.add(chunk);
        }
    }


    // When constructing from a program, we store both program and chunks
    private Script(byte[] program, @Nullable Instant creationTime) {
        Objects.requireNonNull(program);
        this.program = Arrays.copyOf(program, program.length); // defensive copy;
        this.chunks = parseIntoChunks(this.program);
        this.creationTime = creationTime;
    }

    // When constructing from chunks, we store only chunks, and generate program when getter is called
    private Script(List<ScriptChunk> chunks, @Nullable Instant creationTime) {
        Objects.requireNonNull(chunks);
        this.program = null;
        this.chunks = Collections.unmodifiableList(new ArrayList<>(chunks));    // defensive copy
        this.creationTime = creationTime;
    }

    /**
     * Gets the serialized program as a newly created byte array.
     *
     * @return serialized program
     */
    public byte[] program() {
        if (program != null)
            // Don't round-trip as Bitcoin Core doesn't and it would introduce a mismatch.
            return Arrays.copyOf(program, program.length);
        else {
            int size = chunks.stream().mapToInt(ScriptChunk::size).sum();
            ByteBuffer buf = ByteBuffer.allocate(size);
            chunks.forEach(chunk ->
                buf.put(chunk.toByteArray())
            );
            return buf.array();
        }
    }

    /**
     * Gets an immutable list of the scripts parsed form. Each chunk is either an opcode or data element.
     *
     * @return script chunks
     */
    public List<ScriptChunk> chunks() {
        return Collections.unmodifiableList(chunks);
    }

    /**
     * Gets the associated creation time of this script, or empty if undefined. This is currently used in the context of
     * watching wallets only, where the scriptPubKeys being watched actually represent public keys and their
     * addresses.
     *
     * @return associated creation time of this script, or empty if undefined
     */
    public Optional<Instant> creationTime() {
        return Optional.ofNullable(creationTime);
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

    private static final ScriptChunk[] STANDARD_TRANSACTION_SCRIPT_CHUNKS = {
        new ScriptChunk(ScriptOpCodes.OP_DUP, null),
        new ScriptChunk(ScriptOpCodes.OP_HASH160, null),
        new ScriptChunk(ScriptOpCodes.OP_EQUALVERIFY, null),
        new ScriptChunk(ScriptOpCodes.OP_CHECKSIG, null),
    };


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
    public Address getToAddress(Network network) throws ScriptException {
        return getToAddress(network, false);
    }

    /**
     * Gets the destination address from this script, if it's in the required form.
     *
     * @param forcePayToPubKey
     *            If true, allow payToPubKey to be casted to the corresponding address. This is useful if you prefer
     *            showing addresses rather than pubkeys.
     */
    public Address getToAddress(Network network, boolean forcePayToPubKey) throws ScriptException {
        if (ScriptPattern.isP2PKH(this))
            return LegacyAddress.fromPubKeyHash(network, ScriptPattern.extractHashFromP2PKH(this));
        else if (ScriptPattern.isP2SH(this))
            return LegacyAddress.fromScriptHash(network, ScriptPattern.extractHashFromP2SH(this));
        else if (forcePayToPubKey && ScriptPattern.isP2PK(this))
            return ECKey.fromPublicOnly(ScriptPattern.extractKeyFromP2PK(this)).toAddress(ScriptType.P2PKH, network);
        else if (ScriptPattern.isP2WH(this))
            return SegwitAddress.fromHash(network, ScriptPattern.extractHashFromP2WH(this));
        else if (ScriptPattern.isP2TR(this))
            return SegwitAddress.fromProgram(network, 1, ScriptPattern.extractOutputKeyFromP2TR(this));
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
            ByteUtils.writeInt16LE(buf.length, os);
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
        return new ScriptBuilder()
                .data(signature)
                .data(pubkey)
                .build()
                .program();
    }

    public static byte[] createInputScript(byte[] signature) {
        return new ScriptBuilder()
                .data(signature)
                .build()
                .program();
    }

    /**
     * Creates an incomplete scriptSig that, once filled with signatures, can redeem output containing this scriptPubKey.
     * Instead of the signatures resulting script has OP_0.
     * Having incomplete input script allows to pass around partially signed tx.
     * It is expected that this program later on will be updated with proper signatures.
     */
    public Script createEmptyInputScript(@Nullable ECKey key, @Nullable Script redeemScript) {
        if (ScriptPattern.isP2PKH(this)) {
            checkArgument(key != null, () ->
                    "key required to create P2PKH input script");
            return ScriptBuilder.createInputScript(null, key);
        } else if (ScriptPattern.isP2WPKH(this)) {
            return ScriptBuilder.createEmpty();
        } else if (ScriptPattern.isP2PK(this)) {
            return ScriptBuilder.createInputScript(null);
        } else if (ScriptPattern.isP2SH(this)) {
            checkArgument(redeemScript != null, () ->
                    "redeem script required to create P2SH input script");
            return ScriptBuilder.createP2SHMultiSigInputScript(null, redeemScript);
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
        Objects.requireNonNull(redeemScriptChunk.data);
        Script redeemScript = Script.parse(redeemScriptChunk.data);

        int sigCount = 0;
        int myIndex = redeemScript.findKeyInRedeem(signingKey);
        for (ScriptChunk chunk : existingChunks) {
            if (chunk.opcode == OP_0) {
                // OP_0, skip
            } else {
                Objects.requireNonNull(chunk.data);
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

        throw new IllegalStateException("Could not find matching key for signature on " + hash.toString() + " sig " + ByteUtils.formatHex(signatureBytes));
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
        checkArgument((opcode == OP_0 || opcode == OP_1NEGATE) || (opcode >= OP_1 && opcode <= OP_16), () ->
                "decodeFromOpN called on non OP_N opcode: " + ScriptOpCodes.getOpCodeName(opcode));
        if (opcode == OP_0)
            return 0;
        else if (opcode == OP_1NEGATE)
            return -1;
        else
            return opcode + 1 - OP_1;
    }

    public static int encodeToOpN(int value) {
        checkArgument(value >= -1 && value <= 16, () ->
                "encodeToOpN called for " + value + " which we cannot encode in an opcode");
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
        List<ScriptChunk> chunks = new ArrayList<>(5); // common size
        try {
            parseIntoChunksPartial(program, chunks);
        } catch (ScriptException e) {
            // Ignore errors and count up to the parse-able length
        }
        return getSigOpCount(chunks, false);
    }

    /**
     * Gets the count of P2SH Sig Ops in the Script scriptSig
     */
    public static long getP2SHSigOpCount(byte[] scriptSig) throws ScriptException {
        List<ScriptChunk> chunks = new ArrayList<>(5); // common size
        try {
            parseIntoChunksPartial(scriptSig, chunks);
        } catch (ScriptException e) {
            // Ignore errors and count up to the parse-able length
        }
        Collections.reverse(chunks);
        for (ScriptChunk chunk : chunks) {
            if (!chunk.isOpCode()) {
                Script subScript = parse(chunk.data);
                return getSigOpCount(subScript.chunks, true);
            }
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
            checkArgument(redeemScript != null, () ->
                    "P2SH script requires redeemScript to be spent");
            return redeemScript.getNumberOfSignaturesRequiredToSpend() * SIG_SIZE + redeemScript.program().length;
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
        ByteArrayOutputStream bos = new ByteArrayOutputStream(inputScript.length);

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
    
    // Utility that doesn't copy for internal use
    private byte[] getQuickProgram() {
        if (program != null)
            return program;
        return program();
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
