/*
 * Copyright 2017 John L. Jegutanis
 * Copyright 2018 Andreas Schildbach
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

import org.bitcoinj.core.LegacyAddress;
import org.bitcoinj.core.SegwitAddress;
import org.bitcoinj.core.Sha256Hash;
import org.bitcoinj.core.Utils;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;

import static org.bitcoinj.script.Script.decodeFromOpN;
import static org.bitcoinj.script.ScriptOpCodes.*;

/**
 * This is a Script pattern matcher with some typical script patterns
 */
public class ScriptPattern {
    /**
     * Returns true if this script is of the form {@code DUP HASH160 <pubkey hash> EQUALVERIFY CHECKSIG}, ie, payment to an
     * address like {@code 1VayNert3x1KzbpzMGt2qdqrAThiRovi8}. This form was originally intended for the case where you wish
     * to send somebody money with a written code because their node is offline, but over time has become the standard
     * way to make payments due to the short and recognizable base58 form addresses come in.
     */
    public static boolean isP2PKH(Script script) {
        List<ScriptChunk> chunks = script.chunks;
        if (chunks.size() != 5)
            return false;
        if (!chunks.get(0).equalsOpCode(OP_DUP))
            return false;
        if (!chunks.get(1).equalsOpCode(OP_HASH160))
            return false;
        byte[] chunk2data = chunks.get(2).data;
        if (chunk2data == null)
            return false;
        if (chunk2data.length != LegacyAddress.LENGTH)
            return false;
        if (!chunks.get(3).equalsOpCode(OP_EQUALVERIFY))
            return false;
        if (!chunks.get(4).equalsOpCode(OP_CHECKSIG))
            return false;
        return true;
    }

    /**
     * Extract the pubkey hash from a P2PKH scriptPubKey. It's important that the script is in the correct form, so you
     * will want to guard calls to this method with {@link #isP2PKH(Script)}.
     */
    public static byte[] extractHashFromP2PKH(Script script) {
        return script.chunks.get(2).data;
    }

    /**
     * <p>
     * Whether or not this is a scriptPubKey representing a P2SH output. In such outputs, the logic that
     * controls reclamation is not actually in the output at all. Instead there's just a hash, and it's up to the
     * spending input to provide a program matching that hash.
     * </p>
     * <p>
     * P2SH is described by <a href="https://github.com/bitcoin/bips/blob/master/bip-0016.mediawiki">BIP16</a>.
     * </p>
     */
    public static boolean isP2SH(Script script) {
        List<ScriptChunk> chunks = script.chunks;
        // We check for the effective serialized form because BIP16 defines a P2SH output using an exact byte
        // template, not the logical program structure. Thus you can have two programs that look identical when
        // printed out but one is a P2SH script and the other isn't! :(
        // We explicitly test that the op code used to load the 20 bytes is 0x14 and not something logically
        // equivalent like {@code OP_HASH160 OP_PUSHDATA1 0x14 <20 bytes of script hash> OP_EQUAL}
        if (chunks.size() != 3)
            return false;
        if (!chunks.get(0).equalsOpCode(OP_HASH160))
            return false;
        ScriptChunk chunk1 = chunks.get(1);
        if (chunk1.opcode != 0x14)
            return false;
        byte[] chunk1data = chunk1.data;
        if (chunk1data == null)
            return false;
        if (chunk1data.length != LegacyAddress.LENGTH)
            return false;
        if (!chunks.get(2).equalsOpCode(OP_EQUAL))
            return false;
        return true;
    }

    /**
     * Extract the script hash from a P2SH scriptPubKey. It's important that the script is in the correct form, so you
     * will want to guard calls to this method with {@link #isP2SH(Script)}.
     */
    public static byte[] extractHashFromP2SH(Script script) {
        return script.chunks.get(1).data;
    }

    /**
     * Returns true if this script is of the form {@code <pubkey> OP_CHECKSIG}. This form was originally intended for transactions
     * where the peers talked to each other directly via TCP/IP, but has fallen out of favor with time due to that mode
     * of operation being susceptible to man-in-the-middle attacks. It is still used in coinbase outputs and can be
     * useful more exotic types of transaction, but today most payments are to addresses.
     */
    public static boolean isP2PK(Script script) {
        List<ScriptChunk> chunks = script.chunks;
        if (chunks.size() != 2)
            return false;
        ScriptChunk chunk0 = chunks.get(0);
        if (chunk0.isOpCode())
            return false;
        byte[] chunk0data = chunk0.data;
        if (chunk0data == null)
            return false;
        if (chunk0data.length <= 1)
            return false;
        if (!chunks.get(1).equalsOpCode(OP_CHECKSIG))
            return false;
        return true;
    }

    /**
     * Extract the pubkey from a P2SH scriptPubKey. It's important that the script is in the correct form, so you will
     * want to guard calls to this method with {@link #isP2PK(Script)}.
     */
    public static byte[] extractKeyFromP2PK(Script script) {
        return script.chunks.get(0).data;
    }

    /**
     * Returns true if this script is of the form {@code OP_0 <hash>}. This can either be a P2WPKH or P2WSH scriptPubKey. These
     * two script types were introduced with segwit.
     */
    public static boolean isP2WH(Script script) {
        List<ScriptChunk> chunks = script.chunks;
        if (chunks.size() != 2)
            return false;
        if (!chunks.get(0).equalsOpCode(OP_0))
            return false;
        byte[] chunk1data = chunks.get(1).data;
        if (chunk1data == null)
            return false;
        if (chunk1data.length != SegwitAddress.WITNESS_PROGRAM_LENGTH_PKH
                && chunk1data.length != SegwitAddress.WITNESS_PROGRAM_LENGTH_SH)
            return false;
        return true;
    }

    /**
     * Returns true if this script is of the form {@code OP_0 <hash>} and hash is 20 bytes long. This can only be a P2WPKH
     * scriptPubKey. This script type was introduced with segwit.
     */
    public static boolean isP2WPKH(Script script) {
        if (!isP2WH(script))
            return false;
        List<ScriptChunk> chunks = script.chunks;
        if (!chunks.get(0).equalsOpCode(OP_0))
            return false;
        byte[] chunk1data = chunks.get(1).data;
        return chunk1data != null && chunk1data.length == SegwitAddress.WITNESS_PROGRAM_LENGTH_PKH;
    }

    /**
     * Returns true if this script is of the form {@code OP_0 <hash>} and hash is 32 bytes long. This can only be a P2WSH
     * scriptPubKey. This script type was introduced with segwit.
     */
    public static boolean isP2WSH(Script script) {
        if (!isP2WH(script))
            return false;
        List<ScriptChunk> chunks = script.chunks;
        if (!chunks.get(0).equalsOpCode(OP_0))
            return false;
        byte[] chunk1data = chunks.get(1).data;
        return chunk1data != null && chunk1data.length == SegwitAddress.WITNESS_PROGRAM_LENGTH_SH;
    }

    /**
     * Extract the pubkey hash from a P2WPKH or the script hash from a P2WSH scriptPubKey. It's important that the
     * script is in the correct form, so you will want to guard calls to this method with
     * {@link #isP2WH(Script)}.
     */
    public static byte[] extractHashFromP2WH(Script script) {
        return script.chunks.get(1).data;
    }

    /**
     * Returns whether this script matches the format used for m-of-n multisig outputs:
     * {@code [m] [keys...] [n] CHECKMULTISIG}
     */
    public static boolean isSentToMultisig(Script script) {
        List<ScriptChunk> chunks = script.chunks;
        if (chunks.size() < 4) return false;
        ScriptChunk chunk = chunks.get(chunks.size() - 1);
        // Must end in OP_CHECKMULTISIG[VERIFY].
        if (!chunk.isOpCode()) return false;
        if (!(chunk.equalsOpCode(OP_CHECKMULTISIG) || chunk.equalsOpCode(OP_CHECKMULTISIGVERIFY))) return false;
        try {
            // Second to last chunk must be an OP_N opcode and there should be that many data chunks (keys).
            ScriptChunk m = chunks.get(chunks.size() - 2);
            if (!m.isOpCode()) return false;
            int numKeys = decodeFromOpN(m.opcode);
            if (numKeys < 1 || chunks.size() != 3 + numKeys) return false;
            for (int i = 1; i < chunks.size() - 2; i++) {
                if (chunks.get(i).isOpCode()) return false;
            }
            // First chunk must be an OP_N opcode too.
            if (decodeFromOpN(chunks.get(0).opcode) < 1) return false;
        } catch (IllegalStateException e) {
            return false;   // Not an OP_N opcode.
        }
        return true;
    }

    /**
     * Returns whether this script matches the format used for LOCKTIMEVERIFY transactions.
     */
    public static boolean isSentToCltvPaymentChannel(Script script) {
        List<ScriptChunk> chunks = script.chunks;
        if (chunks.size() != 10) return false;
        // Check that opcodes match the pre-determined format.
        if (!chunks.get(0).equalsOpCode(OP_IF)) return false;
        // chunk[1] = recipient pubkey
        if (!chunks.get(2).equalsOpCode(OP_CHECKSIGVERIFY)) return false;
        if (!chunks.get(3).equalsOpCode(OP_ELSE)) return false;
        // chunk[4] = locktime
        if (!chunks.get(5).equalsOpCode(OP_CHECKLOCKTIMEVERIFY)) return false;
        if (!chunks.get(6).equalsOpCode(OP_DROP)) return false;
        if (!chunks.get(7).equalsOpCode(OP_ENDIF)) return false;
        // chunk[8] = sender pubkey
        if (!chunks.get(9).equalsOpCode(OP_CHECKSIG)) return false;
        return true;
    }

    /**
     * Retrieves the public key of the sender from a LOCKTIMEVERIFY transaction. It's important that the script is in
     * the correct form, so you will want to guard calls to this method with
     * {@link #isSentToCltvPaymentChannel(Script)}.
     */
    public static byte[] extractSenderPubKeyFromCltvPaymentChannel(Script script) {
        return script.chunks.get(8).data;
    }

    /**
     * Retrieves the public key of the recipient from a LOCKTIMEVERIFY transaction. It's important that the script is in
     * the correct form, so you will want to guard calls to this method with
     * {@link #isSentToCltvPaymentChannel(Script)}.
     */
    public static byte[] extractRecipientPubKeyFromCltvPaymentChannel(Script script) {
        return script.chunks.get(1).data;
    }

    /**
     * Retrieves the locktime from a LOCKTIMEVERIFY transaction. It's important that the script is in the correct form,
     * so you will want to guard calls to this method with {@link #isSentToCltvPaymentChannel(Script)}.
     */
    public static BigInteger extractExpiryFromCltvPaymentChannel(Script script) {
        return Script.castToBigInteger(script.chunks.get(4).data, 5, false);
    }

    /**
     * Returns whether this script is using OP_RETURN to store arbitrary data.
     */
    public static boolean isOpReturn(Script script) {
        List<ScriptChunk> chunks = script.chunks;
        return chunks.size() > 0 && chunks.get(0).equalsOpCode(ScriptOpCodes.OP_RETURN);
    }

    private static final byte[] SEGWIT_COMMITMENT_HEADER = Utils.HEX.decode("aa21a9ed");

    /**
     * Returns whether this script matches the pattern for a segwit commitment (in an output of the coinbase
     * transaction).
     */
    public static boolean isWitnessCommitment(Script script) {
        List<ScriptChunk> chunks = script.chunks;
        if (chunks.size() < 2)
            return false;
        if (!chunks.get(0).equalsOpCode(ScriptOpCodes.OP_RETURN))
            return false;
        byte[] chunkData = chunks.get(1).data;
        if (chunkData == null || chunkData.length != 36)
            return false;
        if (!Arrays.equals(Arrays.copyOfRange(chunkData, 0, 4), SEGWIT_COMMITMENT_HEADER))
            return false;
        return true;
    }

    /**
     * Retrieves the hash from a segwit commitment (in an output of the coinbase transaction).
     */
    public static Sha256Hash extractWitnessCommitmentHash(Script script) {
        return Sha256Hash.wrap(Arrays.copyOfRange(script.chunks.get(1).data, 4, 36));
    }
}
