/*
 * Copyright 2019 Giannis L. Jegutanis
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

/*
 * Ported from the Bitcoin Core project:
 *   Copyright (c) 2009-2019 The Bitcoin Core developers
 *   Distributed under the MIT software license, see the accompanying
 *   file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */

package org.bitcoinj.core;

import com.google.common.annotations.Beta;
import org.bitcoinj.base.internal.Buffers;
import org.bitcoinj.crypto.ECKey;
import org.bitcoinj.script.Script;

import java.nio.BufferOverflowException;
import java.nio.ByteBuffer;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.bitcoinj.base.internal.Buffers.readLengthPrefixedBytes;
import static org.bitcoinj.core.PartiallySignedTransaction.*;

/**
 * A class for PSBTs which contain per output information.
 * <i>Note: this is an experimental "beta" API and could change in future releases</i>
 * */
@Beta
public class PsbtOutput {
    public Script redeemScript;
    public Script witnessScript;
    public Map<ECKey, KeyOriginInfo> hdKeyPaths;
    public Map<RawBytes, RawBytes> unknown;

    public PsbtOutput(){
        redeemScript = Script.EMPTY;
        witnessScript = Script.EMPTY;
        unknown = new LinkedHashMap<>();
        hdKeyPaths = new LinkedHashMap<>();
    }

    /*
     * Deserialize a PSBT Output from a buffer
     *
     * @param payload the buffer
     * @return the PSBT Output
     * @throws ProtocolException for malformed PSBTs
     */
    public static PsbtOutput read(ByteBuffer payload) throws ProtocolException {
        PsbtOutput output = new PsbtOutput();

        // Used for duplicate key detection
        HashSet<RawBytes> keyLookup = new HashSet<>();

        // Read loop
        boolean foundSeparator = false;
        while (payload.hasRemaining()) {
            byte[] key = readLengthPrefixedBytes(payload);

            // the key is empty if that was actually a separator byte
            // This is a special case for key lengths 0 as those are not allowed (except for separator)
            if (key.length == 0) {
                foundSeparator = true;
                break;
            }

            // First byte of key is the type
            byte type = key[0];

            // Do stuff based on type
            switch (type) {
                case PSBT_OUT_REDEEMSCRIPT:
                    if (!keyLookup.add(RawBytes.wrap(key))) {
                        throw new ProtocolException("Duplicate Key, output redeemScript already provided");
                    } else if (key.length != 1) {
                        throw new ProtocolException("Output redeemScript key is more than one byte type");
                    }
                    output.redeemScript = Script.parse(readLengthPrefixedBytes(payload));
                    break;
                case PSBT_OUT_WITNESSSCRIPT:
                    if (!keyLookup.add(RawBytes.wrap(key))) {
                        throw new ProtocolException("Duplicate Key, output witnessScript already provided");
                    } else if (key.length != 1) {
                        throw new ProtocolException("Output witnessScript key is more than one byte type");
                    }
                    output.witnessScript = Script.parse(readLengthPrefixedBytes(payload));
                    break;
                case PSBT_OUT_BIP32_DERIVATION:
                    // Also does the key length and duplication checks
                    parseHDKeyPaths(payload, key, output.hdKeyPaths);
                    break;
                // Unknown stuff
                default:
                    if (!keyLookup.add(RawBytes.wrap(key))) {
                        throw new ProtocolException("Duplicate Key, key for unknown value already provided");
                    }
                    output.unknown.put(RawBytes.wrap(key), RawBytes.wrap(readLengthPrefixedBytes(payload)));
            }
        }

        if (!foundSeparator) {
            throw new ProtocolException("Separator is missing at the end of an output map");
        }

        return output;
    }

    /**
     * @return the size of the serialized message.
     */
    public int messageSize() {
        int size = 0;
        // The redeem script size
        if (!redeemScript.isEmpty()) {
            size += 1; // PSBT_OUT_REDEEMSCRIPT
            size += redeemScript.size();
        }

        // The witness script size
        if (!witnessScript.isEmpty()) {
            size += 1; // PSBT_OUT_WITNESSSCRIPT;
            size += witnessScript.size();
        }

        // Size of hd keypaths
        size += sizeOfHDKeyPaths(hdKeyPaths);

        // Size of unknowns
        size += sizeOfUnknown(unknown);

        // Separator is 1 byte
        size += 1;

        return size;
    }

    /**
     * Write this PSBT output into the given buffer.
     * @param buf the buffer to write into
     * @return the buffer
     * @throws BufferOverflowException if the message doesn't fit the remaining buffer
     */
    public ByteBuffer write(ByteBuffer buf) throws BufferOverflowException {
        // Write the redeem script
        if (!redeemScript.isEmpty()) {
            Buffers.writeLengthPrefixedBytes(buf, new byte[]{PSBT_OUT_REDEEMSCRIPT});
            Buffers.writeLengthPrefixedBytes(buf, redeemScript.program());
        }

        // Write the witness script
        if (!witnessScript.isEmpty()) {
            Buffers.writeLengthPrefixedBytes(buf, new byte[]{PSBT_OUT_WITNESSSCRIPT});
            Buffers.writeLengthPrefixedBytes(buf, witnessScript.program());
        }

        // Write any hd keypaths
        serializeHDKeyPaths(buf, hdKeyPaths, PSBT_OUT_BIP32_DERIVATION);

        writeUnknown(buf, unknown);

        buf.put(PSBT_SEPARATOR);

        return buf;
    }

    /**
     * Merge another psbt output in to this one
     * @param psbtOutput the other psbt
     */
    void mergeInto(PsbtOutput psbtOutput) {
        // Use putAll here as the used objects are immutable
        hdKeyPaths.putAll(psbtOutput.hdKeyPaths);
        copyUnknown(psbtOutput.unknown, unknown);
        if (redeemScript.isEmpty() && !psbtOutput.redeemScript.isEmpty()) {
            redeemScript = psbtOutput.redeemScript.copy();
        }
        if (witnessScript.isEmpty() && !psbtOutput.witnessScript.isEmpty()) {
            witnessScript = psbtOutput.witnessScript.copy();
        }
    }
}
