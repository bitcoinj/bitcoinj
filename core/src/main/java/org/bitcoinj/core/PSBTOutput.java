/*
 * Copyright 2019 John L. Jegutanis
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
import org.bitcoinj.script.Script;

import java.io.IOException;
import java.io.OutputStream;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.bitcoinj.core.PartiallySignedTransaction.*;

/**
 * A class for PSBTs which contain per output information.
 *
 * Note: this is an experimental "beta" API and could change in future releases
 * */
@Beta
public class PSBTOutput extends ChildMessage {
    public Script redeemScript;
    public Script witnessScript;
    public Map<ECKey, KeyOriginInfo> hdKeyPaths;
    public Map<RawBytes, RawBytes> unknown;

    public PSBTOutput(NetworkParameters params){
        super(params);
        redeemScript = Script.EMPTY;
        witnessScript = Script.EMPTY;
        unknown = new LinkedHashMap<>();
        hdKeyPaths = new LinkedHashMap<>();
    }

    public PSBTOutput(NetworkParameters params, PartiallySignedTransaction psbt, byte[] payload, int offset,
                     MessageSerializer serializer) {
        super(params, payload, offset, psbt, serializer, UNKNOWN_LENGTH);
    }

    @Override
    protected void parse() throws ProtocolException {
        redeemScript = Script.EMPTY;
        witnessScript = Script.EMPTY;
        unknown = new LinkedHashMap<>();
        hdKeyPaths = new LinkedHashMap<>();

        // Used for duplicate key detection
        HashSet<RawBytes> keyLookup = new HashSet<>();

        // Read loop
        boolean foundSeparator = false;
        while (hasMoreBytes()) {
            byte[] key = readByteArray();

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
                    redeemScript = new Script(readByteArray());
                    break;
                case PSBT_OUT_WITNESSSCRIPT:
                    if (!keyLookup.add(RawBytes.wrap(key))) {
                        throw new ProtocolException("Duplicate Key, output witnessScript already provided");
                    } else if (key.length != 1) {
                        throw new ProtocolException("Output witnessScript key is more than one byte type");
                    }
                    witnessScript = new Script(readByteArray());
                    break;
                case PSBT_OUT_BIP32_DERIVATION:
                    // Also does the key length and duplication checks
                    parseHDKeyPaths(this, key, hdKeyPaths);
                    break;
                // Unknown stuff
                default:
                    if (!keyLookup.add(RawBytes.wrap(key))) {
                        throw new ProtocolException("Duplicate Key, key for unknown value already provided");
                    }
                    unknown.put(RawBytes.wrap(key), RawBytes.wrap(readByteArray()));
            }
        }

        if (!foundSeparator) {
            throw new ProtocolException("Separator is missing at the end of an output map");
        }

        // The total length of the input
        length = cursor - offset;
    }

    @Override
    protected void bitcoinSerializeToStream(OutputStream stream) throws IOException {
        // Write the redeem script
        if (!redeemScript.isEmpty()) {
            serializeToVector(stream, PSBT_OUT_REDEEMSCRIPT);
            serializeToVector(stream, redeemScript.getProgram());
        }

        // Write the witness script
        if (!witnessScript.isEmpty()) {
            serializeToVector(stream, PSBT_OUT_WITNESSSCRIPT);
            serializeToVector(stream, witnessScript.getProgram());
        }

        // Write any hd keypaths
        serializeHDKeyPaths(stream, hdKeyPaths, PSBT_OUT_BIP32_DERIVATION);

        serializeUnknown(stream, unknown);

        stream.write(PSBT_SEPARATOR);
    }

    public void merge(PSBTOutput psbtOutput) {
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
