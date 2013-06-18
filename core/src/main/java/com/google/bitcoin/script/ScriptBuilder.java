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

package com.google.bitcoin.script;

import com.google.bitcoin.core.Address;
import com.google.bitcoin.core.ECKey;
import com.google.bitcoin.crypto.TransactionSignature;
import com.google.common.collect.Lists;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static com.google.bitcoin.script.ScriptOpCodes.*;
import static com.google.common.base.Preconditions.checkArgument;

/**
 * <p>Tools for the construction of commonly used script types. You don't normally need this as it's hidden behind
 * convenience methods on {@link com.google.bitcoin.core.Transaction}, but they are useful when working with the
 * protocol at a lower level.</p>
 */
public class ScriptBuilder {
    private List<ScriptChunk> chunks;

    public ScriptBuilder() {
        chunks = Lists.newLinkedList();
    }

    public ScriptBuilder op(int opcode) {
        chunks.add(new ScriptChunk(true, new byte[]{(byte)opcode}));
        return this;
    }

    public ScriptBuilder data(byte[] data) {
        byte[] copy = Arrays.copyOf(data, data.length);
        chunks.add(new ScriptChunk(false, copy));
        return this;
    }

    public ScriptBuilder smallNum(int num) {
        checkArgument(num >= 0, "Cannot encode negative numbers with smallNum");
        checkArgument(num <= 16, "Cannot encode numbers larger than 16 with smallNum");
        chunks.add(new ScriptChunk(true, new byte[]{(byte)Script.encodeToOpN(num)}));
        return this;
    }

    public Script build() {
        return new Script(chunks);
    }

    /** Creates a scriptPubKey that encodes payment to the given address. */
    public static Script createOutputScript(Address to) {
        // OP_DUP OP_HASH160 <pubKeyHash> OP_EQUALVERIFY OP_CHECKSIG
        return new ScriptBuilder()
                .op(OP_DUP)
                .op(OP_HASH160)
                .data(to.getHash160())
                .op(OP_EQUALVERIFY)
                .op(OP_CHECKSIG)
                .build();
    }

    /** Creates a scriptPubKey that encodes payment to the given raw public key. */
    public static Script createOutputScript(ECKey key) {
        return new ScriptBuilder().data(key.getPubKey()).op(OP_CHECKSIG).build();
    }

    /** Creates a scriptSig that can redeem a pay-to-address output. */
    public static Script createInputScript(TransactionSignature signature, ECKey pubKey) {
        byte[] pubkeyBytes = pubKey.getPubKey();
        return new ScriptBuilder().data(signature.encodeToBitcoin()).data(pubkeyBytes).build();
    }

    /** Creates a scriptSig that can redeem a pay-to-pubkey output. */
    public static Script createInputScript(TransactionSignature signature) {
        return new ScriptBuilder().data(signature.encodeToBitcoin()).build();
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
        List<byte[]> sigs = new ArrayList<byte[]>(signatures.size());
        for (TransactionSignature signature : signatures)
            sigs.add(signature.encodeToBitcoin());
        return createMultiSigInputScriptBytes(sigs);
    }

    /** Create a program that satisfies an OP_CHECKMULTISIG program, using pre-encoded signatures. */
    public static Script createMultiSigInputScriptBytes(List<byte[]> signatures) {
        checkArgument(signatures.size() <= 16);
        ScriptBuilder builder = new ScriptBuilder();
        builder.smallNum(0);  // Work around a bug in CHECKMULTISIG that is now a required part of the protocol.
        for (byte[] signature : signatures)
            builder.data(signature);
        return builder.build();
    }
}
