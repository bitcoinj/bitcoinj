/*
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

package org.bitcoinj.core;

import org.bitcoinj.base.utils.ByteUtils;
import org.bitcoinj.core.internal.InternalUtils;
import org.bitcoinj.crypto.TransactionSignature;
import org.bitcoinj.script.Script;

import javax.annotation.Nullable;
import java.io.IOException;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static com.google.common.base.Preconditions.checkArgument;

public class TransactionWitness {
    public static final TransactionWitness EMPTY = new TransactionWitness(0);

    /**
     * Creates the stack pushes necessary to redeem a P2WPKH output. If given signature is null, an empty push will be
     * used as a placeholder.
     */
    public static TransactionWitness redeemP2WPKH(@Nullable TransactionSignature signature, ECKey pubKey) {
        checkArgument(pubKey.isCompressed(), "only compressed keys allowed");
        TransactionWitness witness = new TransactionWitness(2);
        witness.setPush(0, signature != null ? signature.encodeToBitcoin() : new byte[0]); // signature
        witness.setPush(1, pubKey.getPubKey()); // pubkey
        return witness;
    }

    /**
     * Creates the stack pushes necessary to redeem a P2WSH output.
     */
    public static TransactionWitness redeemP2WSH(Script witnessScript, TransactionSignature... signatures) {
        TransactionWitness witness = new TransactionWitness(signatures.length + 2);
        witness.setPush(0, new byte[]{});
        int i;
        for (i = 0; i < signatures.length; i++) {
            witness.setPush(i + 1, signatures[i].encodeToBitcoin());
        }
        witness.setPush(i + 1, witnessScript.getProgram());
        return witness;
    }

    private final List<byte[]> pushes;

    public TransactionWitness(int pushCount) {
        pushes = new ArrayList<>(Math.min(pushCount, Utils.MAX_INITIAL_ARRAY_LENGTH));
    }

    public byte[] getPush(int i) {
        return pushes.get(i);
    }

    public int getPushCount() {
        return pushes.size();
    }

    public void setPush(int i, byte[] value) {
        while (i >= pushes.size()) {
            pushes.add(new byte[]{});
        }
        pushes.set(i, value);
    }

    protected void bitcoinSerializeToStream(OutputStream stream) throws IOException {
        stream.write(new VarInt(pushes.size()).encode());
        for (byte[] push : pushes) {
            stream.write(new VarInt(push.length).encode());
            stream.write(push);
        }
    }

    @Override
    public String toString() {
        List<String> stringPushes = new ArrayList<>(pushes.size());
        for (byte[] push : pushes) {
            if (push == null) {
                stringPushes.add("NULL");
            } else if (push.length == 0) {
                stringPushes.add("EMPTY");
            } else {
                stringPushes.add(ByteUtils.HEX.encode(push));
            }
        }
        return InternalUtils.SPACE_JOINER.join(stringPushes);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        TransactionWitness other = (TransactionWitness) o;
        if (pushes.size() != other.pushes.size()) return false;
        for (int i = 0; i < pushes.size(); i++) {
            if (!Arrays.equals(pushes.get(i), other.pushes.get(i))) return false;
        }
        return true;
    }

    @Override
    public int hashCode() {
        int hashCode = 1;
        for (byte[] push : pushes) {
            hashCode = 31 * hashCode + (push == null ? 0 : Arrays.hashCode(push));
        }
        return hashCode;
    }
}
