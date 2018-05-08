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

import java.io.IOException;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class TransactionWitness {
    public static final TransactionWitness EMPTY = new TransactionWitness(0);

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
        for (int i = 0; i < pushes.size(); i++) {
            byte[] push = pushes.get(i);
            stream.write(new VarInt(push.length).encode());
            stream.write(push);
        }
    }

    @Override
    public String toString() {
        List<String> stringPushes = new ArrayList<>();
        for (int j = 0; j < this.getPushCount(); j++) {
            byte[] push = this.getPush(j);
            if (push == null) {
                stringPushes.add("NULL");
            } else if (push.length == 0) {
                stringPushes.add("EMPTY");
            } else {
                stringPushes.add(Utils.HEX.encode(push));
            }
        }
        return Utils.SPACE_JOINER.join(stringPushes);
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
