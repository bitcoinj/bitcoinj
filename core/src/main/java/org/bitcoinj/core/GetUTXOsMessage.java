/*
 * Copyright 2014 the bitcoinj authors
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

package org.bitcoinj.core;

import com.google.common.collect.ImmutableList;

import java.io.IOException;
import java.io.OutputStream;
import java.util.List;

public class GetUTXOsMessage extends Message {
    public static final int MIN_PROTOCOL_VERSION = 70002;

    private boolean includeMempool;
    private ImmutableList<TransactionOutPoint> outPoints;

    public GetUTXOsMessage(NetworkParameters params, List<TransactionOutPoint> outPoints, boolean includeMempool) {
        super(params);
        this.outPoints = ImmutableList.copyOf(outPoints);
        this.includeMempool = includeMempool;
    }

    public GetUTXOsMessage(NetworkParameters params, byte[] payloadBytes) {
        super(params, payloadBytes, 0);
    }

    @Override
    protected void parse() throws ProtocolException {
        includeMempool = readBytes(1)[0] == 1;
        long numOutpoints = readVarInt();
        ImmutableList.Builder<TransactionOutPoint> list = ImmutableList.builder();
        for (int i = 0; i < numOutpoints; i++) {
            TransactionOutPoint outPoint = new TransactionOutPoint(params, payload, cursor);
            list.add(outPoint);
            cursor += outPoint.getMessageSize();
        }
        outPoints = list.build();
        length = cursor;
    }

    public boolean getIncludeMempool() {
        return includeMempool;
    }

    public ImmutableList<TransactionOutPoint> getOutPoints() {
        return outPoints;
    }

    @Override
    protected void parseLite() throws ProtocolException {
        // Not needed.
    }

    @Override
    void bitcoinSerializeToStream(OutputStream stream) throws IOException {
        stream.write(new byte[]{1});  // include mempool.
        stream.write(new VarInt(outPoints.size()).encode());
        for (TransactionOutPoint outPoint : outPoints) {
            outPoint.bitcoinSerializeToStream(stream);
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        GetUTXOsMessage that = (GetUTXOsMessage) o;

        if (includeMempool != that.includeMempool) return false;
        if (!outPoints.equals(that.outPoints)) return false;

        return true;
    }

    @Override
    public int hashCode() {
        int result = (includeMempool ? 1 : 0);
        result = 31 * result + outPoints.hashCode();
        return result;
    }
}
