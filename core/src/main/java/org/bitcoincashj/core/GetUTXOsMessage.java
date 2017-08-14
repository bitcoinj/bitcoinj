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

package org.bitcoincashj.core;

import com.google.common.base.Objects;
import com.google.common.collect.ImmutableList;

import java.io.IOException;
import java.io.OutputStream;
import java.util.List;

/**
 * <p>This command is supported only by <a href="http://github.com/bitcoinxt/bitcoinxt">Bitcoin XT</a> nodes, which
 * advertise themselves using the second service bit flag. It requests a query of the UTXO set keyed by a set of
 * outpoints (i.e. tx hash and output index). The result contains a bitmap of spentness flags, and the contents of
 * the associated outputs if they were found. The results aren't authenticated by anything, so the peer could lie,
 * or a man in the middle could swap out its answer for something else. Please consult
 * <a href="https://github.com/bitcoin/bips/blob/master/bip-0065.mediawiki">BIP 65</a> for more information on this
 * message.</p>
 *
 * <p>Note that this message does not let you query the UTXO set by address, script or any other criteria. The
 * reason is that Bitcoin nodes don't calculate the necessary database indexes to answer such queries, to save
 * space and time. If you want to look up unspent outputs by address, you can either query a block explorer site,
 * or you can use the {@link FullPrunedBlockChain} class to build the required indexes yourself. Bear in that it will
 * be quite slow and disk intensive to do that!</p>
 * 
 * <p>Instances of this class are not safe for use by multiple threads.</p>
 */
public class GetUTXOsMessage extends Message {
    public static final int MIN_PROTOCOL_VERSION = 70002;
    /** Bitmask of service flags required for a node to support this command (0x3) */
    public static final long SERVICE_FLAGS_REQUIRED = 3;

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
    protected void bitcoinSerializeToStream(OutputStream stream) throws IOException {
        stream.write(new byte[]{includeMempool ? (byte) 1 : 0});  // include mempool.
        stream.write(new VarInt(outPoints.size()).encode());
        for (TransactionOutPoint outPoint : outPoints) {
            outPoint.bitcoinSerializeToStream(stream);
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        GetUTXOsMessage other = (GetUTXOsMessage) o;
        return includeMempool == other.includeMempool && outPoints.equals(other.outPoints);
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(includeMempool, outPoints);
    }
}
