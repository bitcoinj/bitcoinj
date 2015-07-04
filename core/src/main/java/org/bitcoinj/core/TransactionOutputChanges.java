/**
 * Copyright 2012 Matt Corallo.
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

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.LinkedList;
import java.util.List;

/**
 * <p>TransactionOutputChanges represents a delta to the set of unspent outputs. It used as a return value for
 * {@link AbstractBlockChain#connectTransactions(int, Block)}. It contains the full list of transaction outputs created
 * and spent in a block. It DOES contain outputs created that were spent later in the block, as those are needed for
 * BIP30 (no duplicate txid creation if the previous one was not fully spent prior to this block) verification.</p>
 */
public class TransactionOutputChanges {
    public final List<UTXO> txOutsCreated;
    public final List<UTXO> txOutsSpent;
    
    public TransactionOutputChanges(List<UTXO> txOutsCreated, List<UTXO> txOutsSpent) {
        this.txOutsCreated = txOutsCreated;
        this.txOutsSpent = txOutsSpent;
    }
    
    public TransactionOutputChanges(InputStream in) throws IOException {
        int numOutsCreated = (in.read() & 0xFF) |
                             ((in.read() & 0xFF) << 8) |
                             ((in.read() & 0xFF) << 16) |
                             ((in.read() & 0xFF) << 24);
        txOutsCreated = new LinkedList<UTXO>();
        for (int i = 0; i < numOutsCreated; i++)
            txOutsCreated.add(new UTXO(in));
        
        int numOutsSpent = (in.read() & 0xFF) |
                           ((in.read() & 0xFF) << 8) |
                           ((in.read() & 0xFF) << 16) |
                           ((in.read() & 0xFF) << 24);
        txOutsSpent = new LinkedList<UTXO>();
        for (int i = 0; i < numOutsSpent; i++)
            txOutsSpent.add(new UTXO(in));
    }

    public void serializeToStream(OutputStream bos) throws IOException {
        int numOutsCreated = txOutsCreated.size();
        bos.write(0xFF & numOutsCreated);
        bos.write(0xFF & (numOutsCreated >> 8));
        bos.write(0xFF & (numOutsCreated >> 16));
        bos.write(0xFF & (numOutsCreated >> 24));
        for (UTXO output : txOutsCreated) {
            output.serializeToStream(bos);
        }
        
        int numOutsSpent = txOutsSpent.size();
        bos.write(0xFF & numOutsSpent);
        bos.write(0xFF & (numOutsSpent >> 8));
        bos.write(0xFF & (numOutsSpent >> 16));
        bos.write(0xFF & (numOutsSpent >> 24));
        for (UTXO output : txOutsSpent) {
            output.serializeToStream(bos);
        }
    }
}
