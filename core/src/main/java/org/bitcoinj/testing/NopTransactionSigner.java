/**
 * Copyright 2014 Kosta Korenkov
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
package org.bitcoinj.testing;

import org.bitcoinj.signers.TransactionSigner;
import org.bitcoinj.wallet.KeyBag;

public class NopTransactionSigner implements TransactionSigner {
    private boolean isReady;

    public NopTransactionSigner() {
    }

    public NopTransactionSigner(boolean ready) {
        this.isReady = ready;
    }

    @Override
    public boolean isReady() {
        return isReady;
    }

    @Override
    public byte[] serialize() {
        return isReady ? new byte[]{1} : new byte[]{0};
    }

    @Override
    public void deserialize(byte[] data) {
        if (data.length > 0)
            isReady = data[0] == 1;
    }

    @Override
    public boolean signInputs(ProposedTransaction t, KeyBag keyBag) {
        return false;
    }
}
