/**
 * Copyright 2014 Andreas Schildbach
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

package com.google.bitcoin.core;

import static org.junit.Assert.*;

import org.junit.Test;

import com.google.bitcoin.params.RegTestParams;

public class TransactionTest {

    private static final RegTestParams PARAMS = RegTestParams.get();

    @Test
    public void fixedHash() throws Exception {
        Sha256Hash hash = new Sha256Hash(new byte[32]);
        Transaction tx = new Transaction(PARAMS, 1, hash);
        tx.addInput(new TransactionInput(PARAMS, tx, new byte[0]));
        tx.addOutput(new TransactionOutput(PARAMS, tx, Coin.COIN, new byte[0]));
        tx.setLockTime(1234);
        assertEquals(hash, tx.getHash());
    }
}
