/**
 * Copyright 2012 Google Inc.
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

/**
 * A Transaction in a Wallet - includes the pool ID
 * 
 * @author Miron Cuperman
 */
public class WalletTransaction {
    public enum Pool {
        UNSPENT(0),
        SPENT(1),
        PENDING(2),
        INACTIVE(3),
        DEAD(4),
        ALL(-1);
        
        private int value;
        Pool(int value) {
            this.value = value;
        }
        
        public int getValue() {
            return value;
        }
    }
    private Transaction transaction;
    private Pool pool;
    
    public WalletTransaction(Pool pool, Transaction transaction) {
        this.pool = pool;
        this.transaction = transaction;
    }

    public Transaction getTransaction() {
        return transaction;
    }
    
    public Pool getPool() {
        return pool;
    }
}

