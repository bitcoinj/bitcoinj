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
        INACTIVE(2),
        DEAD(3),
        PENDING(16),
        PENDING_INACTIVE(18),
        ALL(-1);
        
        private int value;
        Pool(int value) {
            this.value = value;
        }
        
        public int getValue() {
            return value;
        }

        public static Pool valueOf(int value) {
            switch (value) {
            case 0: return UNSPENT;
            case 1: return SPENT;
            case 2: return INACTIVE;
            case 3: return DEAD;
            case 16: return PENDING;
            case 18: return PENDING_INACTIVE;
            default: return null;
            }
        }
    }
    private Transaction transaction;
    private Pool pool;
    
    public WalletTransaction(Pool pool, Transaction transaction) {
        assert pool != null;
        
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

