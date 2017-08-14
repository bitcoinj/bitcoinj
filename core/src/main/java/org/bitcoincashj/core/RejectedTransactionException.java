/*
 * Copyright 2014 Adam Mackler
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

/**
 * This exception is used by the TransactionBroadcast class to indicate that a broadcast
 * Transaction has been rejected by the network, for example because it violates a
 * protocol rule. Note that not all invalid transactions generate a reject message, and
 * some peers may never do so.
 */
public class RejectedTransactionException extends Exception {
    private Transaction tx;
    private RejectMessage rejectMessage;

    public RejectedTransactionException(Transaction tx, RejectMessage rejectMessage) {
        super(rejectMessage.toString());
        this.tx = tx;
        this.rejectMessage = rejectMessage;
    }

    /** Return the original Transaction object whose broadcast was rejected. */
    public Transaction getTransaction() { return tx; }

    /** Return the RejectMessage object representing the broadcast rejection. */
    public RejectMessage getRejectMessage() { return rejectMessage; }
}
