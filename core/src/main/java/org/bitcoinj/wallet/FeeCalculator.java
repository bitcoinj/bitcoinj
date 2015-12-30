/*
 * Copyright 2015 Ross Nicoll
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.bitcoinj.wallet;

import org.bitcoinj.core.Coin;
import org.bitcoinj.core.Transaction;
import org.bitcoinj.core.Wallet;

/**
 * Modular calculator for transaction fees.
 */
public interface FeeCalculator {
    /**
     * Calculate the fees required for a send request.
     *
     * @param req the request to take fee calculation variables (fee and fee per
     * kilobyte) from. Implementations may use the contained transaction for
     * information such as structure of the outputs, but must use calculatedSize
     * for the total transactions size.
     * @param calculatedSize the calculateSize of the transaction including change
     * outputs.
     * @return fees required for the request.
     */
    public Coin calculateFees(Wallet.SendRequest req, int calculatedSize);

    /**
     * Calculate the fees required for a transaction.
     *
     * @param fee the base fee to pay for the transaction.
     * @param feePerKb the additional fee per kilobyte of data.
     * @param tx the transaction to calculate fee for.
     * @return fees required for the transaction.
     */
    public Coin calculateFees(Coin fee, Coin feePerKb, Transaction tx);
}
