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
 * Default fee calculator intended for the Bitcoin network.
 */
public class DefaultFeeCalculator implements FeeCalculator {
    @Override
    public Coin calculateFees(Wallet.SendRequest req, int calculatedSize) {
        return calculateFees(req.fee, req.feePerKb, calculatedSize);
    }

    @Override
    public Coin calculateFees(Coin fee, Coin feePerKb, Transaction tx) {
        return calculateFees(fee, feePerKb, tx.getOptimalEncodingMessageSize());
    }

    private Coin calculateFees(Coin fee, Coin feePerKb, int calculatedSize) {
        Coin fees = fee == null ? Coin.ZERO : fee;
        if (calculatedSize > 0) {
            // If the size is exactly 1000 bytes then we'll over-pay, but this should be rare.
            fees = fees.add(feePerKb.multiply((calculatedSize / 1000) + 1));
        } else {
            fees = fees.add(feePerKb);  // First time around the loop.
        }
        return fees;
    }
}
