/*
 * Copyright 2014 the bitcoinj authors.
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

package org.bitcoinj.wallet;

import org.bitcoinj.core.*;

import java.util.HashSet;
import java.util.Iterator;
import java.util.List;

/**
 * A filtering coin selector delegates to another coin selector, but won't select outputs spent by the given transactions.
 */
public class FilteringCoinSelector implements CoinSelector {
    protected CoinSelector delegate;
    protected HashSet<TransactionOutPoint> spent = new HashSet<>();

    public FilteringCoinSelector(CoinSelector delegate) {
        this.delegate = delegate;
    }

    public void excludeOutputsSpentBy(Transaction tx) {
        for (TransactionInput input : tx.getInputs()) {
            spent.add(input.getOutpoint());
        }
    }

    @Override
    public CoinSelection select(Coin target, List<TransactionOutput> candidates) {
        Iterator<TransactionOutput> iter = candidates.iterator();
        while (iter.hasNext()) {
            TransactionOutput output = iter.next();
            if (spent.contains(output.getOutPointFor())) iter.remove();
        }
        return delegate.select(target, candidates);
    }
}
