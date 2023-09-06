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

import org.bitcoinj.base.Coin;
import org.bitcoinj.base.internal.StreamUtils;
import org.bitcoinj.core.TransactionOutPoint;
import org.bitcoinj.core.TransactionOutput;

import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * A filtering coin selector delegates to another coin selector, but won't select outputs spent by the given transactions.
 */
public class FilteringCoinSelector implements CoinSelector {
    protected final CoinSelector delegate;
    protected final Set<TransactionOutPoint> spent;

    public FilteringCoinSelector(CoinSelector delegate, List<TransactionOutPoint> excludedOutPoints) {
        this.delegate = delegate;
        this.spent = Collections.unmodifiableSet(new HashSet<>(excludedOutPoints));
    }

    @Override
    public CoinSelection select(Coin target, List<TransactionOutput> candidates) {
        List<TransactionOutput> filtered = candidates.stream()
                .filter(output -> !spent.contains(output.getOutPointFor()))
                .collect(StreamUtils.toUnmodifiableList());
        return delegate.select(target, filtered);
    }
}
