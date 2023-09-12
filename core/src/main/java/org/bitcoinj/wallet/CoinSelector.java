/*
 * Copyright by the original author or authors.
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
import org.bitcoinj.core.TransactionOutput;

import java.util.List;
import java.util.function.Predicate;

import static java.util.stream.Collectors.collectingAndThen;

/**
 * A CoinSelector is responsible for picking some outputs to spend, from the list of all possible outputs. It
 * allows you to customize the policies for creation of transactions to suit your needs. The select operation
 * may return a {@link CoinSelection} that has a valueGathered lower than the requested target, if there's not
 * enough money in the wallet.
 */
@FunctionalInterface
public interface CoinSelector {
    /**
     * Creates a CoinSelection that tries to meet the target amount of value. The candidates list is given to
     * this call and can be edited freely. See the docs for CoinSelection to learn more, or look a the implementation
     * of {@link DefaultCoinSelector}.
     */
    CoinSelection select(Coin target, List<TransactionOutput> candidates);

    /**
    * Create a {@code CoinSelector} from a predicate function that filters a single {@link TransactionOutput}
    * @param predicate Returns true if a "coin" ({@code TransactionOutput}) should be included.
    * @return A CoinSelector that only returns coins matching the predicate
    */
    static CoinSelector fromPredicate(Predicate<TransactionOutput> predicate) {
        return (target, candidates) -> candidates.stream()
                        .filter(predicate)
                        .collect(collectingAndThen(StreamUtils.toUnmodifiableList(), CoinSelection::new));
    }
}
