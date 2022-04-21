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

import org.bitcoinj.core.Coin;
import org.bitcoinj.core.TransactionOutput;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import java.util.stream.Stream;

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

    // Select using a filtering predicate
    static CoinSelection select(Coin target, List<TransactionOutput> candidates, Predicate<TransactionOutput> filter) {
        return selectCommon(target, candidates, false, null, filter);
    }

    // Select with a pre-sort, then using a filtering predicate
    static CoinSelection sortSelect(Coin target, List<TransactionOutput> candidates, Comparator<TransactionOutput> comparator, Predicate<TransactionOutput> filter) {
        return selectCommon(target, candidates, true, comparator, filter);
    }

    // Default implementation
    static CoinSelection selectCommon(Coin target, List<TransactionOutput> candidates, boolean sortFirst, Comparator<TransactionOutput> comparator, Predicate<TransactionOutput> filter) {
        Stream<TransactionOutput> stream = sortFirst ? candidates.stream().sorted(comparator) : candidates.stream();
        List<TransactionOutput> sorted = stream.collect(Collectors.toList());
        List<TransactionOutput> gathered = new ArrayList<>();
        long satsGathered = 0;
        for (TransactionOutput candidate : sorted) {
            if (satsGathered >= target.value) {
                break;  // This is short-circuiting, so we can't do it without a custom stream short-circuiting operator or Java9's `takeWhile()`
            }
            if (filter.test(candidate)) {
                satsGathered += candidate.getValue().value;
                gathered.add(candidate);
            }
        }
        return new CoinSelection(Coin.ofSat(satsGathered), gathered);

    }

    interface FilteringCoinSelector extends CoinSelector, Predicate<TransactionOutput>  {
        @Override
        default CoinSelection select(Coin target, List<TransactionOutput> candidates) {
            return CoinSelector.select(target, candidates, this);
        }
    }

    /**
     * This is the comparator from {@link DefaultCoinSelector} that could be used to simplify it.
     */
    Comparator<TransactionOutput> TXOUT_COMPARATOR = (a, b) -> {
        int depth1 = a.getParentTransactionDepthInBlocks();
        int depth2 = b.getParentTransactionDepthInBlocks();
        Coin aValue = a.getValue();
        Coin bValue = b.getValue();
        BigInteger aCoinDepth = BigInteger.valueOf(aValue.value).multiply(BigInteger.valueOf(depth1));
        BigInteger bCoinDepth = BigInteger.valueOf(bValue.value).multiply(BigInteger.valueOf(depth2));
        int c1 = bCoinDepth.compareTo(aCoinDepth);
        if (c1 != 0) return c1;
        // The "coin*days" destroyed are equal, sort by value alone to get the lowest transaction size.
        int c2 = bValue.compareTo(aValue);
        if (c2 != 0) return c2;
        // They are entirely equivalent (possibly pending) so sort by hash to ensure a total ordering.
        BigInteger aHash = a.getParentTransactionHash().toBigInteger();
        BigInteger bHash = b.getParentTransactionHash().toBigInteger();
        return aHash.compareTo(bHash);
    };

}
