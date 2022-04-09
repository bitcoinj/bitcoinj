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

package org.bitcoinj.core;

import org.junit.Test;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.stream.Stream;

import static java.util.stream.Collectors.collectingAndThen;
import static java.util.stream.Collectors.toList;
import static org.junit.Assert.assertEquals;

/**
 * Test sorting of {@link Address} (both {{@link LegacyAddress} and {@link SegwitAddress}}) with
 * the default comparators.
 */
public class AddressComparatorSortTest {
    /**
     * A manually sorted list of address for verifying sorting with our default comparator.
     * See {@link Address#compareTo}.
     */
    private static final List<Address> correctlySortedAddresses = Stream.of(
                    // Main net, Legacy
                    "1Dorian4RoXcnBv9hnQ4Y2C1an6NJ4UrjX",
                    "1EXoDusjGwvnjZUyKkxZ4UHEf77z6A5S4P",
                    // Main net, Segwit
                    "bc1qgdjqv0av3q56jvd82tkdjpy7gdp9ut8tlqmgrpmv24sq90ecnvqqjwvw97",
                    "bc1q5shngj24323nsrmxv99st02na6srekfctt30ch",
                    // Test net, Legacy
                    "moneyqMan7uh8FqdCA2BV5yZ8qVrc9ikLP",
                    "mpexoDuSkGGqvqrkrjiFng38QPkJQVFyqv",
                    // Test net, Segwit
                    "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7",
                    "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx"
            ).map(s -> Address.fromString(null, s))
            .collect(collectingAndThen(toList(), Collections::unmodifiableList));

    @Test
    public void testAddressComparisonSortOrder() {
        // Shuffle the list and then sort with the built-in comparator
        List<Address> shuffled = shuffled(correctlySortedAddresses);    // Shuffled copy
        List<Address> sortedAfterShuffle = sorted(shuffled);            // Sorted copy of shuffled copy

        assertEquals(correctlySortedAddresses, sortedAfterShuffle);
    }

    // shuffle an immutable list producing a new immutable list
    private static List<Address> shuffled(List<Address> addresses) {
        List<Address> shuffled = new ArrayList<>(addresses);            // Make modifiable copy
        Collections.shuffle(shuffled);                                  // shuffle it
        return Collections.unmodifiableList(shuffled);                  // Return unmodifiable view
    }

    // sort an immutable list producing a new immutable list
    private static List<Address> sorted(List<Address> addresses) {
        return addresses.stream()                                       // stream it
                .sorted()                                               // sort it
                .collect(collectingAndThen(toList(), Collections::unmodifiableList));  // collect as unmodifiable
    }
}
