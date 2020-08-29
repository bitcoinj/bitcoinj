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
package org.bitcoinj.core

import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import org.junit.jupiter.api.Assertions.assertEquals

/**
 * Integration test for [Address] sorting using the [Comparable] implementation
 * in [Address], [LegacyAddress], and [SegwitAddress].
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class AddressComparisonTest  {

    private val correctlySortedAddresses = listOf(
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
    ).map{Address.fromString(null, it)}

    @Test
    fun testAddressComparisonSortOrder() {
        // Shuffle the list and then sort with the built-in comparator
        val sortedAfterShuffle = correctlySortedAddresses.shuffled().sorted()

        assertEquals(correctlySortedAddresses, sortedAfterShuffle)
    }
}