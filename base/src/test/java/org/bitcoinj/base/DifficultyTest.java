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

package org.bitcoinj.base;

import junitparams.JUnitParamsRunner;
import junitparams.Parameters;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.math.BigInteger;
import java.time.Duration;

import static org.junit.Assert.assertEquals;

@RunWith(JUnitParamsRunner.class)
public class DifficultyTest {

    @Test
    @Parameters(method = "testVectors")
    public void compactToInteger(long compact, String expectedInteger) {
        Difficulty difficulty = Difficulty.ofCompact(compact);
        assertEquals(expectedInteger, difficulty.toIntegerString());
    }

    @Test
    @Parameters(method = "testVectors")
    public void integerToCompact(long expectedCompact, String integerHex) {
        Difficulty difficulty = Difficulty.ofInteger(new BigInteger(integerHex, 16));
        long compact = difficulty.compact();
        assertEquals(expectedCompact, compact);
    }

    private Object[] testVectors() {
        return new Object[] {
                // from https://en.bitcoin.it/wiki/Difficulty
                new Object[] { 0x1d00ffff, "ffff0000000000000000000000000000000000000000000000000000" }, // difficulty 1
                new Object[] { 0x1b0404cb, "404cb000000000000000000000000000000000000000000000000" },
                // from https://developer.bitcoin.org/reference/block_chain.html#target-nbits
                new Object[] { 0x02008000, "80" },
                new Object[] { 0x05009234, "92340000" },
                new Object[] { 0x04123456, "12345600" },
        };
    }

    @Test
    public void exponentZero_mantissaIsShiftedOutOfExistance() {
        assertEquals("0", Difficulty.ofCompact(0x00778899).toIntegerString());
    }

    @Test
    public void exponentOne_mantissaIsLoosingTwoBytes() {
        assertEquals("77", Difficulty.ofCompact(0x01778899).toIntegerString());
    }

    @Test
    public void exponentTwo_mantissaIsLoosingOneByte() {
        assertEquals("7788", Difficulty.ofCompact(0x02778899).toIntegerString());
    }

    @Test(expected = IllegalArgumentException.class)
    public void exponent_tooHigh() {
        Difficulty.ofCompact(0x217fffff);
    }

    @Test
    public void mantissa_highestPossible() {
        Difficulty.ofCompact(0x007fffff);
    }

    @Test(expected = IllegalArgumentException.class)
    public void mantissa_tooHigh() {
        // the 24th bit is sign, so the value would be negative
        Difficulty.ofCompact(0x00800000);
    }

    @Test
    public void mantissa_lowestPossible() {
        Difficulty.ofCompact(0x00008000);
    }

    @Test(expected = IllegalArgumentException.class)
    public void mantissa_tooLow() {
        // these bits can be encoded more optimally by shifting to the left by one
        Difficulty.ofCompact(0x00007fff);
    }

    @Test(expected = IllegalArgumentException.class)
    public void ofInteger_negativeValueNotAllowed() {
        Difficulty.ofInteger(BigInteger.ONE.negate());
    }

    @Test(expected = IllegalArgumentException.class)
    public void ofInteger_valueTooHigh() {
        BigInteger easierThanEasiest = Difficulty.EASIEST_DIFFICULTY_TARGET.asInteger().add(BigInteger.ONE);
        Difficulty.ofInteger(easierThanEasiest);
    }

    @Test
    public void adjust_easiestEvenEasier_shouldNotAdjust() {
        Difficulty easier = Difficulty.EASIEST_DIFFICULTY_TARGET.adjust(
                Duration.ofDays(15), Duration.ofDays(10), Difficulty.EASIEST_DIFFICULTY_TARGET);
        assertEquals(Difficulty.EASIEST_DIFFICULTY_TARGET, easier);
    }

    @Test
    public void compareTo() {
        Difficulty d1 = Difficulty.ofCompact(0x10771111);
        Difficulty d2 = Difficulty.ofCompact(0x11111177);
        assertEquals(1, d2.compareTo(d1));
    }
}
