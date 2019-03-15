/*
 * Copyright 2019 Tim Strasser
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

package org.bitcoinj.utils;

import static org.bitcoinj.utils.BtcFormat.COIN_SCALE;
import static org.bitcoinj.utils.BtcFormat.MICROCOIN_SCALE;
import static org.bitcoinj.utils.BtcFormat.MILLICOIN_SCALE;
import static org.junit.Assert.assertEquals;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Locale;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

@RunWith(Parameterized.class)
public class BtcFixedFormatTest {

    private final ArrayList<Integer> groups;
    private int input;
    private String expectedOutput;
    private BtcFixedFormat btcFixedFormat;

    public BtcFixedFormatTest(int input, String expectedOutput) {
        this.input = input;
        this.expectedOutput = expectedOutput;
        this.groups = new ArrayList<>();
    }

    @Parameterized.Parameters
    public static Collection<Object[]> parameters() {
        return Arrays.asList(new Object[][]{
                {COIN_SCALE, "Coin-"},
                {1, "Decicoin-"},
                {2, "Centicoin-"},
                {MILLICOIN_SCALE, "Millicoin-"},
                {MICROCOIN_SCALE, "Microcoin-"},
                {-1, "Dekacoin-"},
                {-2, "Hectocoin-"},
                {-3, "Kilocoin-"},
                {-6, "Megacoin-"},
                {-100, "Fixed (-100) "}
        });
    }

    @Before
    public void initBtcFixedFormat() {
        this.btcFixedFormat = new BtcFixedFormat(Locale.getDefault(), input, 2, groups);
    }

    @Test
    public void testPrefixLabel() {
        assertEquals(String.format("%s%s %s", expectedOutput, "format", btcFixedFormat.pattern()),
                btcFixedFormat.toString());
    }
}
