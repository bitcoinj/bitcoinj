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

package org.bitcoinj.testing;

import org.bitcoinj.base.Coin;
import org.bitcoinj.base.Monetary;
import org.bitcoinj.base.Network;

/**
 * Mock Alt-net implementation of {@link Network} for unit tests.
 */
public class MockAltNetwork implements Network {
    @Override
    public String id() {
        return "mock.alt.network";
    }

    @Override
    public int legacyAddressHeader() {
        return 48;
    }

    @Override
    public int legacyP2SHHeader() {
        return 5;
    }

    @Override
    public String segwitAddressHrp() {
        return "mock";
    }

    @Override
    public String uriScheme() {
        return "mockcoin";
    }

    @Override
    public boolean hasMaxMoney() {
        return false;
    }

    @Override
    public Monetary maxMoney() {
        return Coin.valueOf(Long.MAX_VALUE);
    }

    @Override
    public boolean exceedsMaxMoney(Monetary monetary) {
        return false;
    }
}
