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

import org.bitcoinj.base.internal.MockAltNetwork;
import org.bitcoinj.core.BitcoinSerializer;
import org.bitcoinj.core.Block;
import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.core.StoredBlock;
import org.bitcoinj.core.VerificationException;
import org.bitcoinj.store.BlockStore;
import org.bitcoinj.store.BlockStoreException;

/**
 * Mock Alt-net subclass of {@link NetworkParameters} for unit tests.
 */
public class MockAltNetworkParams extends NetworkParameters {
    public static final String MOCKNET_GOOD_ADDRESS = "LLxSnHLN2CYyzB5eWTR9K9rS9uWtbTQFb6";

    public MockAltNetworkParams() {
        super(new MockAltNetwork());
    }

    @Override
    public Block getGenesisBlock() {
        return null;
    }

    @Override
    public BitcoinSerializer getSerializer() {
        return null;
    }
}
