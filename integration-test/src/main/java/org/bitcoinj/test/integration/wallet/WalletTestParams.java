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

package org.bitcoinj.test.integration.wallet;

import java.io.File;
import java.time.Instant;

/**
 * Constant parameters used in Wallet integration tests
 */
public class WalletTestParams {
    public static final String WALLET_MNEMONIC = "panda diary marriage suffer basic glare surge auto scissors describe sell unique";
    public static final File WALLET_FILE = new File("src/test/resources/org/bitcoinj/test/integration/wallet/panda-test-wallet.wallet");
    public static final Instant WALLET_BIRTHDAY = Instant.ofEpochSecond(1554102000);
}
