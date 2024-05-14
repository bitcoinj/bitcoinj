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

package org.bitcoinj.examples;

import org.bitcoinj.base.Address;
import org.bitcoinj.base.BitcoinNetwork;
import org.bitcoinj.base.ScriptType;
import org.bitcoinj.core.Context;
import org.bitcoinj.crypto.ECKey;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;

/**
 * Forwarding Service Functional/Integration test. Uses {@link BitcoinNetwork#TESTNET} so is {@code @Disabled}.
 * To run this test comment-out the {@code @Disabled} annotation.
 */
@Disabled
public class ForwardingServiceTest {
    static final BitcoinNetwork network = BitcoinNetwork.TESTNET;
    static final Address forwardingAddress = new ECKey().toAddress(ScriptType.P2WPKH, network);
    static final String[] args = new String[] { forwardingAddress.toString(), network.toString() };

    @BeforeEach
    void setupTest() {
        Context.propagate(new Context());
    }

    @Test
    public void startAndImmediatelyInterrupt(@TempDir File tempDir) {
        // Start the service and immediately interrupt
        Thread thread = new Thread(
                () -> new ForwardingService(args).run()
        );
        thread.start();
        thread.interrupt();
    }

    @Test
    public void startAndImmediatelyClose(@TempDir File tempDir) {
        // Instantiate the service, start it, and immediately close it
        try (ForwardingService service = new ForwardingService(args) ) {
            service.run();
        }
    }
}
