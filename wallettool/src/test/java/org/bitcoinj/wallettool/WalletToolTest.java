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

package org.bitcoinj.wallettool;

import org.junit.jupiter.api.Test;
import picocli.CommandLine;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * Basic functional/integration tests of {@code wallet-tool}
 */
public class WalletToolTest {

    @Test
    void canConstruct() {
        WalletTool walletTool = new WalletTool();

        assertNotNull(walletTool);
    }

    @Test
    void noArgsFails() {
        int exitCode = execute();

        assertEquals(2, exitCode);
    }

    @Test
    void emptyStringArgFails() {
        int exitCode = execute("");

        assertEquals(1, exitCode);
    }

    @Test
    void helpSucceeds() {
        int exitCode = execute("--help");

        assertEquals(0, exitCode);
    }

    /**
     * Run the wallet-tool via {@link CommandLine#execute(String...)}
     * @param args command-line arguments
     * @return exit code
     */
    int execute(String... args) {
        return new CommandLine(new WalletTool()).execute(args);
    }
}
