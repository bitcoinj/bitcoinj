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

import junitparams.JUnitParamsRunner;
import junitparams.Parameters;
import org.junit.Test;
import org.junit.runner.RunWith;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * Test ProtocolVersion
 */
@RunWith(JUnitParamsRunner.class)
public class ProtocolVersionTest {
    @Test
    @Parameters(method = "allInstances")
    public void testValues(ProtocolVersion instance) {
        assertTrue(instance.intValue() > 0);
    }

    @Test
    @Parameters(method = "allInstances")
    public void deprecatedMembers(ProtocolVersion instance) {
        assertEquals(instance.intValue(), instance.getBitcoinProtocolVersion());
    }

    @Test
    public void deprecatedInstance() {
        assertEquals(60001, ProtocolVersion.PONG.intValue());
    }

    private ProtocolVersion[] allInstances() {
        return ProtocolVersion.values();
    }
}
