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

    @Test
    public void specificVersionValues() {
        assertEquals(70000, ProtocolVersion.MINIMUM.intValue());
        assertEquals(70001, ProtocolVersion.BLOOM_FILTER.intValue());
        assertEquals(70011, ProtocolVersion.BLOOM_FILTER_BIP111.intValue());
        assertEquals(70012, ProtocolVersion.WITNESS_VERSION.intValue());
        assertEquals(70013, ProtocolVersion.FEEFILTER.intValue());
        assertEquals(70013, ProtocolVersion.CURRENT.intValue());
    }

    @Test
    public void versionOrdering() {
        assertTrue(ProtocolVersion.MINIMUM.intValue() < ProtocolVersion.BLOOM_FILTER.intValue());
        assertTrue(ProtocolVersion.BLOOM_FILTER.intValue() < ProtocolVersion.BLOOM_FILTER_BIP111.intValue());
        assertTrue(ProtocolVersion.BLOOM_FILTER_BIP111.intValue() < ProtocolVersion.WITNESS_VERSION.intValue());
        assertTrue(ProtocolVersion.WITNESS_VERSION.intValue() <= ProtocolVersion.FEEFILTER.intValue());
    }

    @Test
    public void currentIsFeeFilter() {
        assertEquals(ProtocolVersion.FEEFILTER.intValue(), ProtocolVersion.CURRENT.intValue());
    }
}
