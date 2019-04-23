/*
 * Copyright 2011 Google Inc.
 * Copyright 2014 Andreas Schildbach
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

package org.bitcoinj.core;

import org.bitcoinj.params.UnitTestParams;
import org.junit.Before;
import org.junit.Test;

import static org.bitcoinj.core.Utils.HEX;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

// TODO: This does not check the subVer or set fields. Support proper version matching.
public class AlertMessageTest {
    private static final byte[] TEST_KEY_PRIV = HEX.decode("6421e091445ade4b24658e96aa60959ce800d8ea9e7bd8613335aa65ba8d840b");
    private AlertMessage alertMessage;

    @Before
    public void setUp() throws Exception {
        final ECKey key = ECKey.fromPrivate(TEST_KEY_PRIV);
        NetworkParameters params = new UnitTestParams() {
            @Override
            public byte[] getAlertSigningKey() {
                return key.getPubKey();
            }
        };
        final byte[] payload = HEX.decode("5c010000004544eb4e000000004192ec4e00000000eb030000e9030000000000000048ee00000088130000002f43416c6572742073797374656d20746573743a2020202020202020207665722e302e352e3120617661696c61626c6500473045022100ec799908c008b272d5e5cd5a824abaaac53d210cc1fa517d8e22a701ecdb9e7002206fa1e7e7c251d5ba0d7c1fe428fc1870662f2927531d1cad8d4581b45bc4f8a7");
        // A CalertMessage taken from Bitcoin Core.
        alertMessage = new AlertMessage(params, payload);
    }
    
    @Test
    public void testGetRelayUntil() {
        assertEquals(1324041285, alertMessage.getRelayUntil().getTime() / 1000);
    }

    @Test
    public void testGetExpiration() {
        assertEquals(1324126785, alertMessage.getExpiration().getTime() / 1000);
    }

    @Test
    public void testGetId() {
        assertEquals(1003, alertMessage.getId());
    }

    @Test
    public void testGetCancel() {
        assertEquals(1001, alertMessage.getCancel());
    }

    @Test
    public void testGetMinVer() {
        assertEquals(0, alertMessage.getMinVer());
    }

    @Test
    public void testGetMaxVer() {
        assertEquals(61000, alertMessage.getMaxVer());
    }

    @Test
    public void testGetPriority() {
        assertEquals(5000, alertMessage.getPriority());
    }

    @Test
    public void testGetStatusBar() {
        assertEquals("CAlert system test:         ver.0.5.1 available", alertMessage.getStatusBar());
    }

    @Test
    public void testGetIsSignatureValid() {
        assertTrue(alertMessage.isSignatureValid());
    }
}
