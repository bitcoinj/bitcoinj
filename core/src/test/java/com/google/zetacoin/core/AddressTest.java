/**
 * Copyright 2011 Google Inc.
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

package com.google.zetacoin.core;

import com.google.zetacoin.params.MainNetParams;
import com.google.zetacoin.params.TestNet3Params;
import com.google.zetacoin.script.ScriptBuilder;

import org.junit.Test;
import org.spongycastle.util.encoders.Hex;

import java.util.Arrays;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class AddressTest {
    static final NetworkParameters testParams = TestNet3Params.get();
    static final NetworkParameters mainParams = MainNetParams.get();

    @Test
    public void stringification() throws Exception {
        // Test a testnet address.
        Address a = new Address(testParams, Hex.decode("fda79a24e50ff70ff42f7d89585da5bd19d9e5cc"));
        assertEquals("cosHPHjvW6CfJJtk5wxNoH6yfcqgNyBbfU", a.toString());
        assertFalse(a.isP2SHAddress());

        Address b = new Address(mainParams, Hex.decode("4a22c3c4cbb31e4d03b15550636762bda0baf85a"));
        assertEquals("ZJoFRNuQw78Egw5ZBZ69vRWWk2bFyLy75t", b.toString());
        assertFalse(b.isP2SHAddress());
    }
    
    @Test
    public void decoding() throws Exception {
        Address a = new Address(testParams, "cosHPHjvW6CfJJtk5wxNoH6yfcqgNyBbfU");
        assertEquals("fda79a24e50ff70ff42f7d89585da5bd19d9e5cc", Utils.bytesToHexString(a.getHash160()));

        Address b = new Address(mainParams, "ZJoFRNuQw78Egw5ZBZ69vRWWk2bFyLy75t");
        assertEquals("4a22c3c4cbb31e4d03b15550636762bda0baf85a", Utils.bytesToHexString(b.getHash160()));
    }
    
    @Test
    public void errorPaths() {
        // Check what happens if we try and decode garbage.
        try {
            new Address(testParams, "this is not a valid address!");
            fail();
        } catch (WrongNetworkException e) {
            fail();
        } catch (AddressFormatException e) {
            // Success.
        }

        // Check the empty case.
        try {
            new Address(testParams, "");
            fail();
        } catch (WrongNetworkException e) {
            fail();
        } catch (AddressFormatException e) {
            // Success.
        }

        // Check the case of a mismatched network.
        try {
            new Address(testParams, "ZJoFRNuQw78Egw5ZBZ69vRWWk2bFyLy75t");
            fail();
        } catch (WrongNetworkException e) {
            // Success.
            assertEquals(e.verCode, MainNetParams.get().getAddressHeader());
            assertTrue(Arrays.equals(e.acceptableVersions, TestNet3Params.get().getAcceptableAddressCodes()));
        } catch (AddressFormatException e) {
            fail();
        }
    }
    
    @Test
    public void getNetwork() throws Exception {
        NetworkParameters params = Address.getParametersFromAddress("ZJoFRNuQw78Egw5ZBZ69vRWWk2bFyLy75t");
        assertEquals(MainNetParams.get().getId(), params.getId());
        params = Address.getParametersFromAddress("cosHPHjvW6CfJJtk5wxNoH6yfcqgNyBbfU");
        assertEquals(TestNet3Params.get().getId(), params.getId());
    }
    
    @Test
    public void p2shAddress() throws Exception {
        // Test that we can construct P2SH addresses
        Address mainNetP2SHAddress = new Address(MainNetParams.get(), "4gwZsKARr3ekip8RRaBbrNfM8QNXbFmnS1");
        assertEquals(mainNetP2SHAddress.version, MainNetParams.get().p2shHeader);
        assertTrue(mainNetP2SHAddress.isP2SHAddress());
        Address testNetP2SHAddress = new Address(TestNet3Params.get(), "2Jgnd62HREwcJ6fvXzeo3GUX1rEeL4arpzR");
        assertEquals(testNetP2SHAddress.version, TestNet3Params.get().p2shHeader);
        assertTrue(testNetP2SHAddress.isP2SHAddress());

        // Test that we can determine what network a P2SH address belongs to
        NetworkParameters mainNetParams = Address.getParametersFromAddress("4gwZsKARr3ekip8RRaBbrNfM8QNXbFmnS1");
        assertEquals(MainNetParams.get().getId(), mainNetParams.getId());
        NetworkParameters testNetParams = Address.getParametersFromAddress("2Jgnd62HREwcJ6fvXzeo3GUX1rEeL4arpzR");
        assertEquals(TestNet3Params.get().getId(), testNetParams.getId());

        // Test that we can convert them from hashes
        byte[] hex = Hex.decode("2ac4b0b501117cc8119c5797b519538d4942e90e");
        Address a = Address.fromP2SHHash(mainParams, hex);
        assertEquals("4gwZsKARr3ekip8RRaBbrNfM8QNXbFmnS1", a.toString());
        Address b = Address.fromP2SHHash(testParams, Hex.decode("18a0e827269b5211eb51a4af1b2fa69333efa722"));
        assertEquals("2Jgnd62HREwcJ6fvXzeo3GUX1rEeL4arpzR", b.toString());
        Address c = Address.fromP2SHScript(mainParams, ScriptBuilder.createP2SHOutputScript(hex));
        assertEquals("4gwZsKARr3ekip8RRaBbrNfM8QNXbFmnS1", c.toString());
    }
}
