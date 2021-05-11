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

import static org.junit.Assert.assertEquals;

import java.io.*;

import org.bitcoinj.script.ScriptBuilder;
import org.junit.Before;
import org.junit.Test;

public class UTXOTest {

    private UTXO utxo;
    private UTXO utxoCopy;

    @Before
    public void setUp() throws IOException, ClassNotFoundException {
        ECKey key = new ECKey();
        utxo = new UTXO(Sha256Hash.of(new byte[]{1,2,3}), 1, Coin.COIN, 10, true, ScriptBuilder.createP2PKOutputScript(key));
        ByteArrayOutputStream os = new ByteArrayOutputStream();
        new ObjectOutputStream(os).writeObject(utxo);
        utxoCopy = (UTXO) new ObjectInputStream(
                new ByteArrayInputStream(os.toByteArray())).readObject();
    }

    @Test
    public void testUTXOCopy() {
        assertEquals(utxo, utxoCopy);
    }

    @Test
    public void testGetValue() {
        assertEquals(utxo.getValue(), utxoCopy.getValue());
    }

    @Test
    public void testGetScript() {
        assertEquals(utxo.getScript(), utxoCopy.getScript());
    }

    @Test
    public void testGetHash() {
        assertEquals(utxo.getHash(), utxoCopy.getHash());
    }

    @Test
    public void testGetIndex() {
        assertEquals(utxo.getIndex(), utxoCopy.getIndex());
    }

    @Test
    public void testGetHeight() {
        assertEquals(utxo.getHeight(), utxoCopy.getHeight());
    }

    @Test
    public void testIsCoinbase() {
        assertEquals(utxo.isCoinbase(), utxoCopy.isCoinbase());
    }
}
