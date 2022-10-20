/*
 * Copyright 2011 Google Inc.
 * Copyright 2014 Andreas Schildbach
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

import org.bitcoinj.base.Coin;
import org.bitcoinj.base.Sha256Hash;
import org.bitcoinj.script.ScriptBuilder;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;

import static org.junit.Assert.assertEquals;

public class UTXOTest {

    @Test
    public void testSerialization() throws Exception {
        ECKey key = new ECKey();
        UTXO utxo = new UTXO(Sha256Hash.of(new byte[]{1,2,3}), 1, Coin.COIN, 10, true, ScriptBuilder.createP2PKOutputScript(key));
        ByteArrayOutputStream os = new ByteArrayOutputStream();
        utxo.serializeToStream(os);
        InputStream is = new ByteArrayInputStream(os.toByteArray());
        UTXO utxoCopy = UTXO.fromStream(is);
        assertEquals(utxo, utxoCopy);
        assertEquals(utxo.getValue(), utxoCopy.getValue());
        assertEquals(utxo.getHeight(), utxoCopy.getHeight());
        assertEquals(utxo.isCoinbase(), utxoCopy.isCoinbase());
        assertEquals(utxo.getScript(), utxoCopy.getScript());
    }
}
