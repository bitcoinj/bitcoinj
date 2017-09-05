/*
 * Copyright 2017 John L. Jegutanis
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

package org.bitcoinj.script;

import com.google.common.collect.Lists;
import org.bitcoinj.core.ECKey;
import org.bitcoinj.params.MainNetParams;
import org.junit.Test;

import java.math.BigInteger;
import java.util.List;

import static org.junit.Assert.assertTrue;

public class ScriptPatternTest {
    private List<ECKey> keys = Lists.newArrayList(new ECKey(), new ECKey(), new ECKey());

    @Test
    public void testCommonScripts() {
        assertTrue(ScriptPattern.isSentToAddress(
                ScriptBuilder.createOutputScript(keys.get(0).toAddress(MainNetParams.get())).getChunks()
        ));
        assertTrue(ScriptPattern.isPayToScriptHash(
                ScriptBuilder.createP2SHOutputScript(2, keys).getChunks()
        ));
        assertTrue(ScriptPattern.isSentToMultisig(
                ScriptBuilder.createMultiSigOutputScript(2, keys).getChunks()
        ));
        assertTrue(ScriptPattern.isSentToRawPubKey(
                ScriptBuilder.createOutputScript(keys.get(0)).getChunks()
        ));
        assertTrue(ScriptPattern.isSentToCltvPaymentChannel(
                ScriptBuilder.createCLTVPaymentChannelOutput(BigInteger.ONE, keys.get(0), keys.get(1)).getChunks()
        ));
        assertTrue(ScriptPattern.isOpReturn(
                ScriptBuilder.createOpReturnScript(new byte[10]).getChunks()
        ));
    }
}
