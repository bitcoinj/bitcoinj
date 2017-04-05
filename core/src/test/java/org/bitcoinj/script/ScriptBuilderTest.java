/*
 * Copyright 2017 Thomas König
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

import static org.junit.Assert.assertEquals;

import org.junit.Test;

public class ScriptBuilderTest {
    /**
     * Numbers greater than 16 must be encoded with PUSHDATA
     */
    @Test
    public void test() {
        ScriptBuilder scriptBuilder = new ScriptBuilder();
        scriptBuilder.number(15).number(16).number(17);

        scriptBuilder.number(0, 17).number(1, 16).number(2, 15);

        Script script = scriptBuilder.build();
        assertEquals("PUSHDATA(1)[11] 16 15 15 16 PUSHDATA(1)[11]", script.toString());
    }
}
