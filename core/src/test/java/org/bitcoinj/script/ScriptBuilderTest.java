/*
 * Copyright 2018 Nicola Atzei
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

import static org.bitcoinj.script.ScriptOpCodes.OP_FALSE;
import static org.bitcoinj.script.ScriptOpCodes.OP_TRUE;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

public class ScriptBuilderTest {

    @Test
    public void testNumber() {
        for (int i = -100; i <= 100; i++) {
            Script s = new ScriptBuilder().number(i).build();
            for (ScriptChunk ch : s.chunks) {
                assertTrue(Integer.toString(i), ch.isShortestPossiblePushData());
            }
        }
    }

    @Test
    public void numberBuilderZero() {
        // Test encoding of zero, which should result in an opcode
        final ScriptBuilder builder = new ScriptBuilder();

        // 0 should encode directly to 0
        builder.number(0);
        assertArrayEquals(new byte[] {
            0x00         // Pushed data
        }, builder.build().getProgram());
    }

    @Test
    public void numberBuilderPositiveOpCode() {
        final ScriptBuilder builder = new ScriptBuilder();

        builder.number(5);
        assertArrayEquals(new byte[] {
            0x55         // Pushed data
        }, builder.build().getProgram());
    }

    @Test
    public void numberBuilderBigNum() {
        ScriptBuilder builder = new ScriptBuilder();
        // 21066 should take up three bytes including the length byte
        // at the start

        builder.number(0x524a);
        assertArrayEquals(new byte[] {
            0x02,             // Length of the pushed data
            0x4a, 0x52        // Pushed data
        }, builder.build().getProgram());

        // Test the trimming code ignores zeroes in the middle
        builder = new ScriptBuilder();
        builder.number(0x110011);
        assertEquals(4, builder.build().getProgram().length);

        // Check encoding of a value where signed/unsigned encoding differs
        // because the most significant byte is 0x80, and therefore a
        // sign byte has to be added to the end for the signed encoding.
        builder = new ScriptBuilder();
        builder.number(0x8000);
        assertArrayEquals(new byte[] {
            0x03,             // Length of the pushed data
            0x00, (byte) 0x80, 0x00  // Pushed data
        }, builder.build().getProgram());
    }

    @Test
    public void numberBuilderNegative() {
        // Check encoding of a negative value
        final ScriptBuilder builder = new ScriptBuilder();
        builder.number(-5);
        assertArrayEquals(new byte[] {
            0x01,        // Length of the pushed data
            ((byte) 133) // Pushed data
        }, builder.build().getProgram());
    }

    @Test
    public void numberBuilder16() {
        ScriptBuilder builder = new ScriptBuilder();
        // Numbers greater than 16 must be encoded with PUSHDATA
        builder.number(15).number(16).number(17);
        builder.number(0, 17).number(1, 16).number(2, 15);
        Script script = builder.build();
        assertEquals("PUSHDATA(1)[11] 16 15 15 16 PUSHDATA(1)[11]", script.toString());
    }

    @Test
    public void testOpTrue() {
        byte[] expected = new byte[] { OP_TRUE };
        byte[] s = new ScriptBuilder().opTrue().build().getProgram();
        assertArrayEquals(expected, s);
    }

    @Test
    public void testOpFalse() {
        byte[] expected = new byte[] { OP_FALSE };
        byte[] s = new ScriptBuilder().opFalse().build().getProgram();
        assertArrayEquals(expected, s);
    }
}
