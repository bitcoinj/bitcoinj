/*
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

package org.bitcoinj.script;

import static org.bitcoinj.script.ScriptOpCodes.OP_0;
import static org.bitcoinj.script.ScriptOpCodes.OP_IF;
import static org.bitcoinj.script.ScriptOpCodes.OP_PUSHDATA1;
import static org.bitcoinj.script.ScriptOpCodes.OP_PUSHDATA2;
import static org.bitcoinj.script.ScriptOpCodes.OP_PUSHDATA4;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.Random;

import nl.jqno.equalsverifier.EqualsVerifier;
import org.junit.Test;

import com.google.common.primitives.Bytes;

public class ScriptChunkTest {

    private static final Random RANDOM = new Random(42);

    @Test
    public void equalsContract() {
        EqualsVerifier.forClass(ScriptChunk.class)
                .usingGetClass()
                .verify();
    }

    @Test
    public void testToStringOnInvalidScriptChunk() {
        // see https://github.com/bitcoinj/bitcoinj/issues/1860
        // In summary: toString() throws when given an invalid ScriptChunk.
        // It should perhaps be impossible to even construct such a ScriptChunk, but
        // until that is the case, toString() should not throw.
        ScriptChunk pushWithoutData = new ScriptChunk(OP_PUSHDATA1, null);

        // the chunk is invalid, but at least we can determine its opcode
        assertEquals("PUSHDATA1", pushWithoutData.toString());
    }

    @Test
    public void testShortestPossibleDataPush() {
        assertTrue("empty push", new ScriptBuilder().data(new byte[0]).build().getChunks().get(0)
                .isShortestPossiblePushData());

        for (byte i = -1; i < 127; i++)
            assertTrue("push of single byte " + i, new ScriptBuilder().data(new byte[] { i }).build().getChunks()
                    .get(0).isShortestPossiblePushData());

        for (int len = 2; len < Script.MAX_SCRIPT_ELEMENT_SIZE; len++)
            assertTrue("push of " + len + " bytes", new ScriptBuilder().data(new byte[len]).build().getChunks().get(0)
                    .isShortestPossiblePushData());

        // non-standard chunks
        for (byte i = 1; i <= 16; i++)
            assertFalse("push of smallnum " + i, new ScriptChunk(1, new byte[] { i }).isShortestPossiblePushData());
        assertFalse("push of 75 bytes", new ScriptChunk(OP_PUSHDATA1, new byte[75]).isShortestPossiblePushData());
        assertFalse("push of 255 bytes", new ScriptChunk(OP_PUSHDATA2, new byte[255]).isShortestPossiblePushData());
        assertFalse("push of 65535 bytes", new ScriptChunk(OP_PUSHDATA4, new byte[65535]).isShortestPossiblePushData());
    }

    @Test
    public void testToByteArray_opcode() {
        byte[] expected = new byte[] { OP_IF };
        byte[] actual = new ScriptChunk(OP_IF, null).toByteArray();
        assertArrayEquals(expected, actual);
    }

    @Test
    public void testToByteArray_smallNum() {
        byte[] expected = new byte[] { OP_0 };
        byte[] actual = new ScriptChunk(OP_0, null).toByteArray();
        assertArrayEquals(expected, actual);
    }

    @Test
    public void testToByteArray_lt_OP_PUSHDATA1() {
        // < OP_PUSHDATA1
        for (byte len = 1; len < OP_PUSHDATA1; len++) {
            byte[] bytes = new byte[len];
            RANDOM.nextBytes(bytes);
            byte[] expected = Bytes.concat(new byte[] { len }, bytes);
            byte[] actual = new ScriptChunk(len, bytes).toByteArray();
            assertArrayEquals(expected, actual);
        }
    }

    @Test
    public void testToByteArray_OP_PUSHDATA1() {
        // OP_PUSHDATA1
        byte[] bytes = new byte[0xFF];
        RANDOM.nextBytes(bytes);
        byte[] expected = Bytes.concat(new byte[] { OP_PUSHDATA1, (byte) 0xFF }, bytes);
        byte[] actual = new ScriptChunk(OP_PUSHDATA1, bytes).toByteArray();
        assertArrayEquals(expected, actual);
    }

    @Test
    public void testToByteArray_OP_PUSHDATA2() {
        // OP_PUSHDATA2
        byte[] bytes = new byte[0x0102];
        RANDOM.nextBytes(bytes);
        byte[] expected = Bytes.concat(new byte[] { OP_PUSHDATA2, 0x02, 0x01 }, bytes);
        byte[] actual = new ScriptChunk(OP_PUSHDATA2, bytes).toByteArray();
        assertArrayEquals(expected, actual);
    }

    @Test
    public void testToByteArray_OP_PUSHDATA4() {
        // OP_PUSHDATA4
        byte[] bytes = new byte[0x0102];
        RANDOM.nextBytes(bytes);
        byte[] expected = Bytes.concat(new byte[] { OP_PUSHDATA4, 0x02, 0x01, 0x00, 0x00 }, bytes);
        byte[] actual = new ScriptChunk(OP_PUSHDATA4, bytes).toByteArray();
        assertArrayEquals(expected, actual);
    }
}
