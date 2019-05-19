package org.bitcoinj.script;

import com.google.common.collect.ImmutableList;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Random;

import static org.bitcoinj.script.ScriptOpCodes.*;

/**
 * ScriptChunk.size() determines the size of a serialized ScriptChunk without actually performing serialization.
 * This parameterized test is meant to exhaustively prove that the method does what it promises.
 */
@RunWith(value = Parameterized.class)
public class ScriptChunkSizeTest {

    private static final Random RANDOM = new Random(42);

    @Parameterized.Parameter
    public ScriptChunk scriptChunk;

    @Parameterized.Parameters
    public static Collection<ScriptChunk> data() {
        ArrayList<ScriptChunk> opcodes = new ArrayList<>(0xff);
        for (int op = OP_NOP; op < 0xff + 1; op++) opcodes.add(new ScriptChunk(op, null));

        ArrayList<ScriptChunk> smallData = new ArrayList<>(OP_PUSHDATA1);
        for (int op = 1; op < OP_PUSHDATA1; op++) smallData.add(new ScriptChunk(op, randomBytes(op)));

        ArrayList<ScriptChunk> pushData1 = new ArrayList<>(0xff);
        for (int i = 0; i < 0xff + 1; i++) pushData1.add(new ScriptChunk(OP_PUSHDATA1, randomBytes(i)));

        ArrayList<ScriptChunk> pushData2 = new ArrayList<>((int)Script.MAX_SCRIPT_ELEMENT_SIZE + 1);
        for (int i = 0; i < Script.MAX_SCRIPT_ELEMENT_SIZE + 1; i++)
            pushData2.add(new ScriptChunk(OP_PUSHDATA2, randomBytes(i)));

        ArrayList<ScriptChunk> pushData4 = new ArrayList<>((int)Script.MAX_SCRIPT_ELEMENT_SIZE + 1);
        for (int i = 0; i < Script.MAX_SCRIPT_ELEMENT_SIZE + 1; i++)
            pushData4.add(new ScriptChunk(OP_PUSHDATA4, randomBytes(i)));

        return ImmutableList.<ScriptChunk>builder()
                .addAll(opcodes)
                .addAll(smallData)
                .addAll(pushData1)
                .addAll(pushData2)
                .addAll(pushData4)
                .build();
    }

    private static byte[] randomBytes(int size) {
        byte[] bytes = new byte[size];
        RANDOM.nextBytes(bytes);
        return bytes;
    }

    @Test
    public void testSize() {
        Assert.assertEquals(scriptChunk.toByteArray().length, scriptChunk.size());
    }
}