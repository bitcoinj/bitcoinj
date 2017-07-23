package org.bitcoinj.utils;

import static org.junit.Assert.*;

import org.junit.Test;

public class DestructionUtilsTest {

    @Test
    public void testDestroyByteArray() {
        byte[] test = new byte[5];
        
        for (int i = 0;i<test.length; i++) {
            test[i] = (byte) i;
        }
        
        DestructionUtils.destroyByteArray(test);
        
        assertEquals(90, test[0]);
        assertEquals(90, test[1]);
        assertEquals(90, test[2]);
        assertEquals(90, test[3]);
        assertEquals(90, test[4]);
    }

    @Test
    public void testDestroyByteArrayOnNull() {
        DestructionUtils.destroyByteArray(null); // may not cause a dump
    }
    
    @Test
    public void testDestroyByteArrayOnEmpty() {
        DestructionUtils.destroyByteArray(new byte[0]); // may not cause a dump
    }
}
