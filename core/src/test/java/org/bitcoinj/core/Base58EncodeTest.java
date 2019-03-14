package org.bitcoinj.core;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Collection;

import static org.junit.Assert.assertEquals;
import static org.junit.runners.Parameterized.*;

@RunWith(Parameterized.class)
public class Base58EncodeTest {

    private byte[] input;
    private String expected;

    public Base58EncodeTest(byte[] input, String expected) {
        this.input = input;
        this.expected = expected;
    }

    @Parameters
    public static Collection<Object[]> parameters() {
        return Arrays.asList(new Object[][]{
                {"Hello World".getBytes(), "JxF12TrwUP45BMd"},
                {BigInteger.valueOf(3471844090L).toByteArray(), "16Ho7Hs"},
                {new byte[1], "1"},
                {new byte[7], "1111111"},
                {new byte[0], ""}
        });
    }

    @Test
    public void testEncode() {
        assertEquals(expected, Base58.encode(input));
    }
}