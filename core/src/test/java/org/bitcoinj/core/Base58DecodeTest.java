package org.bitcoinj.core;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import java.util.Arrays;
import java.util.Collection;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.runners.Parameterized.Parameters;

@RunWith(Parameterized.class)
public class Base58DecodeTest {

    private String input;
    private byte[] expected;

    public Base58DecodeTest(String input, byte[] expected) {
        this.input = input;
        this.expected = expected;
    }

    @Parameters
    public static Collection<Object[]> parameters() {
        return Arrays.asList(new Object[][]{
                {"JxF12TrwUP45BMd", "Hello World".getBytes()},
                {"1", new byte[1]},
                {"1111", new byte[4]}
        });
    }

    @Test
    public void testDecode() {
        byte[] actualBytes = Base58.decode(input);
        assertArrayEquals(input,  actualBytes, expected);
    }

    @Test
    public void testDecode_emptyString() {
        assertEquals(0, Base58.decode("").length);
    }

    @Test(expected = AddressFormatException.class)
    public void testDecode_invalidBase58() {
        Base58.decode("This isn't valid base58");
    }

}