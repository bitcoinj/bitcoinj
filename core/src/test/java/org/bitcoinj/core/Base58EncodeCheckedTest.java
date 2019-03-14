package org.bitcoinj.core;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

import java.util.Arrays;
import java.util.Collection;

import static org.junit.Assert.assertEquals;

@RunWith(Parameterized.class)
public class Base58EncodeCheckedTest {

    private int version;
    private byte[] input;
    private String expected;

    @Parameters
    public static Collection<Object[]> parameters() {
        return Arrays.asList(new Object[][]{
                {111, new byte[LegacyAddress.LENGTH], "mfWxJ45yp2SFn7UciZyNpvDKrzbhyfKrY8"},
                {128, new byte[32], "5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAbuatmU"}
        });
    }

    public Base58EncodeCheckedTest(int version, byte[] input, String expected) {
        this.version = version;
        this.input = input;
        this.expected = expected;
    }

    @Test
    public void testEncode() {
        assertEquals(expected, Base58.encodeChecked(version, input));
    }
}