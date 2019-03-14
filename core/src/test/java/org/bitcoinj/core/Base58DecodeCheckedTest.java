package org.bitcoinj.core;

import org.junit.Assume;
import org.junit.Rule;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;

@RunWith(Theories.class)
public class Base58DecodeCheckedTest {

    @Rule
    public ExpectedException expectedException = ExpectedException.none();

    private static final String BASE58_ALPHABET = "123456789abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ";
    private boolean containsOnlyValidBase58Chars(String input) {
        for(String s : input.split("")) {
            if (!BASE58_ALPHABET.contains(s)) {
                return false;
            }
        }
        return true;
    }

    @DataPoints
    public static String[] parameters = new String[]{
            "4stwEBjT6FYyVV",
            "93VYUMzRG9DdbRP72uQXjaWibbQwygnvaCu9DumcqDjGybD864T",
            "J0F12TrwUP45BMd",
            "4s"
    };

    @Theory
    public void testDecodeChecked(String input) {
        Assume.assumeTrue(containsOnlyValidBase58Chars(input));
        Assume.assumeTrue(input.length() > 4);
        Base58.decodeChecked(input);
    }

    @Theory
    public void decode_invalidCharacter_notInAlphabet(String input) {
        Assume.assumeFalse(containsOnlyValidBase58Chars(input));
        Assume.assumeTrue(input.length() > 4);
        expectedException.expect(AddressFormatException.InvalidCharacter.class);
        Base58.decodeChecked(input);
    }

    @Theory
    public void testDecodeChecked_shortInput(String input) {
        Assume.assumeTrue(containsOnlyValidBase58Chars(input));
        Assume.assumeTrue(input.length() < 4);
        expectedException.expect(AddressFormatException.InvalidDataLength.class);
        Base58.decodeChecked(input);
    }
}