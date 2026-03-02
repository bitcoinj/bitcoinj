/*
 * Copyright by the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.bitcoinj.core.internal;

import org.bouncycastle.util.encoders.Base32;
import org.bouncycastle.util.encoders.DecoderException;

import java.util.Locale;

/**
 * Base32 encoding utilities.
 * <p>
 * TODO: Remove the dependency on Bouncy Castle when possible.
 */
public class BaseUtils {

    /**
     * Encode bytes to a Base32 string (lower case, no padding).
     * Replaces: BaseEncoding.base32().omitPadding().lowerCase().encode(bytes)
     */
    public static String base32Encode(byte[] bytes) {
        String encoded = Base32.toBase32String(bytes);

        return encoded.toLowerCase(Locale.ROOT).replace("=", "");
    }

    /**
     * Decode a Base32 string to bytes.
     * Replaces: BaseEncoding.base32().omitPadding().lowerCase().decode(string)
     */
    public static byte[] base32Decode(String string) {
        String uppercasePadded = pad(string.toUpperCase(Locale.ROOT));
        try {
            return Base32.decode(uppercasePadded);
        } catch (DecoderException e) {
            throw new IllegalArgumentException("Invalid Base32 input", e);
        }
    }

    private static String pad(String string) {
        int padding = (8 - (string.length() % 8)) % 8;
        if (padding != 0) {
            StringBuilder sb = new StringBuilder(string);
            for (int i = 0; i < padding; i++) {
                sb.append('=');
            }
            string = sb.toString();
        }
        return string;
    }
}
