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
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.DecoderException;

import java.util.Locale;

/**
 * Base32 and Base64 encoding utilities to replace Guava's BaseEncoding.
 */
public final class BaseUtils {

    /**
     * Encode bytes to a Base32 string (lower case, no padding).
     * Replaces: BaseEncoding.base32().omitPadding().lowerCase().encode(bytes)
     */
    public static String base32Encode(byte[] bytes) {
        // Bouncy Castle returns standard RFC 4648 (Upper case, with padding)
        String encoded = Base32.toBase32String(bytes);
        
        return encoded.toLowerCase(Locale.ROOT).replace("=", "");
    }

    /**
     * Decode a Base32 string to bytes.
     * Replaces: BaseEncoding.base32().omitPadding().lowerCase().decode(string)
     */
    public static byte[] base32Decode(String string) {
        try {
            int missing = (8 - (string.length() % 8)) % 8;
            if (missing > 0) {
                StringBuilder sb = new StringBuilder(string.length() + missing);
                sb.append(string);
                for (int i = 0; i < missing; i++) {
                    sb.append('=');
                }
                string = sb.toString();
            }
            
            return Base32.decode(string.toUpperCase(Locale.ROOT));
        } catch (DecoderException e) {
            
            throw new IllegalArgumentException("Invalid Base32 input", e);
        }
    }

    /**
     * Encode bytes to a Base64 string (no padding).
     * Replaces: BaseEncoding.base64().omitPadding().encode(bytes)
     */
    public static String base64Encode(byte[] bytes) {
        String encoded = Base64.toBase64String(bytes);
        
        return encoded.replace("=", "");
    }

    /**
     * Decode a Base64 string to bytes.
     * Replaces: BaseEncoding.base64().omitPadding().decode(string)
     */
    public static byte[] base64Decode(String string) {
        try {
            int missing = (4 - (string.length() % 4)) % 4;
            if (missing > 0) {
                StringBuilder sb = new StringBuilder(string.length() + missing);
                sb.append(string);
                for (int i = 0; i < missing; i++) {
                    sb.append('=');
                }
                string = sb.toString();
            }
            return Base64.decode(string);
        } catch (DecoderException e) {
            throw new IllegalArgumentException("Invalid Base64 input", e);
        }
    }
}
