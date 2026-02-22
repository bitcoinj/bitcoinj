/*
 * Copyright by the original author or authors.
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

package org.bitcoinj.crypto;

import org.bitcoinj.base.internal.ByteArray;

import javax.crypto.SecretKey;
import java.util.Arrays;

/**
 * Wrapper for a {@code byte[]} containing an AES Key.
 */
public class AesKey extends ByteArray implements SecretKey {
    private boolean destroyed = false;
    /**
     * Wrapper for a {@code byte[]} containing an AES Key
     * @param keyBytes implementation-dependent AES Key bytes
     */
    public AesKey(byte[] keyBytes) {
        super(keyBytes);
    }

    @Override
    public byte[] bytes() {
        if (destroyed) throw new IllegalStateException("Key has been destroyed");
        return super.bytes();
    }

    @Override
    public String getAlgorithm() {
        return "AES";
    }

    @Override
    public String getFormat() {
        return "RAW";
    }

    @Override
    public byte[] getEncoded() {
        return bytes();
    }

    @Override
    public void destroy() {
        Arrays.fill(bytes, (byte) 0);
        destroyed = true;
    }

    @Override
    public boolean isDestroyed() {
        return destroyed;
    }
}
