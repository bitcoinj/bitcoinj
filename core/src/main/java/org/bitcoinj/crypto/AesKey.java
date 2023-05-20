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
import org.bouncycastle.crypto.params.KeyParameter;

/**
 *  Wrapper for a {@code byte[]}  containing an AES Key. This is a replacement for Bouncy Castle's {@link KeyParameter} which
 *  was used for this purpose in previous versions of <b>bitcoinj</b>. Unfortunately, this created a Gradle _API_ dependency
 *  on Bouncy Castle when that wasn't strictly necessary.
 *  <p>
 *  We have made this change without deprecation because it affected many method signatures and because updating is a trivial change.
 *  If for some reason you have code that uses the Bouncy Castle {@link KeyParameter} type and need to convert
 *  to or from {@code AesKey}, you can temporarily use {@link #ofKeyParameter(KeyParameter)} or {@link #toKeyParameter()}
 */
public class AesKey extends ByteArray {
    /**
     * Wrapper for a {@code byte[]} containing an AES Key
     * @param keyBytes implementation-dependent AES Key bytes
     */
    public AesKey(byte[] keyBytes) {
        super(keyBytes);
    }

    /**
     * Provided to ease migration from {@link KeyParameter}.
     * @return The key bytes
     * @deprecated Use {@link #bytes()}
     */
    @Deprecated
    public byte[] getKey() {
        return bytes();
    }

    /**
     * Provided to ease migration from {@link KeyParameter}.
     * @param keyParameter instance to convert
     * @return new, preferred container for AES keys
     * @deprecated Use {@code new AesKey(keyParameter.bytes())}
     */
    @Deprecated
    public static AesKey ofKeyParameter(KeyParameter keyParameter) {
        return new AesKey(keyParameter.getKey());
    }

    /**
     * Provided to ease migration from {@link KeyParameter}.
     * @return  if for some reason you still need (temporarily, we hope) a {@link KeyParameter}
     * @deprecated Use {@code new KeyParameter(key.bytes)}
     */
    @Deprecated
    public KeyParameter toKeyParameter() {
        return new KeyParameter(this.bytes());
    }
}
