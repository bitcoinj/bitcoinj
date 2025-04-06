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

/**
 *  Wrapper for a {@code byte[]}  containing an AES Key. This is a replacement for Bouncy Castle's {@code KeyParameter} which
 *  was used for this purpose in previous versions of <b>bitcoinj</b>. Unfortunately, this created a Gradle _API_ dependency
 *  on Bouncy Castle when that wasn't strictly necessary.
 *  <p>
 *  We have made this change without deprecation because it affected many method signatures and because updating is a trivial change.
 */
public class AesKey extends ByteArray {
    /**
     * Wrapper for a {@code byte[]} containing an AES Key
     * @param keyBytes implementation-dependent AES Key bytes
     */
    public AesKey(byte[] keyBytes) {
        super(keyBytes);
    }
}
