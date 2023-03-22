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

package org.bitcoinj.base;

import org.junit.Test;

import java.nio.Buffer;
import java.nio.ByteBuffer;

import static org.junit.Assert.assertEquals;

public class Sha256HashTest {
    @Test
    public void readAndWrite() {
        Sha256Hash hash = Sha256Hash.of(new byte[32]); // hash should be pseudo-random
        ByteBuffer buf = ByteBuffer.allocate(Sha256Hash.LENGTH);
        hash.write(buf);
        ((Buffer) buf).rewind();
        Sha256Hash hashCopy = Sha256Hash.read(buf);
        assertEquals(hash, hashCopy);
    }
}
