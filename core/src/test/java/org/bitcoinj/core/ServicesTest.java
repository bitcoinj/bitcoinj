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

package org.bitcoinj.core;

import junitparams.JUnitParamsRunner;
import junitparams.Parameters;
import org.bitcoinj.core.Services;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.nio.Buffer;
import java.nio.ByteBuffer;
import java.util.Iterator;
import java.util.Random;
import java.util.stream.LongStream;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

@RunWith(JUnitParamsRunner.class)
public class ServicesTest {
    @Test
    public void has() {
        Services services = Services.of(Services.NODE_BLOOM | Services.NODE_WITNESS);
        assertTrue(services.has(Services.NODE_BLOOM));
        assertTrue(services.has(Services.NODE_WITNESS));
        assertTrue(services.has(Services.NODE_BLOOM | Services.NODE_WITNESS));
        assertFalse(services.has(Services.NODE_BITCOIN_CASH));
        assertFalse(services.has(Services.NODE_BLOOM | Services.NODE_WITNESS | Services.NODE_BITCOIN_CASH));
    }

    @Test
    public void hasAny_true() {
        Services services = Services.of(Services.NODE_BLOOM);
        assertTrue(services.hasAny());
    }

    @Test
    public void hasAny_false() {
        Services services = Services.none();
        assertFalse(services.hasAny());
    }

    @Test
    @Parameters(method = "randomLongs")
    public void readAndWrite(long bits) {
        Services services = Services.of(bits);
        ByteBuffer buf = ByteBuffer.allocate(Services.BYTES);
        services.write(buf);
        assertFalse(buf.hasRemaining());
        ((Buffer) buf).rewind();
        Services servicesCopy = Services.read(buf);
        assertFalse(buf.hasRemaining());
        assertEquals(services, servicesCopy);
        assertEquals(bits, servicesCopy.bits());
    }

    private Iterator<Long> randomLongs() {
        Random random = new Random();
        return LongStream.generate(() -> random.nextLong()).limit(10).iterator();
    }
}
