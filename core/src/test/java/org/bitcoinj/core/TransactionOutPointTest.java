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
import org.bitcoinj.base.Sha256Hash;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.nio.Buffer;
import java.nio.ByteBuffer;
import java.util.Iterator;
import java.util.Random;
import java.util.stream.Stream;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;

@RunWith(JUnitParamsRunner.class)
public class TransactionOutPointTest {
    @Test
    @Parameters(method = "randomOutPoints")
    public void readAndWrite(TransactionOutPoint outpoint) {
        ByteBuffer buf = ByteBuffer.allocate(TransactionOutPoint.BYTES);
        outpoint.write(buf);
        assertFalse(buf.hasRemaining());
        ((Buffer) buf).rewind();
        TransactionOutPoint outpointCopy = TransactionOutPoint.read(buf);
        assertFalse(buf.hasRemaining());
        assertEquals(outpoint, outpointCopy);
    }

    private Iterator<TransactionOutPoint> randomOutPoints() {
        Random random = new Random();
        return Stream.generate(() -> {
            byte[] randomBytes = new byte[Sha256Hash.LENGTH];
            random.nextBytes(randomBytes);
            return new TransactionOutPoint(Integer.toUnsignedLong(random.nextInt()), Sha256Hash.wrap(randomBytes));
        }).limit(10).iterator();
    }

    @Test
    public void deprecatedMembers() {
        TransactionOutPoint outpoint = TransactionOutPoint.UNCONNECTED;
        outpoint.getHash();
        outpoint.getMessageSize();
        outpoint.getIndex();
        outpoint.bitcoinSerialize();
    }
}
