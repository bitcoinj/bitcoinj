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
import java.util.List;
import java.util.Random;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;

@RunWith(JUnitParamsRunner.class)
public class PartialMerkleTreeTest {
    @Test
    @Parameters(method = "randomPartialMerkleTrees")
    public void readAndWrite(PartialMerkleTree pmt) {
        ByteBuffer buf = ByteBuffer.allocate(pmt.messageSize());
        pmt.write(buf);
        assertFalse(buf.hasRemaining());
        ((Buffer) buf).rewind();
        PartialMerkleTree pmtCopy = PartialMerkleTree.read(buf);
        assertFalse(buf.hasRemaining());
        assertEquals(pmt, pmtCopy);
    }

    private Iterator<PartialMerkleTree> randomPartialMerkleTrees() {
        Random random = new Random();
        return Stream.generate(() -> {
            byte[] randomBits = new byte[random.nextInt(20)];
            random.nextBytes(randomBits);
            List<Sha256Hash> hashes = Stream.generate(() -> {
                byte[] randomHash = new byte[Sha256Hash.LENGTH];
                return Sha256Hash.wrap(randomHash);
            }).limit(random.nextInt(10)).collect(Collectors.toList());
            return new PartialMerkleTree(random.nextInt(20), hashes, randomBits);
        }).limit(10).iterator();
    }
}
