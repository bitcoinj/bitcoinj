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
import org.junit.Test;
import org.junit.runner.RunWith;

import java.math.BigInteger;
import java.nio.Buffer;
import java.nio.ByteBuffer;
import java.time.Instant;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

@RunWith(JUnitParamsRunner.class)
public class StoredBlockTest {

    // Max chain work to fit in 12 bytes
    private static final BigInteger MAX_WORK_V1 = new BigInteger(/* 12 bytes */ "ffffffffffffffffffffffff", 16);
    // Chain work too large to fit in 12 bytes
    private static final BigInteger TOO_LARGE_WORK_V1 = new BigInteger(/* 13 bytes */ "ffffffffffffffffffffffffff", 16);
    // Max chain work to fit in 32 bytes
    private static final BigInteger MAX_WORK_V2 = new BigInteger(/* 32 bytes */
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 16);
    // Chain work too large to fit in 32 bytes
    private static final BigInteger TOO_LARGE_WORK_V2 = new BigInteger(/* 33 bytes */
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 16);
    // Just an arbitrary block
    private static final Block BLOCK = Block.createGenesis(Instant.now(), Block.EASIEST_DIFFICULTY_TARGET);

    private Object[] vectors_serializeCompact_pass() {
        return new Object[] {
                new Object[] { BigInteger.ZERO }, // no work
                new Object[] { BigInteger.ONE }, // small work
                new Object[] { BigInteger.valueOf(Long.MAX_VALUE) }, // a larg-ish work
                new Object[] { MAX_WORK_V1 },
        };
    }

    @Test
    @Parameters(method = "vectors_serializeCompact_pass")
    public void roundtripSerializeCompact_pass(BigInteger chainWork) {
        roundtripSerializeCompact(chainWork);
    }

    private Object[] vectors_serializeCompact_fail() {
        return new Object[] {
                new Object[] { TOO_LARGE_WORK_V1 },
                new Object[] { MAX_WORK_V2 },
                new Object[] { TOO_LARGE_WORK_V2 },
                new Object[] { BigInteger.valueOf(-1) }, // negative
        };
    }

    @Test(expected = RuntimeException.class)
    @Parameters(method = "vectors_serializeCompact_fail")
    public void roundtripSerializeCompact_fail(BigInteger chainWork) {
        roundtripSerializeCompact(chainWork);
    }

    private void roundtripSerializeCompact(BigInteger chainWork) {
        StoredBlock block = new StoredBlock(BLOCK, chainWork, 0);
        ByteBuffer buf = ByteBuffer.allocate(StoredBlock.COMPACT_SERIALIZED_SIZE);
        block.serializeCompact(buf);
        assertEquals(StoredBlock.COMPACT_SERIALIZED_SIZE, buf.position());
        ((Buffer) buf).rewind();
        assertEquals(StoredBlock.deserializeCompact(buf), block);
    }

    private Object[] vectors_serializeCompactV2_pass() {
        return new Object[] {
                new Object[] { BigInteger.ZERO }, // no work
                new Object[] { BigInteger.ONE }, // small work
                new Object[] { BigInteger.valueOf(Long.MAX_VALUE) }, // a larg-ish work
                new Object[] { MAX_WORK_V1 },
                new Object[] { TOO_LARGE_WORK_V1 },
                new Object[] { MAX_WORK_V2 },
        };
    }

    @Test
    @Parameters(method = "vectors_serializeCompactV2_pass")
    public void roundtripSerializeCompactV2_pass(BigInteger chainWork) {
        roundtripSerializeCompactV2(chainWork);
    }

    private Object[] vectors_serializeCompactV2_fail() {
        return new Object[] {
                new Object[] { TOO_LARGE_WORK_V2 },
                new Object[] { BigInteger.valueOf(-1) }, // negative
        };
    }

    @Test(expected = RuntimeException.class)
    @Parameters(method = "vectors_serializeCompactV2_fail")
    public void roundtripSerializeCompactV2_fail(BigInteger chainWork) {
        roundtripSerializeCompactV2(chainWork);
    }

    private void roundtripSerializeCompactV2(BigInteger chainWork) {
        StoredBlock block = new StoredBlock(BLOCK, chainWork, 0);
        ByteBuffer buf = ByteBuffer.allocate(StoredBlock.COMPACT_SERIALIZED_SIZE_V2);
        block.serializeCompactV2(buf);
        assertEquals(StoredBlock.COMPACT_SERIALIZED_SIZE_V2, buf.position());
        ((Buffer) buf).rewind();
        assertEquals(StoredBlock.deserializeCompactV2(buf), block);
    }

    @Test
    public void moreWorkThan() {
        StoredBlock noWorkBlock = new StoredBlock(BLOCK, BigInteger.ZERO, 0);
        StoredBlock smallWorkBlock = new StoredBlock(BLOCK, BigInteger.ONE, 0);
        StoredBlock maxWorkBlockV1 = new StoredBlock(BLOCK, MAX_WORK_V1, 0);
        StoredBlock maxWorkBlockV2 = new StoredBlock(BLOCK, MAX_WORK_V2, 0);

        assertTrue(smallWorkBlock.moreWorkThan(noWorkBlock));
        assertTrue(maxWorkBlockV1.moreWorkThan(noWorkBlock));
        assertTrue(maxWorkBlockV1.moreWorkThan(smallWorkBlock));
        assertTrue(maxWorkBlockV2.moreWorkThan(maxWorkBlockV1));
    }
}
