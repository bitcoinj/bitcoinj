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

import org.bitcoinj.params.MainNetParams;
import org.easymock.EasyMock;
import org.junit.Before;
import org.junit.Test;

import java.io.IOException;

import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.replay;

public class CheckpointManagerTest {

    NetworkParameters params;

    @Before
    public void setUp() {
        // Use MainNetParams and only mock the behavior of getId()
        params = EasyMock.partialMockBuilder(MainNetParams.class)
                .withConstructor()
                .addMockedMethod("getId")
                .createMock();
    }

    @Test(expected = NullPointerException.class)
    public void shouldThrowNullPointerExceptionWhenCheckpointsNotFound() throws IOException {
        expect(params.getId()).andReturn("org/bitcoinj/core/checkpointmanagertest/notFound");
        replay(params);
        new CheckpointManager(params, null);
    }

    @Test(expected = IOException.class)
    public void shouldThrowNullPointerExceptionWhenCheckpointsInUnknownFormat() throws IOException {
        expect(params.getId()).andReturn("org/bitcoinj/core/checkpointmanagertest/unsupportedFormat");
        replay(params);
        new CheckpointManager(params, null);
    }

    @Test(expected = IllegalStateException.class)
    public void shouldThrowIllegalStateExceptionWithNoCheckpoints() throws IOException {
        expect(params.getId()).andReturn("org/bitcoinj/core/checkpointmanagertest/noCheckpoints");
        replay(params);
        new CheckpointManager(params, null);
    }

    @Test
    public void canReadTextualStream() throws IOException {
        expect(params.getId()).andReturn("org/bitcoinj/core/checkpointmanagertest/validTextualFormat");
        replay(params);
        new CheckpointManager(params, null);
    }
}
