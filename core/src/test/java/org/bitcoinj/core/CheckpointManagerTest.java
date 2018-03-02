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

import org.easymock.EasyMockRunner;
import org.easymock.Mock;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.io.IOException;

import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.replay;

@RunWith(EasyMockRunner.class)
public class CheckpointManagerTest {

    @Mock
    NetworkParameters params;

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
        expect(params.getSerializer(false)).andReturn(
                new BitcoinSerializer(params, false));
        expect(params.getProtocolVersionNum(NetworkParameters.ProtocolVersion.CURRENT))
                .andReturn(NetworkParameters.ProtocolVersion.CURRENT.getBitcoinProtocolVersion());
        replay(params);
        new CheckpointManager(params, null);
    }
}
