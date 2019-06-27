/*
 * Copyright 2019 Tim Strasser
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

package org.bitcoinj.core.listeners;

import org.bitcoinj.core.Block;
import org.bitcoinj.core.FilteredBlock;
import org.bitcoinj.core.Peer;
import org.easymock.EasyMock;
import org.easymock.EasyMockRunner;
import org.easymock.Mock;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import static junit.framework.TestCase.fail;

@RunWith(EasyMockRunner.class)
public class DownloadProgressTrackerTest {

    @Mock
    private Peer peer;

    @Mock
    private Block block;

    @Mock
    FilteredBlock filteredBlock;

    @Test
    public void testOnChainDownloadStarted() throws ExecutionException, InterruptedException {
        EasyMock.expect(peer.getBestHeight()).andReturn(4l).times(1);
        EasyMock.replay(peer);
        DownloadProgressTracker downloadProgressTracker = new DownloadProgressTracker();
        downloadProgressTracker.onChainDownloadStarted(peer, 4);
        try {
            Assert.assertEquals(null, downloadProgressTracker.getFuture().get(1, TimeUnit.MILLISECONDS));
            fail();
        } catch (TimeoutException e) {
        }
        downloadProgressTracker.onChainDownloadStarted(peer, 0);
        Assert.assertEquals(4, (long) downloadProgressTracker.getFuture().get());
    }

    @Test
    public void testOnBlocksDownloaded() throws ExecutionException, InterruptedException {
        DownloadProgressTracker downloadProgressTracker = new DownloadProgressTracker();
        downloadProgressTracker.onBlocksDownloaded(peer, block, filteredBlock, 4);
        try {
            Assert.assertEquals(null, downloadProgressTracker.getFuture().get(1, TimeUnit.MILLISECONDS));
            fail();
        } catch (TimeoutException e) {
        }
        EasyMock.expect(block.getTimeSeconds()).andReturn(2l);
        EasyMock.expect(peer.getBestHeight()).andReturn(10l);
        EasyMock.replay(block);
        EasyMock.replay(peer);
        downloadProgressTracker.onBlocksDownloaded(peer, block, filteredBlock, 0);
        Assert.assertEquals(10, (long) downloadProgressTracker.getFuture().get());
    }
}
