/**
 * Copyright 2014 Mike Hearn
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

package org.bitcoinj.net.discovery;

import com.google.common.collect.Lists;
import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.utils.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.*;

import static com.google.common.base.Preconditions.checkArgument;

/**
 * MultiplexingDiscovery queries multiple PeerDiscovery objects, shuffles their responses and then returns the results,
 * thus selecting randomly between them and reducing the influence of any particular seed. Any that don't respond
 * within the timeout are ignored. Backends are queried in parallel. Backends may block.
 */
public class MultiplexingDiscovery implements PeerDiscovery {
    private static final Logger log = LoggerFactory.getLogger(MultiplexingDiscovery.class);

    protected final List<PeerDiscovery> seeds;
    protected final NetworkParameters netParams;
    private volatile ExecutorService vThreadPool;

    /**
     * Will query the given seeds in parallel before producing a merged response.
     */
    public MultiplexingDiscovery(NetworkParameters params, List<PeerDiscovery> seeds) {
        checkArgument(!seeds.isEmpty());
        this.netParams = params;
        this.seeds = seeds;
    }

    @Override
    public InetSocketAddress[] getPeers(final long timeoutValue, final TimeUnit timeoutUnit) throws PeerDiscoveryException {
        vThreadPool = createExecutor();
        try {
            List<Callable<InetSocketAddress[]>> tasks = Lists.newArrayList();
            for (final PeerDiscovery seed : seeds) {
                tasks.add(new Callable<InetSocketAddress[]>() {
                    @Override
                    public InetSocketAddress[] call() throws Exception {
                        return seed.getPeers(timeoutValue,  timeoutUnit);
                    }
                });
            }
            final List<Future<InetSocketAddress[]>> futures = vThreadPool.invokeAll(tasks, timeoutValue, timeoutUnit);
            ArrayList<InetSocketAddress> addrs = Lists.newArrayList();
            for (int i = 0; i < futures.size(); i++) {
                Future<InetSocketAddress[]> future = futures.get(i);
                if (future.isCancelled()) {
                    log.warn("Seed {}: timed out", seeds.get(i));
                    continue;  // Timed out.
                }
                final InetSocketAddress[] inetAddresses;
                try {
                    inetAddresses = future.get();
                } catch (ExecutionException e) {
                    log.warn("Seed {}: failed to look up: {}", seeds.get(i), e.getMessage());
                    continue;
                }
                Collections.addAll(addrs, inetAddresses);
            }
            if (addrs.size() == 0)
                throw new PeerDiscoveryException("No peer discovery returned any results: check internet connection?");
            Collections.shuffle(addrs);
            vThreadPool.shutdownNow();
            return addrs.toArray(new InetSocketAddress[addrs.size()]);
        } catch (InterruptedException e) {
            throw new PeerDiscoveryException(e);
        } finally {
            vThreadPool.shutdown();
        }
    }

    protected ExecutorService createExecutor() {
        return Executors.newFixedThreadPool(seeds.size(), new ContextPropagatingThreadFactory("Multiplexing discovery"));
    }

    @Override
    public void shutdown() {
        ExecutorService tp = vThreadPool;
        if (tp != null)
            tp.shutdown();
    }
}
