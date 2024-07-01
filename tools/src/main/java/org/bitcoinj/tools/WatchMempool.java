/*
 * Copyright 2013 Google Inc.
 * Copyright 2014 Andreas Schildbach
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

package org.bitcoinj.tools;

import org.bitcoinj.base.BitcoinNetwork;
import org.bitcoinj.base.Network;
import org.bitcoinj.base.internal.TimeUtils;
import org.bitcoinj.core.PeerGroup;
import org.bitcoinj.core.Transaction;
import org.bitcoinj.net.discovery.DnsDiscovery;
import org.bitcoinj.utils.BriefLogFormatter;
import org.bitcoinj.wallet.DefaultRiskAnalysis;
import org.bitcoinj.wallet.RiskAnalysis.Result;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.time.Instant;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class WatchMempool {
    private static final Logger log = LoggerFactory.getLogger(WatchMempool.class);
    private static final Network NETWORK = BitcoinNetwork.MAINNET;
    private static final List<Transaction> NO_DEPS = Collections.emptyList();
    private static final Map<String, Integer> counters = new HashMap<>();
    private static final String TOTAL_KEY = "TOTAL";
    private static final Instant START = TimeUtils.currentTime();
    private static final Duration STATISTICS_FREQUENCY = Duration.ofSeconds(5);

    public static void main(String[] args) throws InterruptedException {
        BriefLogFormatter.init();
        PeerGroup peerGroup = new PeerGroup(NETWORK);
        peerGroup.setMaxConnections(32);
        peerGroup.addPeerDiscovery(new DnsDiscovery(NETWORK));
        peerGroup.addOnTransactionBroadcastListener((peer, tx) -> {
            Result result = DefaultRiskAnalysis.FACTORY.create(null, tx, NO_DEPS).analyze();
            incrementCounter(TOTAL_KEY);
            log.info("tx {} result {}", tx.getTxId(), result);
            incrementCounter(result.name());
            if (result == Result.NON_STANDARD)
                incrementCounter(Result.NON_STANDARD + "-" + DefaultRiskAnalysis.isStandard(tx));
        });
        peerGroup.start();

        while (true) {
            Thread.sleep(STATISTICS_FREQUENCY.toMillis());
            printCounters();
        }
    }

    private static synchronized void incrementCounter(String name) {
        Integer count = counters.get(name);
        if (count == null)
            count = 0;
        count++;
        counters.put(name, count);
    }

    private static synchronized void printCounters() {
        Duration elapsed = TimeUtils.elapsedTime(START);
        System.out.printf("Runtime: %d:%02d minutes\n", elapsed.toMinutes(), elapsed.toSecondsPart());
        Integer total = counters.get(TOTAL_KEY);
        if (total == null)
            return;
        for (Map.Entry<String, Integer> counter : counters.entrySet()) {
            System.out.printf("  %-40s%6d  (%d%% of total)\n", counter.getKey(), counter.getValue(),
                    (int) counter.getValue() * 100 / total);
        }
    }
}
