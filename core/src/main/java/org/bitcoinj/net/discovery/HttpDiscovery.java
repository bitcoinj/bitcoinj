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

import com.google.common.annotations.VisibleForTesting;
import com.google.protobuf.InvalidProtocolBufferException;
import org.bitcoin.crawler.PeerSeedProtos;
import org.bitcoinj.core.*;

import javax.annotation.Nullable;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.URI;
import java.security.SignatureException;
import java.util.Arrays;
import java.util.concurrent.TimeUnit;
import java.util.zip.GZIPInputStream;

import static com.google.common.base.Preconditions.checkArgument;

/**
 * A class that knows how to read signed sets of seeds over HTTP, using a simple protobuf based protocol. See the
 * peerseeds.proto file for the definition, with a gzipped delimited SignedPeerSeeds being the root of the data.
 * This is not currently in use by the Bitcoin community, but rather, is here for experimentation.
 */
public class HttpDiscovery implements PeerDiscovery {
    private final ECKey pubkey;
    private final URI uri;
    private final NetworkParameters params;

    /**
     * Constructs a discovery object that will read data from the given HTTP[S] URI and, if a public key is provided,
     * will check the signature using that key.
     */
    public HttpDiscovery(NetworkParameters params, URI uri, @Nullable ECKey pubkey) {
        checkArgument(uri.getScheme().startsWith("http"));
        this.uri = uri;
        this.pubkey = pubkey;
        this.params = params;
    }

    @Override
    public InetSocketAddress[] getPeers(long timeoutValue, TimeUnit timeoutUnit) throws PeerDiscoveryException {
        try {
            HttpURLConnection conn = (HttpURLConnection) uri.toURL().openConnection();
            conn.setRequestProperty("User-Agent", "bitcoinj " + VersionMessage.BITCOINJ_VERSION);
            InputStream stream = conn.getInputStream();
            GZIPInputStream zip = new GZIPInputStream(stream);
            PeerSeedProtos.SignedPeerSeeds proto = PeerSeedProtos.SignedPeerSeeds.parseDelimitedFrom(zip);
            stream.close();
            return protoToAddrs(proto);
        } catch (Exception e) {
            throw new PeerDiscoveryException(e);
        }
    }

    @VisibleForTesting
    public InetSocketAddress[] protoToAddrs(PeerSeedProtos.SignedPeerSeeds proto) throws PeerDiscoveryException, InvalidProtocolBufferException, SignatureException {
        if (pubkey != null) {
            if (!Arrays.equals(proto.getPubkey().toByteArray(), pubkey.getPubKey()))
                throw new PeerDiscoveryException("Public key mismatch");
            Sha256Hash hash = Sha256Hash.create(proto.getPeerSeeds().toByteArray());
            pubkey.verifyOrThrow(hash.getBytes(), proto.getSignature().toByteArray());
        }
        PeerSeedProtos.PeerSeeds seeds = PeerSeedProtos.PeerSeeds.parseFrom(proto.getPeerSeeds());
        if (seeds.getTimestamp() < Utils.currentTimeSeconds() - (60 * 60 * 24))
            throw new PeerDiscoveryException("Seed data is more than one day old: replay attack?");
        if (!seeds.getNet().equals(params.getPaymentProtocolId()))
            throw new PeerDiscoveryException("Network mismatch");
        InetSocketAddress[] results = new InetSocketAddress[seeds.getSeedCount()];
        int i = 0;
        for (PeerSeedProtos.PeerSeedData data : seeds.getSeedList())
            results[i++] = new InetSocketAddress(data.getIpAddress(), data.getPort());
        return results;
    }

    @Override
    public void shutdown() {
    }
}
