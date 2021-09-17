/*
 * Copyright 2014 Mike Hearn
 * Copyright 2015 Andreas Schildbach
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

import com.google.common.annotations.*;
import com.google.protobuf.*;
import org.bitcoin.crawler.*;
import org.bitcoinj.core.*;
import org.slf4j.*;

import javax.annotation.*;
import java.io.*;
import java.net.*;
import java.security.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.zip.*;

import okhttp3.HttpUrl;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

import static com.google.common.base.Preconditions.*;

/**
 * A class that knows how to read signed sets of seeds over HTTP, using a simple protobuf based protocol. See the
 * peerseeds.proto file for the definition, with a gzipped delimited SignedPeerSeeds being the root of the data.
 * This is not currently in use by the Bitcoin community, but rather, is here for experimentation.
 */
public class HttpDiscovery implements PeerDiscovery {
    private static final Logger log = LoggerFactory.getLogger(HttpDiscovery.class);

    public static class Details {
        @Nullable public final ECKey pubkey;
        public final URI uri;

        public Details(@Nullable ECKey pubkey, URI uri) {
            this.pubkey = pubkey;
            this.uri = uri;
        }
    }

    public interface HttpDiscoveryClient {
        InputStream getPeers(URI uri, long services, long timeoutValue, TimeUnit timeoutUnit) throws PeerDiscoveryException;
    }

    private static class OkHttpDiscoveryClient implements HttpDiscoveryClient {
        private final OkHttpClient client;

        public OkHttpDiscoveryClient() {
            this(new OkHttpClient());
        }

        public OkHttpDiscoveryClient(OkHttpClient okHttpClient) {
            client = okHttpClient;
        }

        public InputStream getPeers(URI uri, long services, long timeoutValue, TimeUnit timeoutUnit) throws PeerDiscoveryException {
            HttpUrl.Builder url = HttpUrl.get(uri).newBuilder();
            if (services != 0)
                url.addQueryParameter("srvmask", Long.toString(services));
            Request.Builder request = new Request.Builder();
            request.url(url.build());
            request.addHeader("User-Agent", VersionMessage.LIBRARY_SUBVER); // TODO Add main version.
            log.info("Requesting {} peers from {}", services != 0 ? VersionMessage.toStringServices(services) :
                    "all", url);
            Response response = null;
            try {
                response = client.newCall(request.build()).execute();
            } catch (IOException e) {
                throw new PeerDiscoveryException(e);
            }
            if (!response.isSuccessful())
                throw new PeerDiscoveryException("HTTP request failed: " + response.code() + " " + response.message());
            return response.body().byteStream();
        }
    }

    private final Details details;
    private final NetworkParameters params;
    private final HttpDiscoveryClient client;

    /**
     * Constructs a discovery object that will read data from the given HTTP[S] URI and, if a public key is provided,
     * will check the signature using that key.
     */
    public HttpDiscovery(NetworkParameters params, URI uri, @Nullable ECKey pubkey) {
        this(params, new Details(pubkey, uri));
    }

    /**
     * Constructs a discovery object that will read data from the given HTTP[S] URI and, if a public key is provided,
     * will check the signature using that key.
     */
    public HttpDiscovery(NetworkParameters params, Details details) {
        this(params, details, new OkHttpDiscoveryClient());
    }

    public HttpDiscovery(NetworkParameters params, Details details,  HttpDiscoveryClient httpDiscoveryClient) {
        checkArgument(details.uri.getScheme().startsWith("http"));
        this.details = details;
        this.params = params;
        this.client = httpDiscoveryClient;
    }

    @Deprecated
    public HttpDiscovery(NetworkParameters params, Details details,  OkHttpClient okHttpClient) {
        checkArgument(details.uri.getScheme().startsWith("http"));
        this.details = details;
        this.params = params;
        this.client = new OkHttpDiscoveryClient(okHttpClient);
    }

    public static HttpDiscoveryClient newDefaultClient() {
        return new OkHttpDiscoveryClient();
    }

    @Override
    public List<InetSocketAddress> getPeers(long services, long timeoutValue, TimeUnit timeoutUnit) throws PeerDiscoveryException {
        try {
            InputStream stream = client.getPeers(details.uri, services, timeoutValue, timeoutUnit);
            GZIPInputStream zip = new GZIPInputStream(stream);
            PeerSeedProtos.SignedPeerSeeds proto;
            try {
                proto = PeerSeedProtos.SignedPeerSeeds.parseDelimitedFrom(zip);
            } finally {
                zip.close(); // will close InputStream as well
            }

            final List<InetSocketAddress> peers = protoToAddrs(proto);
            log.info("Got {} peers from {}", peers.size(), details.uri);
            return peers;
        } catch (IOException | SignatureDecodeException | SignatureException e) {
            throw new PeerDiscoveryException(e);
        }
    }

    @VisibleForTesting
    public List<InetSocketAddress> protoToAddrs(PeerSeedProtos.SignedPeerSeeds proto) throws PeerDiscoveryException,
            InvalidProtocolBufferException, SignatureDecodeException, SignatureException {
        if (details.pubkey != null) {
            if (!Arrays.equals(proto.getPubkey().toByteArray(), details.pubkey.getPubKey()))
                throw new PeerDiscoveryException("Public key mismatch");
            byte[] hash = Sha256Hash.hash(proto.getPeerSeeds().toByteArray());
            details.pubkey.verifyOrThrow(hash, proto.getSignature().toByteArray());
        }
        PeerSeedProtos.PeerSeeds seeds = PeerSeedProtos.PeerSeeds.parseFrom(proto.getPeerSeeds());
        if (seeds.getTimestamp() < Utils.currentTimeSeconds() - (60 * 60 * 24))
            throw new PeerDiscoveryException("Seed data is more than one day old: replay attack?");
        if (!seeds.getNet().equals(params.getPaymentProtocolId()))
            throw new PeerDiscoveryException("Network mismatch");
        List<InetSocketAddress> results = new ArrayList<>(seeds.getSeedCount());
        for (PeerSeedProtos.PeerSeedData data : seeds.getSeedList())
            results.add(new InetSocketAddress(data.getIpAddress(), data.getPort()));
        return results;
    }

    @Override
    public void shutdown() {
    }
}
