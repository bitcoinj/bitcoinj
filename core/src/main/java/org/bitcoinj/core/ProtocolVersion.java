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

/**
 * Define important versions of the Bitcoin Protocol
 */
public enum ProtocolVersion {
    MINIMUM(70000),
    @Deprecated
    PONG(60001),
    BLOOM_FILTER(70001), // BIP37
    BLOOM_FILTER_BIP111(70011), // BIP111
    WITNESS_VERSION(70012),
    FEEFILTER(70013), // BIP133
    CURRENT(70013);

    private final int bitcoinProtocol;

    ProtocolVersion(final int bitcoinProtocol) {
        this.bitcoinProtocol = bitcoinProtocol;
    }

    /**
     * @return protocol version as an integer value
     */
    public int intValue() {
        return bitcoinProtocol;
    }

    /**
     * @deprecated Use {@link #intValue()}
     */
    @Deprecated
    public int getBitcoinProtocolVersion() {
        return intValue();
    }
}
