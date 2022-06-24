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

package org.bitcoinj.utils;

/**
 * Cryptocurrency network identifier. In <b>bitcoinj</b> the only implementation of this
 * class is the {@link BitcoinNetwork} {@code enum}. This interface is provided for experimental Bitcoin networks,
 * sidechains, and implementations of Bitcoin-like alt-coins that are based on <b>bitcoinj</b>. It is recommended
 * that implementations of this interface be {@code enum}s that enumerate the available networks
 * for each environment.
 */
public interface Network {
    /**
     * Return a network id string similar to those specified in {@link BitcoinNetwork}
     *
     * @return The network id string
     */
    String id();
}