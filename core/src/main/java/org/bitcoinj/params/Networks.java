/*
 * Copyright 2014 Giannis Dzegoutanis
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

package org.bitcoinj.params;

import org.bitcoinj.core.NetworkParameters;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

/**
 * Utility class that holds all the registered {@link NetworkParameters} types used for address auto discovery.
 * By default only {@link MainNetParams} and {@link TestNet3Params} are used. If you want to use {@link RegTestParams}
 * or {@link UnitTestParams} use {@code register} and then {@code unregister} the {@code TestNet3Params} as they don't
 * have their own Base58 version/type code (although for {@link org.bitcoinj.core.SegwitAddress} the human readable
 * parts for RegTest and TestNet are different.)
 */
public class Networks {
    /** Registered networks */
    private static Set<NetworkParameters> networks = unmodifiableSet(TestNet3Params.get(), MainNetParams.get());

    public static Set<NetworkParameters> get() {
        return networks;
    }

    /**
     * Register a single network type by adding it to the {@code Set}.
     *
     * @param network Network to register/add.
     */
    public static void register(NetworkParameters network) {
        register(Collections.singleton(network));
    }

    /**
     * Register a collection of additional network types by adding them
     * to the {@code Set}.
     *
     * @param networks Networks to register/add.
     */
    public static void register(Collection<NetworkParameters> networks) {
        Networks.networks = combinedSet(Networks.networks, networks);
    }

    /**
     * Unregister a network type.
     *
     * @param network Network type to unregister/remove.
     */
    public static void unregister(NetworkParameters network) {
        Networks.networks = removeFromSet(networks, network);
    }

    // Create an unmodifiable set of NetworkParameters from an array/varargs
    private static Set<NetworkParameters> unmodifiableSet(NetworkParameters... ts) {
        return Collections.unmodifiableSet(new HashSet<>(Arrays.asList(ts)));
    }

    // Create an unmodifiable set by combining two collections
    private static <T> Set<T> combinedSet(Collection<T> a, Collection<T> b) {
        Set<T> tempSet = new HashSet<>(a);
        tempSet.addAll(b);
        return Collections.unmodifiableSet(tempSet);
    }

    // Create a new unmodifiable set by removing an item from an existing set
    private static <T> Set<T> removeFromSet(Set<T> set, T item) {
        Set<T> tempSet = new HashSet<>(set);
        tempSet.remove(item);
        return Collections.unmodifiableSet(tempSet);
    }
}
