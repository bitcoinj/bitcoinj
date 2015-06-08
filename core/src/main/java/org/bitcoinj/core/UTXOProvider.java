/**
 * Copyright 2014 Kalpesh Parmar.
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

import java.util.List;

/**
 * A UTXOProvider encapsulates functionality for returning unspent transaction outputs,
 * for use by the wallet or other code that crafts spends.
 *
 * <p>A {@link org.bitcoinj.store.FullPrunedBlockStore} is an internal implementation within bitcoinj.</p>
 */
public interface UTXOProvider {

    /**
     * // TODO currently the access to outputs is by address. Change to ECKey
     * Get the list of {@link UTXO}'s for a given address.
     * @param addresses List of address.
     * @return The list of transaction outputs.
     * @throws UTXOProvider If there is an error.
     */
    List<UTXO> getOpenTransactionOutputs(List<Address> addresses) throws UTXOProviderException;

    /**
     * Get the height of the chain head.
     * @return The chain head height.
     * @throws UTXOProvider If there is an error.
     */
    int getChainHeadHeight() throws UTXOProviderException;

    /**
     * The {@link NetworkParameters} of this provider.
     * @return The network parameters.
     */
    NetworkParameters getParams();
}
