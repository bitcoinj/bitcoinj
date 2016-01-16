/*
 * Copyright 2013 Google Inc.
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

package org.bitcoinj.wallet.listeners;

import org.bitcoinj.wallet.Wallet;

/**
 * <p>Implementors are called when the wallet is reorganized.</p>
 */
public interface WalletReorganizeEventListener {
    // TODO: Finish onReorganize to be more useful.
    /**
     * <p>This is called when a block is received that triggers a block chain re-organization.</p>
     *
     * <p>A re-organize means that the consensus (chain) of the network has diverged and now changed from what we
     * believed it was previously. Usually this won't matter because the new consensus will include all our old
     * transactions assuming we are playing by the rules. However it's theoretically possible for our balance to
     * change in arbitrary ways, most likely, we could lose some money we thought we had.</p>
     *
     * <p>It is safe to use methods of wallet whilst inside this callback.</p>
     */
    void onReorganize(Wallet wallet);
}
