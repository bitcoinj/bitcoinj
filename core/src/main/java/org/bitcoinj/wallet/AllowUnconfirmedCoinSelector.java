/*
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

package org.bitcoinj.wallet;

import org.bitcoinj.core.Transaction;

/**
 * This coin selector will select any transaction at all, regardless of where it came from or whether it was
 * confirmed yet. However immature coinbases will not be included (would be a protocol violation).
 */
public class AllowUnconfirmedCoinSelector extends DefaultCoinSelector {
    @Override protected boolean shouldSelect(Transaction tx) {
        return true;
    }

    private static AllowUnconfirmedCoinSelector instance;

    /** Returns a global static instance of the selector. */
    public static AllowUnconfirmedCoinSelector get() {
        // This doesn't have to be thread safe as the object has no state, so discarded duplicates are harmless.
        if (instance == null)
            instance = new AllowUnconfirmedCoinSelector();
        return instance;
    }
}
