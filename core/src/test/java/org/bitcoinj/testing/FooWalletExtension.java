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

package org.bitcoinj.testing;

import org.bitcoinj.wallet.Wallet;
import org.bitcoinj.wallet.WalletExtension;

import java.util.Arrays;

import static com.google.common.base.Preconditions.checkArgument;

public class FooWalletExtension implements WalletExtension {
    private final byte[] data = {1, 2, 3};

    private final boolean isMandatory;
    private final String id;

    public FooWalletExtension(String id, boolean isMandatory) {
        this.isMandatory = isMandatory;
        this.id = id;
    }

    @Override
    public String getWalletExtensionID() {
        return id;
    }

    @Override
    public boolean isWalletExtensionMandatory() {
        return isMandatory;
    }

    @Override
    public byte[] serializeWalletExtension() {
        return data;
    }

    @Override
    public void deserializeWalletExtension(Wallet wallet, byte[] data) {
        checkArgument(Arrays.equals(this.data, data));
    }
}
