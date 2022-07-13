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

package org.bitcoinj.wallet;

import org.bitcoinj.base.BitcoinNetwork;
import org.bitcoinj.base.ScriptType;
import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.crypto.ChildNumber;
import org.bitcoinj.crypto.HDPath;

/**
 *  Defines a structure for hierarchical deterministic wallets.
 *  <p>
 *  Use {@link KeyChainGroupStructure#BIP32} for BIP-32 wallets and {@link KeyChainGroupStructure#BIP43} for
 *  BIP-43-family wallets.
 *  <p>
 *  <b>bitcoinj</b> BIP-32 wallets use {@link DeterministicKeyChain#ACCOUNT_ZERO_PATH} for {@link ScriptType#P2PKH}
 *  and {@link DeterministicKeyChain#ACCOUNT_ONE_PATH} for {@link ScriptType#P2WPKH}
 *  <p>
 *  BIP-43-family wallets structured via {@link KeyChainGroupStructure} will always use account number zero. Currently,
 *  only BIP-44 (P2PKH) and BIP-84 (P2WPKH) are supported.
 */
public interface KeyChainGroupStructure {

    /**
     *  Map desired output script type to an account path.
     *  Default to MainNet, BIP-32 Keychains use the same path for MainNet and TestNet
     * @param outputScriptType the script/address type
     * @return account path
     * @deprecated Use {@link #accountPathFor(ScriptType, BitcoinNetwork)} or {@link #accountPathFor(ScriptType, NetworkParameters)}
     */
    @Deprecated
    default HDPath accountPathFor(ScriptType outputScriptType) {
        return accountPathFor(outputScriptType, BitcoinNetwork.MAINNET);
    }

    /**
     * Map desired output script type and network to an account path
     * @param outputScriptType output script type (purpose)
     * @param network network/coin type
     * @return The HD Path: purpose / coinType / accountIndex
     */
    HDPath accountPathFor(ScriptType outputScriptType, BitcoinNetwork network);

    /**
     * Map desired output script type and network to an account path
     * @param outputScriptType output script type (purpose)
     * @param networkParameters network/coin type
     * @return The HD Path: purpose / coinType / accountIndex
     */
    default HDPath accountPathFor(ScriptType outputScriptType, NetworkParameters networkParameters) {
        return accountPathFor(outputScriptType, networkParameters.network());
    }


    /**
     * Original <b>bitcoinj</b> {@link KeyChainGroupStructure} implementation. Based on BIP32 "Wallet structure".
     * For this structure {@code network} is ignored
     */
    KeyChainGroupStructure BIP32 = (outputScriptType, network) -> {
        // network is ignored
        if (outputScriptType == null || outputScriptType == ScriptType.P2PKH)
            return DeterministicKeyChain.ACCOUNT_ZERO_PATH;
        else if (outputScriptType == ScriptType.P2WPKH)
            return DeterministicKeyChain.ACCOUNT_ONE_PATH;
        else
            throw new IllegalArgumentException(outputScriptType.toString());
    };

    /**
     * {@link KeyChainGroupStructure} implementation for BIP-43 family structures.
     * Currently, BIP-44 and BIP-84 are supported. Account number is hard-coded to zero.
     */
    KeyChainGroupStructure BIP43 = (outputScriptType, network) ->
            purpose(outputScriptType).extend(coinType(network), account(0));

    /**
     * Default {@link KeyChainGroupStructure} implementation. Alias for {@link KeyChainGroupStructure#BIP32}
     * @deprecated Use {@link #BIP32} for BIP-32
     */
    @Deprecated
    KeyChainGroupStructure DEFAULT = BIP32;

    /**
     * Return the (root) path containing "purpose" for the specified scriptType
     * @param scriptType script/address type
     * @return An HDPath with a BIP44 "purpose" entry
     */
    static HDPath purpose(ScriptType scriptType) {
        if (scriptType == null || scriptType == ScriptType.P2PKH) {
            return HDPath.BIP44_PARENT;
        } else if (scriptType == ScriptType.P2WPKH) {
            return HDPath.BIP84_PARENT;
        } else {
            throw new IllegalArgumentException(scriptType.toString());
        }
    }

    /**
     * Return coin type path component for a network id
     * @param network network id string, eg. {@link BitcoinNetwork#ID_MAINNET}
     */
    static ChildNumber coinType(BitcoinNetwork network) {
        switch (network) {
            case MAINNET:
                return ChildNumber.COINTYPE_BTC;
            case TESTNET:
                return ChildNumber.COINTYPE_TBTC;
            case REGTEST:
                return ChildNumber.COINTYPE_TBTC;
            default:
                throw new IllegalArgumentException("coinType: Unknown network");
        }
    }

    /**
     * Return path component for an account
     * @param accountIndex account index
     * @return A hardened path component
     */
    static ChildNumber account(int accountIndex) {
        return new ChildNumber(accountIndex, true);
    }
}
