/* Copyright (c) 2017 Stash
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
package org.bitcoinj.core.bip47;

import org.bitcoinj.core.Address;
import org.bitcoinj.core.ECKey;
import org.bitcoinj.core.LegacyAddress;
import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.crypto.ChildNumber;
import org.bitcoinj.crypto.DeterministicKey;
import org.bitcoinj.crypto.HDDerivationException;
import org.bitcoinj.crypto.HDKeyDerivation;

import static org.bitcoinj.core.bip47.BIP47PaymentCode.createMasterPubKeyFromPaymentCode;

/**
 * Created by jimmy on 8/4/17.
 */

/**
 * <p>A {@link BIP47Account} is necessary for BIP47 payment channels. It holds the notification key used to derive the
 * notification address and the key to derive payment addresses in a channel.</p>
 *
 * <p>The BIP47 account is at the derivation path </p><pre>m / 47' / coin_type' / account_id'.</pre>.
 *
 * <p>Properties:</p>
 * <ul>
 * <li>The coin_type' should be chosen as in BIP43. </li>
 * <li>The account_id is any integer (from 0 to 2147483647)</li>
 * <li>The notification key is derived at: <pre>m / 47' / coin_type' / account_id' / 0 </pre> (non hardened)</li>
 * <li>The payment keys are derived at: <pre>m / 47' / coin_type' / account_id' / idx' </pre> (hardened). </li>
 * </ul>
 */
public class BIP47Account {
    private NetworkParameters mNetworkParameters;
    private DeterministicKey mKey;
    private int mIndex;
    private BIP47PaymentCode mBIP47PaymentCode;
    private String mXPub;

    /**
     * Constructor expecting a coin_type' derivation path key and the identity number.
     */
    public BIP47Account(NetworkParameters parameters, DeterministicKey deterministicKey, int index) {
        mNetworkParameters = parameters;
        mIndex = index;
        mKey = HDKeyDerivation.deriveChildKey(deterministicKey, mIndex | ChildNumber.HARDENED_BIT);
        mBIP47PaymentCode = new BIP47PaymentCode(mKey.getPubKey(), mKey.getChainCode());
        mXPub = mKey.serializePubB58(parameters);
    }

    /**
     * Constructor expecting a Base58Check encoded payment code.
     */
    public BIP47Account(NetworkParameters parameters, String strPaymentCode) {
        mNetworkParameters = parameters;
        mIndex = 0;
        mKey = createMasterPubKeyFromPaymentCode(strPaymentCode);
        mBIP47PaymentCode = new BIP47PaymentCode(strPaymentCode);
        mXPub = mKey.serializePubB58(parameters);
    }

    /** Return the Base58Check representation of the payment code*/
    public String getStringPaymentCode() {
        return mBIP47PaymentCode.toString();
    }

    public String getXPub() {
        return mXPub;
    }

    /** Returns the P2PKH address associated with the 0th public key  */
    public Address getNotificationAddress() {
        return LegacyAddress.fromKey(mNetworkParameters, HDKeyDerivation.deriveChildKey(mKey, ChildNumber.ZERO));
    }

    /** Returns the 0th derivation key */
    public ECKey getNotificationKey() {
        return HDKeyDerivation.deriveChildKey(mKey, ChildNumber.ZERO);
    }

    /** Return the payment code as is */
    public BIP47PaymentCode getPaymentCode() {
        return mBIP47PaymentCode;
    }

    /** Returns the nth key.
     * @param idx must be between 0 and 2147483647
     */
    public ECKey keyAt(int idx) throws HDDerivationException {
        return HDKeyDerivation.deriveChildKey(mKey, new ChildNumber(idx, false));
    }

    public byte[] getPrivKey(int index) {
        return HDKeyDerivation.deriveChildKey(mKey, index).getPrivKeyBytes();
    }
}
