/* Copyright (c) 2017 Stash
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.bitcoinj.core.bip47;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;
import org.bitcoinj.core.AddressFormatException;
import org.bitcoinj.core.ECKey;
import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.crypto.BIP47SecretPoint;
import org.bitcoinj.wallet.bip47.NotSecp256k1Exception;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.math.ec.ECPoint;

/**
 * <p>A {@link BIP47PaymentAddress} is derived for account deposits in a bip47 channel. It is used by a recipient's bip47 wallet to derive and watch deposits. It
 * is also used by a sender's bip47 wallet to calculate the next addresses to send a deposit to.</p>
 *
 * <p>The BIP47 BIP47PaymentAddress is at the derivation path </p><pre>m / 47' / coin_type' / account_id' / idx' .</pre>
 *
 * <p>Properties:</p>
 * <ul>
 * <li>The account_id is irrelevant in this class, it's implied in privKey. </li>
 * <li>The owner of BIP47PaymentCode is not the same owner of privKey.</li>
 * </ul>
 */
public class BIP47PaymentAddress {
    // if we are receiving, this is the sender's payment code
    // if we are sending, this is the receiver's payment code
    private org.bitcoinj.core.bip47.BIP47PaymentCode BIP47PaymentCode = null;
    // the index to use in the derivation path
    private int index = 0;
    // the corresponding hardedened key bytes at the derivation path
    private byte[] privKey = null;
    // the network used for formatting
    private NetworkParameters networkParameters;
    // give the values for "a", "b", "G" in the ECDSA curve used in Bitcoin (https://en.bitcoin.it/wiki/Secp256k1)
    private static final X9ECParameters CURVE_PARAMS = CustomNamedCurves.getByName("secp256k1");
    // create the curve
    private static final ECDomainParameters CURVE;
    static {
        CURVE = new ECDomainParameters(CURVE_PARAMS.getCurve(), CURVE_PARAMS.getG(), CURVE_PARAMS.getN(), CURVE_PARAMS.getH());
    }

    /** Creates a BIP47PaymentAddress object that the sender will use to pay, using the hardened key at idx */
    public BIP47PaymentAddress(NetworkParameters networkParameters, BIP47PaymentCode BIP47PaymentCode, int index, byte[] privKey) throws AddressFormatException {
        this.BIP47PaymentCode = BIP47PaymentCode;
        this.index = index;
        this.privKey = privKey;
        this.networkParameters = networkParameters;
    }

    /** Creates a HD key to send a deposit */
    public ECKey getSendECKey() throws AddressFormatException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, IllegalStateException, InvalidKeySpecException, NotSecp256k1Exception {
        return this.getSendECKey(this.secretPoint());
    }

    /** Derives a deposit address to watch to receive payments from BIP47PaymentCode's owner*/
    public ECKey getReceiveECKey() throws AddressFormatException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, IllegalStateException, InvalidKeySpecException, NotSecp256k1Exception {
        return this.getReceiveECKey(this.secretPoint());
    }

    /* Use the generator "G" by */
    //public ECPoint get_sG() throws AddressFormatException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, IllegalStateException, InvalidKeySpecException, NotSecp256k1Exception {
    //    return CURVE_PARAMS.getG().multiply(this.getSecretPoint());
    //}

    /* Accesor for the secret point between sender and receiver */
    public BIP47SecretPoint getSharedSecret() throws AddressFormatException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, IllegalStateException, InvalidKeySpecException {
        return this.sharedSecret();
    }

    //public BigInteger getSecretPoint() throws AddressFormatException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, IllegalStateException, InvalidKeySpecException, NotSecp256k1Exception {
    //    return this.secretPoint();
    //}

    public ECPoint getECPoint() throws AddressFormatException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, IllegalStateException, InvalidKeySpecException {
        ECKey ecKey = ECKey.fromPublicOnly(this.BIP47PaymentCode.derivePubKeyAt(this.networkParameters, this.index));
        return ecKey.getPubKeyPoint();
    }

    /** Returns the scalar shared secret */
    public byte[] hashSharedSecret() throws AddressFormatException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, IllegalStateException, InvalidKeySpecException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(this.getSharedSecret().ECDHSecretAsBytes());
        return hash;
    }

    /* Multply a times the generator G */
    private ECPoint get_sG(BigInteger s) {
        return CURVE_PARAMS.getG().multiply(s);
    }

    /* Derives the key for the payment address where the BIP47PaymentCode's owner will be watching for deposits */
    private ECKey getSendECKey(BigInteger s) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {
        ECPoint ecPoint = this.getECPoint();
        ECPoint sG = this.get_sG(s);
        ECKey ecKey = ECKey.fromPublicOnly(ecPoint.add(sG).getEncoded(true));
        return ecKey;
    }

    /* Calculates the ephemeral hardened key used to generate the P2PKH address where a deposit will be received */
    private ECKey getReceiveECKey(BigInteger s) {
        BigInteger privKeyValue = ECKey.fromPrivate(this.privKey).getPrivKey();
        ECKey ecKey = ECKey.fromPrivate(this.addSecp256k1(privKeyValue, s));
        return ecKey;
    }

    /* Adds two keys together */
    private BigInteger addSecp256k1(BigInteger b1, BigInteger b2) {
        BigInteger ret = b1.add(b2);
        return ret.bitLength() > CURVE.getN().bitLength()?ret.mod(CURVE.getN()):ret;
    }

    /* Return the ECDH shared secret between us and the owner of BIP47PaymentCode */
    private BIP47SecretPoint sharedSecret() throws AddressFormatException, InvalidKeySpecException, InvalidKeyException, IllegalStateException, NoSuchAlgorithmException, NoSuchProviderException {
        byte[] pubKey = this.BIP47PaymentCode.derivePubKeyAt(this.networkParameters, this.index);
        return new BIP47SecretPoint(this.privKey, pubKey);
    }

    /* Returns true if the given point "b" is in the curve */
    private boolean isSecp256k1(BigInteger b) {
        return b.compareTo(BigInteger.ONE) > 0 && b.bitLength() <= CURVE.getN().bitLength();
    }

    /** Returns a SHA256 mask of the secret point */
    private BigInteger secretPoint() throws AddressFormatException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException, NotSecp256k1Exception {
        BigInteger s = new BigInteger(1, this.hashSharedSecret());
        if(!this.isSecp256k1(s)) {
            throw new NotSecp256k1Exception("secret point not on Secp256k1 curve");
        } else {
            return s;
        }
    }
}
