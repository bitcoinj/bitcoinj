/* Copyright (c) 2017 Stash
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.bitcoinj.crypto;

import java.math.BigInteger;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.util.encoders.Hex;

public class BIP47SecretPoint {
    private static final ECParameterSpec params = ECNamedCurveTable.getParameterSpec("secp256k1");

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private PrivateKey privKey = null;
    private PublicKey pubKey = null;
    private KeyFactory kf = null;

    public BIP47SecretPoint() {
    }

    public BIP47SecretPoint(byte[] dataPrv, byte[] dataPub) throws InvalidKeySpecException, InvalidKeyException, IllegalStateException, NoSuchAlgorithmException, NoSuchProviderException {
        this.kf = KeyFactory.getInstance("ECDH", "BC");
        this.privKey = this.loadPrivateKey(dataPrv);
        this.pubKey = this.loadPublicKey(dataPub);
    }

    public PrivateKey getPrivKey() {
        return this.privKey;
    }

    public void setPrivKey(PrivateKey privKey) {
        this.privKey = privKey;
    }

    public PublicKey getPubKey() {
        return this.pubKey;
    }

    public void setPubKey(PublicKey pubKey) {
        this.pubKey = pubKey;
    }

    public byte[] ECDHSecretAsBytes() throws InvalidKeyException, IllegalStateException, NoSuchAlgorithmException, NoSuchProviderException {
        return this.ECDHSecret().getEncoded();
    }

    public boolean isShared(BIP47SecretPoint secret) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException {
        return this.equals(secret);
    }

    private SecretKey ECDHSecret() throws InvalidKeyException, IllegalStateException, NoSuchAlgorithmException, NoSuchProviderException {
        KeyAgreement ka = KeyAgreement.getInstance("ECDH", "BC");
        ka.init(this.privKey);
        ka.doPhase(this.pubKey, true);
        SecretKey secret = ka.generateSecret("AES");
        return secret;
    }

    private boolean equals(BIP47SecretPoint secret) throws InvalidKeyException, IllegalStateException, NoSuchAlgorithmException, NoSuchProviderException {
        return Hex.toHexString(this.ECDHSecretAsBytes()).equals(Hex.toHexString(secret.ECDHSecretAsBytes()));
    }

    private PublicKey loadPublicKey(byte[] data) throws InvalidKeySpecException {
        ECPublicKeySpec pubKey = new ECPublicKeySpec(params.getCurve().decodePoint(data), params);
        return this.kf.generatePublic(pubKey);
    }

    private PrivateKey loadPrivateKey(byte[] data) throws InvalidKeySpecException {
        ECPrivateKeySpec prvkey = new ECPrivateKeySpec(new BigInteger(1, data), params);
        return this.kf.generatePrivate(prvkey);
    }
}
