/* Copyright (c) 2017 Stash
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.bitcoinj.core.bip47;

import java.math.BigInteger;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.tuple.Pair;
import org.bitcoinj.core.*;
import org.bitcoinj.crypto.ChildNumber;
import org.bitcoinj.crypto.DeterministicKey;
import org.bitcoinj.crypto.HDKeyDerivation;

public class BIP47PaymentCode {
    private static final int PUBLIC_KEY_Y_OFFSET = 2;
    private static final int PUBLIC_KEY_X_OFFSET = 3;
    private static final int CHAIN_OFFSET = 35;
    private static final int PUBLIC_KEY_X_LEN = 32;
    private static final int PUBLIC_KEY_Y_LEN = 1;
    private static final int CHAIN_LEN = 32;
    private static final int PAYLOAD_LEN = 80;
    private String strPaymentCode = null;
    private byte[] pubkey = null;
    private byte[] chain = null;

    public BIP47PaymentCode() {
        this.strPaymentCode = null;
        this.pubkey = null;
        this.chain = null;
    }

    public BIP47PaymentCode(String payment_code) throws AddressFormatException {
        this.strPaymentCode = payment_code;
        this.pubkey = this.parse().getLeft();
        this.chain = this.parse().getRight();
    }

    public BIP47PaymentCode(byte[] payload) {
        if(payload.length == 80) {
            this.pubkey = new byte[33];
            this.chain = new byte[32];
            System.arraycopy(payload, 2, this.pubkey, 0, 33);
            System.arraycopy(payload, 35, this.chain, 0, 32);
            this.strPaymentCode = this.makeV1();
        }
    }

    public BIP47PaymentCode(byte[] pubkey, byte[] chain) {
        this.pubkey = pubkey;
        this.chain = chain;
        this.strPaymentCode = this.makeV1();
    }

    public byte[] getPayload() throws AddressFormatException {
        byte[] pcBytes = Base58.decodeChecked(this.strPaymentCode);
        byte[] payload = new byte[80];
        System.arraycopy(pcBytes, 1, payload, 0, payload.length);
        return payload;
    }

    public int getType() throws AddressFormatException {
        byte[] payload = this.getPayload();
        ByteBuffer bb = ByteBuffer.wrap(payload);
        byte type = bb.get();
        return type;
    }

    public byte[] decode() throws AddressFormatException {
        return Base58.decode(this.strPaymentCode);
    }

    public byte[] decodeChecked() throws AddressFormatException {
        return Base58.decodeChecked(this.strPaymentCode);
    }

    public byte[] getPubKey() {
        return this.pubkey;
    }

    public byte[] getChain() {
        return this.chain;
    }

    public String toString() {
        return this.strPaymentCode;
    }

    public static byte[] getMask(byte[] sPoint, byte[] oPoint) {
        Mac sha512_HMAC = null;
        byte[] mac_data = null;

        try {
            sha512_HMAC = Mac.getInstance("HmacSHA512");
            SecretKeySpec secretkey = new SecretKeySpec(oPoint, "HmacSHA512");
            sha512_HMAC.init(secretkey);
            mac_data = sha512_HMAC.doFinal(sPoint);
        } catch (InvalidKeyException var5) {
        } catch (NoSuchAlgorithmException var6) {
        }

        return mac_data;
    }

    public static byte[] blind(byte[] payload, byte[] mask) throws AddressFormatException {
        byte[] ret = new byte[80];
        byte[] pubkey = new byte[32];
        byte[] chain = new byte[32];
        byte[] buf0 = new byte[32];
        byte[] buf1 = new byte[32];
        System.arraycopy(payload, 0, ret, 0, 80);
        System.arraycopy(payload, 3, pubkey, 0, 32);
        System.arraycopy(payload, 35, chain, 0, 32);
        System.arraycopy(mask, 0, buf0, 0, 32);
        System.arraycopy(mask, 32, buf1, 0, 32);
        System.arraycopy(xor(pubkey, buf0), 0, ret, 3, 32);
        System.arraycopy(xor(chain, buf1), 0, ret, 35, 32);
        return ret;
    }

    private Pair<byte[], byte[]> parse() throws AddressFormatException {
        byte[] pcBytes = Base58.decodeChecked(this.strPaymentCode);
        ByteBuffer bb = ByteBuffer.wrap(pcBytes);
        if(bb.get() != 71) {
            throw new AddressFormatException("invalid payment code version");
        } else {
            byte[] chain = new byte[32];
            byte[] pub = new byte[33];
            bb.get();
            bb.get();
            bb.get(pub);
            if(pub[0] != 2 && pub[0] != 3) {
                throw new AddressFormatException("invalid public key");
            } else {
                bb.get(chain);
                return Pair.of(pub, chain);
            }
        }
    }

    private String makeV1() {
        return this.make(1);
    }

    private String makeV2() {
        return this.make(2);
    }

    private String make(int type) {
        String ret = null;
        byte[] payload = new byte[80];
        byte[] payment_code = new byte[81];

        for(int checksum = 0; checksum < payload.length; ++checksum) {
            payload[checksum] = 0;
        }

        payload[0] = (byte)type;
        payload[1] = 0;
        System.arraycopy(this.pubkey, 0, payload, 2, this.pubkey.length);
        System.arraycopy(this.chain, 0, payload, 35, this.chain.length);
        payment_code[0] = 71;
        System.arraycopy(payload, 0, payment_code, 1, payload.length);
        byte[] var7 = Arrays.copyOfRange(Sha256Hash.hashTwice(payment_code), 0, 4);
        byte[] payment_code_checksum = new byte[payment_code.length + var7.length];
        System.arraycopy(payment_code, 0, payment_code_checksum, 0, payment_code.length);
        System.arraycopy(var7, 0, payment_code_checksum, payment_code_checksum.length - 4, var7.length);
        ret = Base58.encode(payment_code_checksum);
        return ret;
    }

    private DeterministicKey createMasterPubKeyFromBytes(byte[] pub, byte[] chain) throws AddressFormatException {
        return HDKeyDerivation.createMasterPubKeyFromBytes(pub, chain);
    }

    private static byte[] xor(byte[] a, byte[] b) {
        if(a.length != b.length) {
            return null;
        } else {
            byte[] ret = new byte[a.length];

            for(int i = 0; i < a.length; ++i) {
                ret[i] = (byte)(b[i] ^ a[i]);
            }

            return ret;
        }
    }

    public boolean isValid() {
        try {
            byte[] afe = Base58.decodeChecked(this.strPaymentCode);
            ByteBuffer byteBuffer = ByteBuffer.wrap(afe);
            if(byteBuffer.get() != 71) {
                throw new AddressFormatException("invalid version: " + this.strPaymentCode);
            } else {
                byte[] chain = new byte[32];
                byte[] pub = new byte[33];
                byteBuffer.get();
                byteBuffer.get();
                byteBuffer.get(pub);
                byteBuffer.get(chain);
                ByteBuffer pubBytes = ByteBuffer.wrap(pub);
                byte firstByte = pubBytes.get();
                return firstByte == 2 || firstByte == 3;
            }
        } catch (BufferUnderflowException var7) {
            return false;
        } catch (AddressFormatException var8) {
            return false;
        }
    }

    public static DeterministicKey createMasterPubKeyFromPaymentCode(String payment_code_str) throws AddressFormatException {
        byte[] paymentCodeBytes = Base58.decodeChecked(payment_code_str);
        ByteBuffer bb = ByteBuffer.wrap(paymentCodeBytes);
        if(bb.get() != 71) {
            throw new AddressFormatException("invalid payment code version");
        } else {
            byte[] chain = new byte[32];
            byte[] pub = new byte[33];
            bb.get();
            bb.get();
            bb.get(pub);
            bb.get(chain);
            return HDKeyDerivation.createMasterPubKeyFromBytes(pub, chain);
        }
    }

    /** Returns the pubkey on the ith derivation path */
    public byte[] derivePubKeyAt(NetworkParameters networkParameters, int i) throws AddressFormatException {
        DeterministicKey key = createMasterPubKeyFromPaymentCode(this.strPaymentCode);
        DeterministicKey dk = HDKeyDerivation.deriveChildKey(key, new ChildNumber(i, false));

        ECKey ecKey;
        if(dk.hasPrivKey()) {
            byte[] now = ArrayUtils.addAll(new byte[1], dk.getPrivKeyBytes());
            ecKey = ECKey.fromPrivate(new BigInteger(now), true);
        } else {
            ecKey = ECKey.fromPublicOnly(dk.getPubKey());
        }

        long now1 = Utils.now().getTime() / 1000L;
        ecKey.setCreationTimeSeconds(now1);

        return ecKey.getPubKey();
    }
}
