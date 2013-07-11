/**
 * Copyright 2013 Matija Mazi.
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

package com.google.bitcoin.crypto.hd;

import com.google.common.collect.ImmutableList;
import org.spongycastle.crypto.macs.HMac;
import org.spongycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.Arrays;

import static com.google.common.base.Preconditions.checkState;

/**
 * Implementation of the (public derivation version) deterministic wallet child key generation algorithm.
 */
public final class HDKeyDerivation {

    private HDKeyDerivation() { }

    private static final HMac MASTER_HMAC_SHA256 = HDUtils.createHmacSha256Digest("Bitcoin seed".getBytes());

    /**
     * @throws HDDerivationException if generated master key is invalid (private key 0 or >= n).
     */
    public static ExtendedHierarchicKey createMasterPrivateKey(byte[] seed) throws HDDerivationException {
        // Calculate I = HMAC-SHA512(key="Bitcoin seed", msg=S)
        byte[] i = HDUtils.hmacSha256(MASTER_HMAC_SHA256, seed);
        // Split I into two 32-byte sequences, Il and Ir.
        // Use Il as master secret key, and Ir as master chain code.
        checkState(i.length == 64, i.length);
        byte[] il = Arrays.copyOfRange(i, 0, 32);
        byte[] ir = Arrays.copyOfRange(i, 32, 64);
        Arrays.fill(i, (byte)0);
        ExtendedHierarchicKey masterPrivKey = createMasterPrivKeyFromBytes(il, ir);
        Arrays.fill(il, (byte)0);
        Arrays.fill(ir, (byte)0);
        return masterPrivKey;
    }

    /**
     * @throws HDDerivationException if privKeyBytes is invalid (0 or >= n).
     */
    static ExtendedHierarchicKey createMasterPrivKeyFromBytes(byte[] privKeyBytes, byte[] chainCode) throws HDDerivationException {
        BigInteger privateKeyFieldElt = HDUtils.toBigInteger(privKeyBytes);
        assertNonZero(privateKeyFieldElt, "Generated master key is invalid.");
        assertLessThanN(privateKeyFieldElt, "Generated master key is invalid.");
        return new ExtendedHierarchicKey(ImmutableList.<ChildNumber>of(), chainCode, null, privateKeyFieldElt, null);
    }

    public static ExtendedHierarchicKey createMasterPubKeyFromBytes(byte[] pubKeyBytes, byte[] chainCode) {
        return new ExtendedHierarchicKey(ImmutableList.<ChildNumber>of(), chainCode, HDUtils.getCurve().decodePoint(pubKeyBytes), null, null);
    }

    /**
     * @param childNumber the "extended" child number, ie. with the 0x80000000 bit specifying private/public derivation.
     */
    public static ExtendedHierarchicKey deriveChildKey(ExtendedHierarchicKey parent, int childNumber) {
        return deriveChildKey(parent, new ChildNumber(childNumber));
    }

    /**
     * @throws HDDerivationException if private derivation is attempted for a public-only parent key, or
     * if the resulting derived key is invalid (eg. private key == 0).
     */
    public static ExtendedHierarchicKey deriveChildKey(ExtendedHierarchicKey parent, ChildNumber childNumber)
            throws HDDerivationException {

        RawKeyBytes rawKey = deriveChildKeyBytes(parent, childNumber);
        return new ExtendedHierarchicKey(
                HDUtils.append(parent.getChildNumberPath(), childNumber),
                rawKey.chainCode,
                parent.hasPrivate() ? null : HDUtils.getCurve().decodePoint(rawKey.keyBytes),
                parent.hasPrivate() ? HDUtils.toBigInteger(rawKey.keyBytes) : null,
                parent);
    }

    private static RawKeyBytes deriveChildKeyBytes(ExtendedHierarchicKey parent, ChildNumber childNumber)
            throws HDDerivationException {

        byte[] parentPublicKey = HDUtils.getBytes(parent.getPubPoint());
        assert parentPublicKey.length == 33 : parentPublicKey.length;
        ByteBuffer data = ByteBuffer.allocate(37);
        if (childNumber.isPrivateDerivation()) {
            data.put(parent.getPrivKeyBytes33());
        } else {
            data.put(parentPublicKey);
        }
        data.putInt(childNumber.getI());
        byte[] i = HDUtils.hmacSha256(parent.getChainCode(), data.array());
        assert i.length == 64 : i.length;
        byte[] il = Arrays.copyOfRange(i, 0, 32);
        byte[] chainCode = Arrays.copyOfRange(i, 32, 64);
        BigInteger ilInt = HDUtils.toBigInteger(il);
        assertLessThanN(ilInt, "Illegal derived key: I_L >= n");
        byte[] keyBytes;
        if (parent.hasPrivate()) {
            BigInteger ki = parent.getPrivAsFieldElement().add(ilInt).mod(HDUtils.getEcParams().getN());
            assertNonZero(ki, "Illegal derived key: derived private key equals 0.");
            keyBytes = ki.toByteArray();
        } else {
            assertArgument(!childNumber.isPrivateDerivation(), "Can't use private derivation with public keys only.");
            ECPoint Ki = HDUtils.getEcParams().getG().multiply(ilInt).add(parent.getPubPoint());
            assertArgument(!Ki.equals(HDUtils.getCurve().getInfinity()),
                    "Illegal derived key: derived public key equals infinity.");
            keyBytes = HDUtils.toCompressed(Ki.getEncoded());
        }
        return new RawKeyBytes(keyBytes, chainCode);
    }

    private static void assertNonZero(BigInteger integer, String errorMessage) {
        assertArgument(!integer.equals(BigInteger.ZERO), errorMessage);
    }

    private static void assertLessThanN(BigInteger integer, String errorMessage) {
        assertArgument(integer.compareTo(HDUtils.getEcParams().getN()) < 0, errorMessage);
    }

    private static void assertArgument(boolean assertion, String errorMessage) {
        if (!assertion) {
            throw new HDDerivationException(errorMessage);
        }
    }

    private static class RawKeyBytes {
        private final byte[] keyBytes, chainCode;

        private RawKeyBytes(byte[] keyBytes, byte[] chainCode) {
            this.keyBytes = keyBytes;
            this.chainCode = chainCode;
        }
    }
}
