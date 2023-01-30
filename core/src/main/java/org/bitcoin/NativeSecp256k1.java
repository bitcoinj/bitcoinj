/*
 * Copyright 2013 Google Inc.
 * Copyright 2014-2016 the libsecp256k1 contributors
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

package org.bitcoin;

import com.google.common.base.Preconditions;

import java.math.BigInteger;
import java.nio.Buffer;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

import static org.bitcoin.NativeSecp256k1Util.AssertFailException;
import static org.bitcoin.NativeSecp256k1Util.assertEquals;

/**
 * <p>This class holds native methods to handle ECDSA verification.</p>
 *
 * <p>You can find an example library that can be used for this at https://github.com/bitcoin/secp256k1</p>
 *
 * <p>To build secp256k1 for use with bitcoinj, run
 * `./configure --enable-jni --enable-experimental --enable-module-schnorr --enable-module-ecdh`
 * and `make` then copy `.libs/libsecp256k1.so` to your system library path
 * or point the JVM to the folder containing it with -Djava.library.path
 * </p>
 * @deprecated See https://github.com/bitcoinj/bitcoinj/issues/2267
 */
@Deprecated
public class NativeSecp256k1 {

    private static final ReentrantReadWriteLock rwl = new ReentrantReadWriteLock();
    private static final Lock r = rwl.readLock();
    private static final Lock w = rwl.writeLock();
    private static ThreadLocal<ByteBuffer> nativeECDSABuffer = new ThreadLocal<>();

    /**
     * Verifies the given secp256k1 signature in native code. Calling when enabled == false is undefined (probably
     * library not loaded)
     *
     * @param data The data which was signed, must be exactly 32 bytes
     * @param signature The signature
     * @param pub The public key which did the signing
     * @return true if correct signature
     * @throws AssertFailException never thrown?
     */
    public static boolean verify(byte[] data, byte[] signature, byte[] pub) throws AssertFailException {
        Preconditions.checkArgument(data.length == 32 && signature.length <= 520 && pub.length <= 520);

        ByteBuffer byteBuff = nativeECDSABuffer.get();
        if (byteBuff == null || byteBuff.capacity() < 520) {
            byteBuff = ByteBuffer.allocateDirect(520);
            byteBuff.order(ByteOrder.nativeOrder());
            nativeECDSABuffer.set(byteBuff);
        }
        ((Buffer) byteBuff).rewind();
        byteBuff.put(data);
        byteBuff.put(signature);
        byteBuff.put(pub);

        r.lock();
        try {
            return secp256k1_ecdsa_verify(byteBuff, Secp256k1Context.getContext(), signature.length, pub.length) == 1;
        } finally {
            r.unlock();
        }
    }

    /**
     * libsecp256k1 Create an ECDSA signature.
     *
     * @param data Message hash, 32 bytes
     * @param sec Secret key, 32 bytes
     * @return sig byte array of signature
     * @throws AssertFailException on bad signature length
     */
    public static byte[] sign(byte[] data, byte[] sec) throws AssertFailException {
        Preconditions.checkArgument(data.length == 32 && sec.length <= 32);

        ByteBuffer byteBuff = nativeECDSABuffer.get();
        if (byteBuff == null || byteBuff.capacity() < 32 + 32) {
            byteBuff = ByteBuffer.allocateDirect(32 + 32);
            byteBuff.order(ByteOrder.nativeOrder());
            nativeECDSABuffer.set(byteBuff);
        }
        ((Buffer) byteBuff).rewind();
        byteBuff.put(data);
        byteBuff.put(sec);

        byte[][] retByteArray;

        r.lock();
        try {
            retByteArray = secp256k1_ecdsa_sign(byteBuff, Secp256k1Context.getContext());
        } finally {
            r.unlock();
        }

        byte[] sigArr = retByteArray[0];
        int sigLen = new BigInteger(new byte[] { retByteArray[1][0] }).intValue();
        int retVal = new BigInteger(new byte[] { retByteArray[1][1] }).intValue();

        assertEquals(sigArr.length, sigLen, "Got bad signature length.");

        return retVal == 0 ? new byte[0] : sigArr;
    }

    /**
     * libsecp256k1 Cleanup - This destroys the secp256k1 context object This should be called at the end of the program
     * for proper cleanup of the context.
     */
    public static synchronized void cleanup() {
        w.lock();
        try {
            secp256k1_destroy_context(Secp256k1Context.getContext());
        } finally {
            w.unlock();
        }
    }

    private static native void secp256k1_destroy_context(long context);
    private static native int secp256k1_ecdsa_verify(ByteBuffer byteBuff, long context, int sigLen, int pubLen);
    private static native byte[][] secp256k1_ecdsa_sign(ByteBuffer byteBuff, long context);
}
