package org.bitcoin;

import java.math.BigInteger;

import static org.bitcoin.NativeSecp256k1Util.assertEquals;

public class RateByteArray {
    public byte[] rate(byte[][] retByteArray, int length) throws NativeSecp256k1Util.AssertFailException {

        byte[] pubArr = retByteArray[0];
        int pubLen = (byte) new BigInteger(new byte[] { retByteArray[1][0] }).intValue() & 0xFF;
        int retVal = new BigInteger(new byte[] { retByteArray[1][1] }).intValue();

        if(length == 32 || length == 64)
            assertEquals(pubArr.length, length, "Got bad pubkey length.");
        else
            assertEquals(pubArr.length, pubLen, "Got bad pubkey length.");

        assertEquals(retVal, 1, "Failed return value check.");

        if(length == 64)
            return retVal == 0 ? new byte[0] : pubArr;

        return pubArr;
    }
}
