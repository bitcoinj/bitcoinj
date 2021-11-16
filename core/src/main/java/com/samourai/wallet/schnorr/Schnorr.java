package com.samourai.wallet.schnorr;

import java.math.BigInteger;
import java.util.Arrays;

public class Schnorr    {

    public static byte[] sign(byte[] msg, byte[] secKey, byte[] auxRand) throws Exception    {
        if(msg.length != 32)    {
            throw new Exception("The message must be a 32-byte array.");
        }
        BigInteger secKey0 = Util.bigIntFromBytes(secKey);

        if(!(BigInteger.ONE.compareTo(secKey0) <= 0 && secKey0.compareTo(Point.getn().subtract(BigInteger.ONE)) <= 0)) {
            throw new Exception("The secret key must be an integer in the range 1..n-1.");
        }
        Point P = Point.mul(Point.getG(), secKey0);
        if(!P.hasEvenY())    {
            secKey0 = Point.getn().subtract(secKey0);
        }
        int len = Util.bytesFromBigInteger(secKey0).length + P.toBytes().length + msg.length;
        byte[] buf = new byte[len];
        byte[] t = Util.xor(Util.bytesFromBigInteger(secKey0), Point.taggedHash("BIP0340/aux", auxRand));
        System.arraycopy(t, 0, buf, 0, t.length);
        System.arraycopy(P.toBytes(), 0, buf, t.length, P.toBytes().length);
        System.arraycopy(msg, 0, buf, t.length + P.toBytes().length, msg.length);
        BigInteger k0 = Util.bigIntFromBytes(Point.taggedHash("BIP0340/nonce", buf)).mod(Point.getn());
        if(k0.compareTo(BigInteger.ZERO) == 0)    {
            throw new Exception("Failure. This happens only with negligible probability.");
        }
        Point R = Point.mul(Point.getG(), k0);
        BigInteger k = null;
        if(!R.hasEvenY())    {
            k = Point.getn().subtract(k0);
        }
        else    {
            k = k0;
        }
        len = R.toBytes().length + P.toBytes().length + msg.length;
        buf = new byte[len];
        System.arraycopy(R.toBytes(), 0, buf, 0, R.toBytes().length);
        System.arraycopy(P.toBytes(), 0, buf, R.toBytes().length, P.toBytes().length);
        System.arraycopy(msg, 0, buf, R.toBytes().length + P.toBytes().length, msg.length);
        BigInteger e = Util.bigIntFromBytes(Point.taggedHash("BIP0340/challenge", buf)).mod(Point.getn());
        BigInteger kes = k.add(e.multiply(secKey0)).mod(Point.getn());
        len = R.toBytes().length + Util.bytesFromBigInteger(kes).length;
        byte[] sig = new byte[len];
        System.arraycopy(R.toBytes(), 0, sig, 0, R.toBytes().length);
        System.arraycopy(Util.bytesFromBigInteger(kes), 0, sig, R.toBytes().length, Util.bytesFromBigInteger(kes).length);
        if(!verify(msg, P.toBytes(), sig))    {
            throw new Exception("The signature does not pass verification.");
        }
        return sig;
    }

    public static boolean verify(byte[] msg, byte[] pubkey, byte[] sig) throws Exception    {
        if(msg.length != 32)    {
            throw new Exception("The message must be a 32-byte array.");
        }
        if(pubkey.length != 32)    {
            throw new Exception("The public key must be a 32-byte array.");
        }
        if(sig.length != 64)    {
            throw new Exception("The signature must be a 64-byte array.");
        }

        Point P = Point.liftX(pubkey);
        if(P == null)    {
            return false;
        }
        BigInteger r = Util.bigIntFromBytes(Arrays.copyOfRange(sig,0, 32));
        BigInteger s = Util.bigIntFromBytes(Arrays.copyOfRange(sig,32, 64));
        if(r.compareTo(Point.getp()) >= 0 || s.compareTo(Point.getn()) >= 0)    {
            return false;
        }
        int len = 32 + pubkey.length + msg.length;
        byte[] buf = new byte[len];
        System.arraycopy(sig, 0, buf, 0, 32);
        System.arraycopy(pubkey, 0, buf, 32, pubkey.length);
        System.arraycopy(msg, 0, buf, 32 + pubkey.length, msg.length);
        BigInteger e = Util.bigIntFromBytes(Point.taggedHash("BIP0340/challenge", buf)).mod(Point.getn());
        Point R = Point.add(Point.mul(Point.getG(), s), Point.mul(P, Point.getn().subtract(e)));
        if(R == null || !R.hasEvenY() || R.getX().compareTo(r) != 0)    {
            return false;
        }
        else    {
            return true;
        }
    }

}
