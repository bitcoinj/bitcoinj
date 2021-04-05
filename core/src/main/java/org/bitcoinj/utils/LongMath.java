package org.bitcoinj.utils;

import java.math.BigInteger;

public class LongMath {
    public static long add(long a,long b){
        return BigInteger.valueOf(a).add(BigInteger.valueOf(b)).longValueExact();
    }
    public static long subtract(long a, long b){
        return BigInteger.valueOf(a).subtract(BigInteger.valueOf(b)).longValueExact();
    }
    public static long pow(long base, int exp){
        return BigInteger.valueOf(base).pow(exp).longValueExact();
    }
    public static long multiply(long a,long b){
        return BigInteger.valueOf(a).multiply(BigInteger.valueOf(b)).longValueExact();
    }
}