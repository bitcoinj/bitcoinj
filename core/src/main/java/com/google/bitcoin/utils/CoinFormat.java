/*
 * Copyright 2014 Andreas Schildbach
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

package com.google.bitcoin.utils;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkState;
import static com.google.common.math.LongMath.checkedMultiply;
import static com.google.common.math.LongMath.checkedPow;
import static com.google.common.math.LongMath.divide;

import java.math.RoundingMode;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

import com.google.bitcoin.core.Coin;

/**
 * <p>
 * Utility for formatting and parsing coin values to and from human readable form.
 * </p>
 * 
 * <p>
 * CoinFormat instances are immutable. Invoking a configuration method has no effect on the receiving instance; you must
 * store and use the new instance it returns, instead. Instances are thread safe, so they may be stored safely as static
 * constants.
 * </p>
 */
public final class CoinFormat {

    /** Standard format for the BTC denomination. */
    public static final CoinFormat BTC = new CoinFormat().shift(0).minDecimals(2).repeatOptionalDecimals(2, 3);
    /** Standard format for the mBTC denomination. */
    public static final CoinFormat MBTC = new CoinFormat().shift(3).minDecimals(2).optionalDecimals(2);
    /** Standard format for the µBTC denomination. */
    public static final CoinFormat UBTC = new CoinFormat().shift(6).minDecimals(0).optionalDecimals(2);

    private final char negativeSign;
    private final char positiveSign;
    private final char decimalMark;
    private final int minDecimals;
    private final List<Integer> decimalGroups;
    private final int shift;
    private final RoundingMode roundingMode;

    private static final String DECIMALS_PADDING = "0000000000000000"; // a few more than necessary for Bitcoin

    /**
     * Set character to prefix negative values.
     */
    public CoinFormat negativeSign(char negativeSign) {
        checkArgument(!Character.isDigit(negativeSign));
        checkArgument(negativeSign > 0);
        if (negativeSign == this.negativeSign)
            return this;
        else
            return new CoinFormat(negativeSign, positiveSign, decimalMark, minDecimals, decimalGroups, shift,
                    roundingMode);
    }

    /**
     * Set character to prefix positive values. A zero value means no sign is used in this case. For parsing, a missing
     * sign will always be interpreted as if the positive sign was used.
     */
    public CoinFormat positiveSign(char positiveSign) {
        checkArgument(!Character.isDigit(positiveSign));
        if (positiveSign == this.positiveSign)
            return this;
        else
            return new CoinFormat(negativeSign, positiveSign, decimalMark, minDecimals, decimalGroups, shift,
                    roundingMode);
    }

    /**
     * Set character to use as the decimal mark. If the formatted value does not have any decimals, no decimal mark is
     * used either.
     */
    public CoinFormat decimalMark(char decimalMark) {
        checkArgument(!Character.isDigit(decimalMark));
        checkArgument(decimalMark > 0);
        if (decimalMark == this.decimalMark)
            return this;
        else
            return new CoinFormat(negativeSign, positiveSign, decimalMark, minDecimals, decimalGroups, shift,
                    roundingMode);
    }

    /**
     * Set minimum number of decimals to use for formatting. If the value precision exceeds all decimals specified
     * (including additional decimals specified by {@link #optionalDecimals(int...)} or
     * {@link #repeatOptionalDecimals(int, int)}), the value will be rounded. This configuration is not relevant for
     * parsing.
     */
    public CoinFormat minDecimals(int minDecimals) {
        if (minDecimals == this.minDecimals)
            return this;
        else
            return new CoinFormat(negativeSign, positiveSign, decimalMark, minDecimals, decimalGroups, shift,
                    roundingMode);
    }

    /**
     * <p>
     * Set additional groups of decimals to use after the minimum decimals, if they are useful for expressing precision.
     * Each value is a number of decimals in that group. If the value precision exceeds all decimals specified
     * (including minimum decimals), the value will be rounded. This configuration is not relevant for parsing.
     * </p>
     * 
     * <p>
     * For example, if you pass <tt>4,2</tt> it will add four decimals to your formatted string if needed, and then add
     * another two decimals if needed. At this point, rather than adding further decimals the value will be rounded.
     * </p>
     * 
     * @param groups
     *            any number numbers of decimals, one for each group
     */
    public CoinFormat optionalDecimals(int... groups) {
        List<Integer> decimalGroups = new ArrayList<Integer>(groups.length);
        for (int group : groups)
            decimalGroups.add(group);
        return new CoinFormat(negativeSign, positiveSign, decimalMark, minDecimals, decimalGroups, shift, roundingMode);
    }

    /**
     * <p>
     * Set repeated additional groups of decimals to use after the minimum decimals, if they are useful for expressing
     * precision. If the value precision exceeds all decimals specified (including minimum decimals), the value will be
     * rounded. This configuration is not relevant for parsing.
     * </p>
     * 
     * <p>
     * For example, if you pass <tt>1,8</tt> it will up to eight decimals to your formatted string if needed. After
     * these have been used up, rather than adding further decimals the value will be rounded.
     * </p>
     * 
     * @param decimals
     *            value of the group to be repeated
     * @param repetitions
     *            number of repetitions
     */
    public CoinFormat repeatOptionalDecimals(int decimals, int repetitions) {
        checkArgument(repetitions > 0);
        List<Integer> decimalGroups = new ArrayList<Integer>(repetitions);
        for (int i = 0; i < repetitions; i++)
            decimalGroups.add(decimals);
        return new CoinFormat(negativeSign, positiveSign, decimalMark, minDecimals, decimalGroups, shift, roundingMode);
    }

    /**
     * Set number of digits to shift the decimal separator to the right, coming from the standard BTC notation that was
     * common pre-2014.
     */
    public CoinFormat shift(int shift) {
        if (shift == this.shift)
            return this;
        else
            return new CoinFormat(negativeSign, positiveSign, decimalMark, minDecimals, decimalGroups, shift,
                    roundingMode);
    }

    /**
     * Set rounding mode to use when it becomes necessary.
     */
    public CoinFormat roundingMode(RoundingMode roundingMode) {
        if (roundingMode == this.roundingMode)
            return this;
        else
            return new CoinFormat(negativeSign, positiveSign, decimalMark, minDecimals, decimalGroups, shift,
                    roundingMode);
    }

    public CoinFormat() {
        // defaults
        this.negativeSign = '-';
        this.positiveSign = 0; // none
        this.decimalMark = '.';
        this.minDecimals = 2;
        this.decimalGroups = null;
        this.shift = 0;
        this.roundingMode = RoundingMode.HALF_UP;
    }

    private CoinFormat(char negativeSign, char positiveSign, char decimalMark, int minDecimals,
            List<Integer> decimalGroups, int shift, RoundingMode roundingMode) {
        this.negativeSign = negativeSign;
        this.positiveSign = positiveSign;
        this.decimalMark = decimalMark;
        this.minDecimals = minDecimals;
        this.decimalGroups = decimalGroups;
        this.shift = shift;
        this.roundingMode = roundingMode;
    }

    /**
     * Format the given value to a human readable form.
     */
    public CharSequence format(Coin coin) {
        // preparation
        int maxDecimals = minDecimals;
        if (decimalGroups != null)
            for (int group : decimalGroups)
                maxDecimals += group;
        checkState(maxDecimals <= Coin.NUM_COIN_DECIMALS);

        // rounding
        long satoshis = Math.abs(coin.value);
        long precisionDivisor = checkedPow(10, Coin.NUM_COIN_DECIMALS - shift - maxDecimals);
        satoshis = checkedMultiply(divide(satoshis, precisionDivisor, roundingMode), precisionDivisor);

        // shifting
        long shiftDivisor = checkedPow(10, Coin.NUM_COIN_DECIMALS - shift);
        long numbers = satoshis / shiftDivisor;
        long decimals = satoshis % shiftDivisor;

        // formatting
        String decimalsStr = String.format(Locale.US, "%0" + (Coin.NUM_COIN_DECIMALS - shift) + "d", decimals);
        StringBuilder str = new StringBuilder(decimalsStr);
        while (str.length() > minDecimals && str.charAt(str.length() - 1) == '0')
            str.setLength(str.length() - 1); // trim trailing zero
        int i = minDecimals;
        if (decimalGroups != null) {
            for (int group : decimalGroups) {
                if (str.length() > i && str.length() < i + group) {
                    while (str.length() < i + group)
                        str.append('0');
                    break;
                }
                i += group;
            }
        }
        if (str.length() > 0)
            str.insert(0, decimalMark);
        str.insert(0, numbers);
        if (coin.value < 0)
            str.insert(0, negativeSign);
        else if (positiveSign != 0)
            str.insert(0, positiveSign);
        return str;
    }

    /**
     * Parse a human readable coin value to a {@link com.google.bitcoin.core.Coin} instance.
     * 
     * @throws NumberFormatException
     *             if the string cannot be parsed for some reason
     */
    public Coin parse(String str) throws NumberFormatException {
        checkState(DECIMALS_PADDING.length() >= Coin.NUM_COIN_DECIMALS);
        if (str.isEmpty())
            throw new NumberFormatException("empty string");
        char first = str.charAt(0);
        if (first == negativeSign || first == positiveSign)
            str = str.substring(1);
        String numbers;
        String decimals;
        int decimalMarkIndex = str.indexOf(decimalMark);
        if (decimalMarkIndex != -1) {
            numbers = str.substring(0, decimalMarkIndex);
            decimals = (str + DECIMALS_PADDING).substring(decimalMarkIndex + 1);
            if (decimals.indexOf(decimalMark) != -1)
                throw new NumberFormatException("more than one decimal mark");
        } else {
            numbers = str;
            decimals = DECIMALS_PADDING;
        }
        String satoshis = numbers + decimals.substring(0, Coin.NUM_COIN_DECIMALS - shift);
        for (char c : satoshis.toCharArray())
            if (!Character.isDigit(c))
                throw new NumberFormatException("illegal character: " + c);
        Coin coin = Coin.valueOf(Long.parseLong(satoshis));
        if (first == negativeSign)
            coin = coin.negate();
        return coin;
    }
}
