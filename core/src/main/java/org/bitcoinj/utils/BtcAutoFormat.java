/*
 * Copyright 2014 Adam Mackler
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

package org.bitcoinj.utils;

import static org.bitcoinj.core.Coin.SMALLEST_UNIT_EXPONENT;
import com.google.common.collect.ImmutableList;

import java.math.BigInteger;
import static java.math.BigDecimal.ONE;
import static java.math.BigDecimal.ZERO;
import java.math.BigDecimal;
import static java.math.RoundingMode.HALF_UP;

import java.text.DecimalFormat;
import java.text.DecimalFormatSymbols;
import java.text.NumberFormat;

import java.util.Locale;

/**
 * <p>This class, a concrete extension of {@link BtcFormat}, is distinguished by its
 * accommodation of multiple denominational units as follows:
 *
 * <p>When formatting Bitcoin monetary values, an instance of this class automatically adjusts
 * the denominational units in which it represents a given value so as to minimize the number
 * of consecutive zeros in the number that is displayed, and includes either a currency code or
 * symbol in the formatted value to indicate which denomination was chosen.
 *
 * <p>When parsing <code>String</code> representations of Bitcoin monetary values, instances of
 * this class automatically recognize units indicators consisting of currency codes and
 * symbols, including including those containing currency or metric prefixes such as
 * <code>"¢"</code> or <code>"c"</code> to indicate hundredths, and interpret each number being
 * parsed in accordance with the recognized denominational units.
 *
 * <p>A more detailed explanation, including examples, is in the documentation for the {@link
 * BtcFormat} class, and further information beyond that is in the documentation for the {@link
 * java.text.Format} class, from which this class descends.

 * @see          java.text.Format
 * @see          java.text.NumberFormat
 * @see          java.text.DecimalFormat
 * @see          DecimalFormatSymbols
 * @see          org.bitcoinj.core.Coin
 */

public final class BtcAutoFormat extends BtcFormat {

    /**
     * Enum for specifying the style of currency indicators thas are used
     * when formatting, ether codes or symbols.
     */
    public enum Style {

        /* Notes:
         * 1) The odd-looking character in the replacements below, named "currency sign," is used in
         *    the patterns recognized by Java's number formatter.  A single occurrence of this
         *    character specifies a currency symbol, while two adjacent occurrences indicate an
         *    international currency code.
         * 2) The positive and negative patterns each have three parts: prefix, number, suffix.
         *    The number characters are limited to digits, zero, decimal-separator, group-separator, and
         *    scientific-notation specifier: [#0.,E]
         *    All number characters besides 'E' must be single-quoted in order to appear as
         *    literals in either the prefix or suffix.
         * These patterns are explained in the documentation for java.text.DecimalFormat.
         */

        /** Constant for the formatting style that uses a currency code, e.g., "BTC". */
        CODE {
            @Override void apply(DecimalFormat decimalFormat) {
                /* To switch to using codes from symbols, we replace each single occurrence of the
                 * currency-sign character with two such characters in a row.
                 * We also insert a space character between every occurence of this character and an
                 * adjacent numerical digit or negative sign (that is, between the currency-sign and
                 * the signed-number). */
                decimalFormat.applyPattern(
                    negify(decimalFormat.toPattern()).replaceAll("¤","¤¤").
                                                      replaceAll("([#0.,E-])¤¤","$1 ¤¤").
                                                      replaceAll("¤¤([0#.,E-])","¤¤ $1")
                );
            }
        },

        /** Constant for the formatting style that uses a currency symbol, e.g., "฿". */
        SYMBOL {
            @Override void apply(DecimalFormat decimalFormat) {
                /* To make certain we are using symbols rather than codes, we replace
                 * each double occurrence of the currency sign character with a single. */
                decimalFormat.applyPattern(negify(decimalFormat.toPattern()).replaceAll("¤¤","¤"));
            }
        };

        /** Effect a style corresponding to an enum value on the given number formatter object. */
        abstract void apply(DecimalFormat decimalFormat);
    }

    /** Constructor */
    protected BtcAutoFormat(Locale locale, Style style, int fractionPlaces) {
        super((DecimalFormat)NumberFormat.getCurrencyInstance(locale), fractionPlaces, ImmutableList.<Integer>of());
        style.apply(this.numberFormat);
    }

    /**
     * Calculate the appropriate denomination for the given Bitcoin monetary value.  This
     * method takes a BigInteger representing a quantity of satoshis, and returns the
     * number of places that value's decimal point is to be moved when formatting said value
     * in order that the resulting number represents the correct quantity of denominational
     * units.
     *
     * <p>As a side-effect, this sets the units indicators of the underlying NumberFormat object.
     * Only invoke this from a synchronized method, and be sure to put the DecimalFormatSymbols
     * back to its proper state, otherwise immutability, equals() and hashCode() fail.
     */
    @Override
    protected int scale(BigInteger satoshis, int fractionPlaces) {
        /* The algorithm is as follows.  TODO: is there a way to optimize step 4?
           1. Can we use coin denomination w/ no rounding?  If yes, do it.
           2. Else, can we use millicoin denomination w/ no rounding? If yes, do it.
           3. Else, can we use micro denomination w/ no rounding?  If yes, do it.
           4. Otherwise we must round:
             (a) round to nearest coin + decimals
             (b) round to nearest millicoin + decimals
             (c) round to nearest microcoin + decimals
             Subtract each of (a), (b) and (c) from the true value, and choose the
             denomination that gives smallest absolute difference.  It case of tie, use the
             smaller denomination.
        */
        int places;
        int coinOffset = Math.max(SMALLEST_UNIT_EXPONENT - fractionPlaces, 0);
        BigDecimal inCoins = new BigDecimal(satoshis).movePointLeft(coinOffset);
        if (inCoins.remainder(ONE).compareTo(ZERO) == 0) {
            inCoins.setScale(0);
            places = COIN_SCALE;
        } else {
            BigDecimal inMillis = inCoins.movePointRight(MILLICOIN_SCALE);
            if (inMillis.remainder(ONE).compareTo(ZERO) == 0) {
                inMillis.setScale(0);
                places = MILLICOIN_SCALE;
            } else {
                BigDecimal inMicros = inCoins.movePointRight(MICROCOIN_SCALE);
                if (inMicros.remainder(ONE).compareTo(ZERO) == 0) {
                    inMicros.setScale(0);
                    places = MICROCOIN_SCALE;
                } else {
                    // no way to avoid rounding: so what denomination gives smallest error?
                    BigDecimal a = inCoins.subtract(inCoins.setScale(0, HALF_UP)).
                                   movePointRight(coinOffset).abs();
                    BigDecimal b = inMillis.subtract(inMillis.setScale(0, HALF_UP)).
                                   movePointRight(coinOffset - MILLICOIN_SCALE).abs();
                    BigDecimal c = inMicros.subtract(inMicros.setScale(0, HALF_UP)).
                                   movePointRight(coinOffset - MICROCOIN_SCALE).abs();
                    if (a.compareTo(b) < 0)
                        if (a.compareTo(c) < 0) places = COIN_SCALE;
                        else places = MICROCOIN_SCALE;
                    else if (b.compareTo(c) < 0) places = MILLICOIN_SCALE;
                    else places = MICROCOIN_SCALE;
                }
            }
        }
        prefixUnitsIndicator(numberFormat, places);
        return places;
    }

    /** Returns the <code>int</code> value indicating coin denomination.  This is what causes
     *  the number in a parsed value that lacks a units indicator to be interpreted as a quantity
     *  of bitcoins. */
    @Override
    protected int scale() { return COIN_SCALE; }

    /** Return the number of decimal places in the fraction part of numbers formatted by this
     *  instance.  This is the maximum number of fraction places that will be displayed;
     *  the actual number used is limited to a precision of satoshis. */
    public int fractionPlaces() { return minimumFractionDigits; }

    /** Return true if the other instance is equivalent to this one.
      * Formatters for different locales will never be equal, even
      * if they behave identically. */
    @Override public boolean equals(Object o) {
        if (o == this) return true;
        if (!(o instanceof BtcAutoFormat)) return false;
        return super.equals((BtcAutoFormat)o);
    }

    /**
     * Return a brief description of this formatter. The exact details of the representation
     * are unspecified and subject to change, but will include some representation of the
     * pattern and the number of fractional decimal places.
     */
    @Override
    public String toString() { return "Auto-format " + pattern(); }

}
