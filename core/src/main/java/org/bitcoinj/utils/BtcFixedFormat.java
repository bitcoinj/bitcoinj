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

import org.bitcoinj.base.Coin;

import java.math.BigInteger;
import java.text.DecimalFormat;
import java.text.Format;
import java.text.NumberFormat;
import java.util.List;
import java.util.Locale;
import java.util.Objects;

import static com.google.common.base.Preconditions.checkArgument;
import static org.bitcoinj.base.Coin.SMALLEST_UNIT_EXPONENT;

/**
 * <p>This class, a concrete extension of {@link BtcFormat}, is distinguished in that each
 * instance formats and by-default parses all Bitcoin monetary values in units of a single
 * denomination that is specified at the time that instance is constructed.</p>
 *
 * <p>By default, neither currency codes nor symbols are included in formatted values as
 * output, nor recognized in parsed values as input.  The can be overridden by applying a
 * custom pattern using either the {@link BtcFormat.Builder#localizedPattern} or
 * {@link BtcFormat.Builder#localizedPattern} methods, as described in the documentation for
 * the {@link BtcFormat.Builder} class.</p>
 *
 * <p>A more detailed explanation, including examples, is in the documentation for the
 * {@link BtcFormat} class, and further information beyond that is in the documentation for the
 * {@link Format} class, from which this class descends.</p>

 * @see Format
 * @see NumberFormat
 * @see DecimalFormat
 * @see Coin
 */

public final class BtcFixedFormat extends BtcFormat {

    /** A constant specifying the use of as many optional decimal places in the fraction part
     * of a formatted number as are useful for expressing precision.  This value can be passed
     * as the final argument to a factory method or {@link #format(Object, int, int...)}.
     */
    public static final int[] REPEATING_PLACES   = {1,1,1,1,1,1,1,1,1,1,1,1,1,1};

    /** A constant specifying the use of as many optional groups of <strong>two</strong>
     * decimal places in the fraction part of a formatted number as are useful for expressing
     * precision.  This value can be passed as the final argument to a factory method or
     * {@link #format(Object, int, int...)}. */
    public static final int[] REPEATING_DOUBLETS = {2,2,2,2,2,2,2};

    /** A constant specifying the use of as many optional groups of <strong>three</strong>
     * decimal places in the fraction part of a formatted number as are useful for expressing
     * precision. This value can be passed as the final argument to a factory method or
     * {@link #format(Object, int, int...)}. */
    public static final int[] REPEATING_TRIPLETS = {3,3,3,3,3};

    /** The number of places the decimal point of formatted values is shifted rightward from
     *  the same value expressed in bitcoins. */
    private final int scale;

    /** Constructor */
    protected BtcFixedFormat(
        Locale locale, int scale, int minDecimals, List<Integer> groups
    ) {
        super((DecimalFormat)NumberFormat.getInstance(locale), minDecimals, groups);
        checkArgument(
            scale <= SMALLEST_UNIT_EXPONENT,
            "decimal cannot be shifted " + String.valueOf(scale) + " places"
        );
        this.scale = scale;
    }

    /** Return the decimal-place shift for this object's unit-denomination.  For example, if
     * the denomination is millibitcoins, this method will return the value {@code 3}.  As
     * a side-effect, prefixes the currency signs of the underlying NumberFormat object.  This
     * method is invoked by the superclass when formatting.  The arguments are ignored because
     * the denomination is fixed regardless of the value being formatted.
     */
    @Override
    protected int scale(BigInteger satoshis, int fractionPlaces) {
        prefixUnitsIndicator(numberFormat, scale);
        return scale;
    }

    /** Return the decimal-place shift for this object's fixed unit-denomination.  For example, if
     *  the denomination is millibitcoins, this method will return the value {@code 3}.  */
    @Override
    public int scale() { return scale; }

    /**
     * Return the currency code that identifies the units in which values formatted and
     * (by-default) parsed by this instance are denominated.  For example, if the formatter's
     * denomination is millibitcoins, then this method will return {@code "mBTC"},
     * assuming the default base currency-code is not overridden using a
     * {@link BtcFormat.Builder}.  */
    public String code() { return prefixCode(coinCode(), scale); }

    /**
     * Return the currency symbol that identifies the units in which values formatted by this
     * instance are denominated. For example, when invoked on an instance denominated in
     * millibitcoins, this method by default returns {@code "₥฿"}, depending on the
     * locale.  */
    public String symbol() { return prefixSymbol(coinSymbol(), scale); }

    /** Return the fractional decimal-placing used when formatting.  This method returns an
     *  {@code int} array.  The value of the first element is the minimum number of
     *  decimal places to be used in all cases, limited to a precision of satoshis.  The value
     *  of each successive element is the size of an optional place-group that will be applied,
     *  possibly partially, if useful for expressing precision.  The actual size of each group
     *  is limited to, and may be reduced to the limit of, a precision of no smaller than
     *  satoshis. */
    public int[] fractionPlaceGroups() {
        Object[] boxedArray = decimalGroups.toArray();
        int len = boxedArray.length + 1;
        int[] array = new int[len];
        array[0] = minimumFractionDigits;
        for (int i = 1; i < len; i++) { array[i] = (Integer) boxedArray[i-1]; }
        return array;
    }

    /** Return true if the given object is equivalent to this one.  Formatters for different
      * locales will never be equal, even if they behave identically. */
    @Override public boolean equals(Object o) {
        if (o == this) return true;
        if (!(o instanceof BtcFixedFormat)) return false;
        BtcFixedFormat other = (BtcFixedFormat)o;
        return super.equals(other) && other.scale() == scale() && other.decimalGroups.equals(decimalGroups);
    }

    /** Return a hash code value for this instance.
     *  @see java.lang.Object#hashCode
     */
    @Override public int hashCode() {
        return Objects.hash(super.hashCode(), scale);
    }

    private static String prefixLabel(int scale) {
        switch (scale) {
        case COIN_SCALE:      return "Coin-";
        case 1:               return "Decicoin-";
        case 2:               return "Centicoin-";
        case MILLICOIN_SCALE: return "Millicoin-";
        case MICROCOIN_SCALE: return "Microcoin-";
        case -1:              return "Dekacoin-";
        case -2:              return "Hectocoin-";
        case -3:              return "Kilocoin-";
        case -6:              return "Megacoin-";
        default: return "Fixed (" + String.valueOf(scale) + ") ";
        }
    }

    /**
     * Returns a brief description of this formatter. The exact details of the representation
     * are unspecified and subject to change, but will include some representation of the
     * formatting/parsing pattern and the fractional decimal place grouping.
     */
    @Override
    public String toString() {
        return prefixLabel(scale) + "format " + pattern();
    }

}
