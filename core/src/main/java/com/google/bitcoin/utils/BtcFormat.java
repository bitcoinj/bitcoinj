/**
 * Placed in the public domain by the author Adam Mackler
 * Use at your own risk.
 */

package com.google.bitcoin.utils;

import com.google.bitcoin.core.Coin;

import java.math.BigDecimal;
import java.math.BigInteger;
import static java.math.BigInteger.ZERO;

import java.text.AttributedCharacterIterator;
import java.text.DecimalFormat;
import java.text.DecimalFormatSymbols;
import java.text.FieldPosition;
import java.text.Format;
import java.text.NumberFormat;
import java.text.ParsePosition;
import java.text.ParseException;

import java.util.Locale;
import java.util.regex.Pattern;
import java.util.regex.Matcher;

/**
 * Instances of this class format and parse locale-specific numerical
 * representations of Bitcoin monetary values.  Denominational units
 * are indicated by a currency symbol or code, and the choice of units
 * used when formatting will depend on the value being represented,
 * chosen so as to minimize the number of zeros displayed without
 * losing precision.  For example, depending on the locale, a value of
 * one bitcoin might be formatted as <code>&#x0E3F;1.00</code>, while
 * a value greater than that by one satoshi would be
 * <code>&#xB5;&#x0E3F;1,000,000.01</code>.
 *
 * <p>There are two formatting styles,
 * <code>SYMBOLIC</code> (the default), and <code>CODED</code>.  The
 * difference is that the <code>SYMBOLIC</code> style uses currency
 * symbols, such as <code>&#x0E3F;</code>, while
 * <code>CODED</code> uses currency codes, such as <code>BTC</code>.
 *
 * <p>To obtain a <code>BtcFormat</code> instance for the desired
 * locale and formatting style, call one of the factory methods, such
 * as <code>getInstance()</code>.  For example:
 * <blockquote><pre>
 * BtcFormat bf = BtcFormat.getInstance(Locale.GERMANY);
 * System.out.print(bf.format(Coin.COIN)); <strong>// prints "1,00 &#x0E3F;"</strong>
 * </pre></blockquote>
 *
 *
 * <p>Bitcoin monetary values can be passed as an argument to the
 * <code>format()</code> method as either a {@link Coin} object
 * or a numerical object such as <code>Long</code> or
 * <code>BigDecimal</code>.  Integer-based types such as
 * <code>BigInteger</code> are interpreted as representing a number of
 * satoshis.  Types that can represent fractional amounts, such as
 * <code>Double</code> are interpreted as representing a number of
 * bitcoins.  A value having a fractional amount of satoshis is
 * rounded to the nearest whole satoshi.  The <code>format()</code>
 * method will not accept <code>String</code>-type arguments.
 *
 * <p>If the denominational units are bitcoins or millicoins, then the
 * formatted number will have two decimal places, even if both hold
 * zero.  If the units are microcoins, then decimal places will be
 * displayed only if necessary, and then always two places, even if
 * the last holds a zero.
 *
 * <p>When formatting, you might want to know what denomination was
 * chosen.  You can get the currency-units indicator, as well as any other
 * field in the formatted output, by using a
 * <code>FieldPosition</code> instance constructed using an appropriate
 * constant from the {@link NumberFormat.Field} class:
 *
 * <blockquote><pre>
 * BtcFormat de = BtcFormat.getCodedInstance(Locale.GERMANY);
 * FieldPosition currField = new FieldPosition(NumberFormat.Field.CURRENCY);
 * <strong>// output will be "987.654.321,23 &#xB5;BTC"</strong>
 * String output = de.format(valueOf(98765432123L), new StringBuffer(), currField);
 * <strong>// currencyCode will be "&#xB5;BTC"</strong>
 * String currencyCode = output.substring(currField.getBeginIndex(), currField.getEndIndex()));
 * </pre></blockquote>

 * <h4>Parsing</h4>
 *
 * <p>The <code>parseObject()</code> method will recognize a variety
 * of currency symbols and codes.  For example, denominational units
 * of microcoins may be specified using <code>&#xB5;&#x0E3F;</code>,
 * <code>u&#x0E3F;</code>, <code>&#xB5;&#x0243;</code>,
 * <code>&#xB5;BTC</code> or other appropriate permutations of those
 * characters.  Both currency symbols and codes are recognized,
 * regardless of whether the <code>BtcFormat</code> instance is of
 * style <code>SYMBOLIC</code> or <code>CODED</code>.  However, if the
 * style is <code>CODED</code> then a space character must separate
 * the units indicator from the number.  When parsing with a
 * <code>SYMBOLIC</code>-style <code>BtcFormat</code> instance, on the
 * other hand, whether or not the units indicator must be separated by
 * a space from the number is determined by the locale.
 *
 * <p>When parsing, if the currency-units indicator is absent, then an
 * indicator of bitcoins is implied.  Note: if the locale or style
 * requires a space to separate the number from the units indicator,
 * that space must be present in the String to be parsed, even if the
 * units indicator is absent.
 *
 * <p>The <code>parseObject()</code> method returns an instance of the
 * {@link Coin} class.  Therefore, attempting to parse a value
 * greater than the maximum that a <code>Coin</code> object can represent
 * will raise a <code>ParseException</code>, as will any other parsing
 * error.
 *
 * <h4>Synchronization</h4>
 *
 * <p>This class is not thread-safe.  It is recommended to create
 * separate instances for each thread.  If multiple threads access a
 * instance concurrently, it must be synchronized externally.
 *
 * @see          Format
 * @see          CoinFormat
 */

public class BtcFormat extends Format {

    private DecimalFormat numberFormat;
    private final DecimalFormatSymbols formatSymbols;
    private final String coinSymbol;

    private BtcFormat(DecimalFormat numberFormat) {
	this.numberFormat = numberFormat;
	formatSymbols = this.numberFormat.getDecimalFormatSymbols();
        String localeSymbol = formatSymbols.getCurrencySymbol();
        if (localeSymbol.contains("฿"))
            if (localeSymbol.contains("Ƀ"))
                coinSymbol = "BTC";
            else coinSymbol = "Ƀ";
        else coinSymbol = "฿";
    }

    /**
     * Returns an instance for the default locale that will indicate
     * denominational units using a currency symbol, for example,
     * <code>&#x0E3F;</code>.
     */
    public static BtcFormat getInstance() {
	return getInstance(Locale.getDefault(Locale.Category.FORMAT));
    }

    /**
     * Returns an instance for the default locale that will indicate
     * denominational units using a currency code, for example,
     * <code>BTC</code>.
     */
    public static BtcFormat getCodedInstance() {
	return getInstance(CODED, Locale.getDefault(Locale.Category.FORMAT));
    }

    /**
     * Returns an instance for the specified locale that will indicate
     * denominational units using a currency symbol, for example,
     * <code>&#x0E3F;</code>.
     */
    public static BtcFormat getInstance(Locale locale) {
	return getInstance(SYMBOLIC, locale);
    }

    /**
     * Returns an instance for the specified locale that will indicate
     * denominational units using a currency code, for example,
     * <code>BTC</code>.
     */
    public static BtcFormat getCodedInstance(Locale locale) {
	return getInstance(CODED, locale);
    }

    /**
     * Returns an instance for the default locale that will indicate
     * denominational units using either a currency symbol or currency
     * code according to the style specified.
     */
    public static BtcFormat getInstance(int style) {
	return getInstance(style, Locale.getDefault(Locale.Category.FORMAT));
    }

    /**
     * Gets the Bitcoin value formatter with the given formatting style for the given locale.
     * @param style the given formatting style. For example, CODED for "BTC1.00" in the US locale.
     * @param aLocale the given locale.
     * @return a Bitcoin value amount formatter.
     */
    public static BtcFormat getInstance(int style, Locale locale) {
	DecimalFormat f = (DecimalFormat) NumberFormat.getCurrencyInstance(locale);
        String p = f.toLocalizedPattern();
        if (style == SYMBOLIC) {
            p = p.replaceAll("¤¤","¤");
            f.applyLocalizedPattern(p);
        } else if (style == CODED) {
            // If necessary, add a space between the currency code and number
            p = p.replaceAll("¤","¤¤").replaceAll("([#0-])¤¤","$1 ¤¤").replaceAll("¤¤([0#-])","¤¤ $1");
        }
        f.applyLocalizedPattern(p);
	return new BtcFormat(f);
    }

    /**
     * Constant for formatting style using currency code, e.g., "BTC".
     */
    public static final int CODED = 0;

    /**
     * Constant for formatting style using currency symbol, e.g., "&#x0E3F;".
     */
    public static final int SYMBOLIC = 1;

    // Keep these around to avoid object re-creation when this formatter is reused
    private BigInteger satScale = BigInteger.valueOf(100);
    private BigInteger micScale = BigInteger.valueOf(1000);
    private BigInteger milScale = BigInteger.valueOf(1000000);

    /**
     * Formats a bitcoin value as a number and units indicator and
     * appends the resulting text to the given string buffer.  The
     * type of monetary value argument can be of any of the following
     * classes: <code>{@link Coin}</code>, <code>Integer</code>,
     * <code>Long</code>, <code>BigInteger</code>,
     * <code>BigDecimal</code>, <code>Double</code>,
     * <code>Float</code>.  Types that can represent only integers are
     * interpreted as representing a number of satoshis.  Types that
     * can represent fractional amounts are interpreted as
     * representing a number of bitcoins.  Fractional amounts are
     * rounded to the nearest satoshi as necessary.
     * @return  the <code>StringBuffer</code> passed in as <code>toAppendTo</code>
     */
    public StringBuffer format(Object qty, StringBuffer toAppendTo, FieldPosition pos) {
	return numberFormat.format(denominate(qty), toAppendTo, pos);
    }

    /**
     * This is where we examine a bitcoin monetary value that the
     * client wants to format in order to determine what
     * denominational units to use.  Then we scale the number
     * accordingly and set the currency symbol and code in the
     * NumberFormatter that does the actual work of formatting. */
    private BigDecimal denominate(Object qty) {
	BigInteger satoshis;
        // the value might be bitcoins or satoshis
	if (qty instanceof Long || qty instanceof Integer)
	    satoshis = BigInteger.valueOf(((Number)qty).longValue());
	else if (qty instanceof BigInteger)
	    satoshis = (BigInteger)qty;
	else if (qty instanceof BigDecimal)
	    satoshis = ((BigDecimal)qty).movePointRight(Coin.NUM_COIN_DECIMALS).
                       setScale(0,BigDecimal.ROUND_HALF_UP).unscaledValue();
	else if (qty instanceof Double || qty instanceof Float) {
            return denominate(BigDecimal.valueOf((Double)qty));
	} else if (qty instanceof Coin)
	    satoshis = BigInteger.valueOf(((Coin)qty).value);
	else
	    throw new IllegalArgumentException("Cannot format a " + qty.getClass().getSimpleName() +
                                               " as a Bicoin value");

        /* Now the value of  `satoshis` is the number of base units in the
         * value to be formatted.  Next, determine which denomination to use. */
        BigDecimal denominated; // number of denominated units to be formatted
        if (satoshis.remainder(micScale).compareTo(ZERO) != 0) { // denominate in µBTC
            denominated = new java.math.BigDecimal(satoshis).movePointLeft(Coin.NUM_COIN_DECIMALS-6);
            formatSymbols.setCurrencySymbol("µ" + coinSymbol);
            formatSymbols.setInternationalCurrencySymbol("µBTC");
            numberFormat.setDecimalFormatSymbols(formatSymbols);
            if (satoshis.remainder(satScale).compareTo(ZERO) != 0) { // show satoshi units
                numberFormat.setMinimumFractionDigits(2);
                numberFormat.setMaximumFractionDigits(2);
            } else {
                numberFormat.setMinimumFractionDigits(0);
                numberFormat.setMaximumFractionDigits(0);
            }
        } else if (satoshis.remainder(milScale).compareTo(ZERO) != 0) { // denominate in mBTC
            denominated = new java.math.BigDecimal(satoshis).movePointLeft(Coin.NUM_COIN_DECIMALS-3);
            formatSymbols.setCurrencySymbol("₥" + coinSymbol);
            formatSymbols.setInternationalCurrencySymbol("mBTC");
            numberFormat.setDecimalFormatSymbols(formatSymbols);
            numberFormat.setMinimumFractionDigits(2);
            numberFormat.setMaximumFractionDigits(2);
        } else { // denominate in BTC
            denominated = new java.math.BigDecimal(satoshis).movePointLeft(Coin.NUM_COIN_DECIMALS);
            formatSymbols.setCurrencySymbol(coinSymbol);
            formatSymbols.setInternationalCurrencySymbol("BTC");
            numberFormat.setDecimalFormatSymbols(formatSymbols);
            numberFormat.setMinimumFractionDigits(2);
            numberFormat.setMaximumFractionDigits(2);
        }

	return denominated;
    }

    /**
     * Formats a bitcoin monetary value and returns an
     * <code>AttributedCharacterIterator</code>.  By iterating, you
     * can examine what fields apply to each character.  This can be
     * useful since a character may be part of more than one field,
     * for example a grouping separator that is also part of the
     * integer field.
     *
     *  <p>For details, see the documentation for the
     * {@link AttributedCharacterIterator} class.
     */
    public AttributedCharacterIterator formatToCharacterIterator(Object obj) {
	return numberFormat.formatToCharacterIterator(denominate(obj));
    }

    private Pattern microPat = Pattern.compile("([µu](฿|Ƀ|BTC))");
    private Pattern milliPat = Pattern.compile("₥(฿|Ƀ|BTC)?|m(฿|Ƀ|BTC)");
    private Pattern coinPat = Pattern.compile("(฿|Ƀ|BTC)?");
    private void setSymbolAndCode(String s) {
        formatSymbols.setCurrencySymbol(s);
        formatSymbols.setInternationalCurrencySymbol(s);
        numberFormat.setDecimalFormatSymbols(formatSymbols);
    }

    /**
     * Parses a String representing a bitcoin monetary value, using
     * the given <code>ParsePosition</code> object.  Consider using
     * the singe-argument version of this overloaded method,
     * {@link parseObject(String)}.
     */
    public Object parseObject(String source, ParsePosition pos) {
        int scale = 100000000; // default: coins
        Matcher matcher = microPat.matcher(source);
        if (matcher.find()) { // microcoins
            setSymbolAndCode(matcher.group());
            scale = 100;
        } else {
            matcher = milliPat.matcher(source);
            if (matcher.find()) { // millicoins
                setSymbolAndCode(matcher.group());
                scale = 100000;
            } else { // bitcoins
                matcher = coinPat.matcher(source);
                matcher.find();
                setSymbolAndCode(matcher.group());
            }
        }
        Number number = numberFormat.parse(source, pos);
        if (number != null) {
            try {
                if (number instanceof Long)
                    return Coin.valueOf(((Long)number).longValue() * scale);
                else
                    return Coin.valueOf(Math.round(((Double)number).doubleValue() * scale));
            } catch (IllegalArgumentException e) {
                pos.setIndex(0);
                return null;
            }
        } else {
            pos.setIndex(0);
            return null;
        }
    }

    /**
     * Returns an array of all locales for which the getInstance()
     * method of this class can return localized instances.  See
     * {@link java.text.NumberFormat#getAvailableLocales()}
     */
    public static Locale[] getAvailableLocales() { return NumberFormat.getAvailableLocales(); }

    /**
     * Gets the number formatter which this formatter uses to
     * format and parse Bitcoin quantity values.
     * @return the number formatter which this date/time formatter uses.
     */
    public NumberFormat getNumberFormat() { return numberFormat; }

}
