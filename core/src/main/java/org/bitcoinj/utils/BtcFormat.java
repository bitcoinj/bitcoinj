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

import org.bitcoinj.utils.BtcAutoFormat.Style;
import static org.bitcoinj.utils.BtcAutoFormat.Style.*;

import org.bitcoinj.core.Coin;
import com.google.common.collect.ImmutableList;
import static com.google.common.base.Preconditions.checkArgument;
import com.google.common.base.Strings;

import java.math.BigDecimal;
import java.math.BigInteger;

import static java.math.RoundingMode.HALF_UP;

import java.text.AttributedCharacterIterator;
import java.text.DecimalFormat;
import java.text.DecimalFormatSymbols;
import java.text.FieldPosition;
import java.text.Format;
import java.text.NumberFormat;
import java.text.ParseException;
import java.text.ParsePosition;

import java.util.Locale;
import java.util.List;
import java.util.ArrayList;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * <p>Instances of this class format and parse locale-specific numerical
 * representations of Bitcoin monetary values.
 *
 * <p>A primary goal of this class is to minimize the danger of
 * human-misreading of monetary values due to mis-counting the number
 * of zeros (or, more generally, of decimal places) in the number that
 * represents a Bitcoin monetary value.  Some of the features offered for doing this
 * are: <ol>
 *   <li>automatic adjustment of denominational units in which a
 *       value is represented so as to lessen the number of adjacent zeros,
 *   <li>use of locale-specific decimal-separators to group digits in
 *       the integer portion of formatted numbers,
 *   <li>fine control over the number and  grouping of fractional decimal places, and
 *   <li>access to character information that allows for vertical
 *       alignment of tabular columns of formatted values.</ol>
 *
 * <h3>Basic Usage</h3>
 *
 * Basic usage is very simple: <ol>
 *   <li>Construct a new formatter object using one of the factory methods. 
 *   <li>Format a value by passing it as an argument to the
 *       {@link BtcFormat#format(Object)} method. 
 *   <li>Parse a value by passing a <code>String</code>-type
 *       representation of it to the {@link BtcFormat#parse(String)} method.</ol>
 *
 * <p>For example, depending on your locale, values might be formatted
 * and parsed as follows:
 *
 * <blockquote><pre>
 * BtcFormat f = BtcFormat.getInstance();
 * String c = f.format(Coin.COIN);                <strong>// "BTC 1.00"</strong>
 * String k = f.format(Coin.COIN.multiply(1000)); <strong>// "BTC 1,000.00"</strong>
 * String m = f.format(Coin.COIN.divide(1000));   <strong>// "mBTC 1.00"</strong>
 * Coin all = f.parseObject("M฿ 21");             <strong>// All the money in the world</strong>
 * </pre></blockquote>
 *
 * <h3>Auto-Denomination versus Fixed-Denomination</h3>
 *
 * There are two provided concrete classes, one that automatically denominates values to
 * be formatted, {@link BtcAutoFormat}, and another that formats any value in units of a
 * fixed, specified denomination, {@link BtcFixedFormat}.  
 *
 * <h5>Automatic Denomination</h5>
 *
 * Automatic denomination means that the formatter adjusts the denominational units in which a
 * formatted number is expressed based on the monetary value that number represents.  An
 * auto-denominating formatter is defined by its style, specified by one of the enumerated
 * values of {@link BtcAutoFormat.Style}.  There are two styles constants: {@link
 * BtcAutoFormat.Style#CODE} (the default), and {@link BtcAutoFormat.Style#SYMBOL}.  The
 * difference is that the <code>CODE</code> style uses an internationally-distinct currency
 * code, such as <code>"BTC"</code>, to indicate the units of denomination, while the
 * <code>SYMBOL</code> style uses a possibly-ambiguous currency symbol such as
 * <code>"฿"</code>.
 *
 * <p>The denomination used when formatting will be either bitcoin, millicoin
 * or microcoin, depending on the value being represented, chosen so as to minimize the number
 * of consecutive zeros displayed without losing precision.  For example, depending on the
 * locale, a value of one bitcoin might be formatted as <pre>฿1.00</pre> where a value
 * exceeding that by one satoshi would be <pre>µ฿1,000,000.01</pre>
 *
 * <h5>Fixed Denomination</h5>
 * 
 * Fixed denomination means that the same denomination of units is used for every value that is
 * formatted or parsed by a given formatter instance.  A fixed-denomination formatter is
 * defined by its scale, which is the number of places one must shift the decimal point in
 * increasing precision to convert the representation of a given quantity of bitcoins into a
 * representation of the same value denominated in the formatter's units.  For example, a scale
 * value of <code>3</code> specifies a denomination of millibitcoins, because to represent
 * <code>1.0000 BTC</code>, or one bitcoin, in millibitcoins, one shifts the decimal point
 * three places, that is, to <code>1000.0 mBTC</code>.
 *
 * <h3>Construction</h3>
 *
 * There are two ways to obtain an instance of this class: <ol>
 *   <li>Use one of the factory methods; or
 *   <li>Use a {@link BtcFormat.Builder} object.</ol>
 *
 * <p>The factory methods are appropriate for basic use where the default
 * configuration is either used or modified.  The <code>Builder</code>
 * class provides more control over the configuration, and gives
 * access to some features not available through the factory methods,
 * such as using custom formatting patterns and currency symbols.
 *
 * <h5>Factory Methods</h5>
 *
 * Although formatting and parsing is performed by one of the concrete
 * subclasses, you can obtain formatters using the various static factory
 * methods of this abstract base class <code>BtcFormat</code>.  There
 * are a variety of overloaded methods that allow you to obtain a
 * formatter that behaves according to your needs.
 *
 * <p>The primary distinction is between automatic- and
 * fixed-denomination formatters.  By default, the
 * <code>getInstance()</code> method with no arguments returns a new,
 * automatic-denominating <code>BtcAutoFormat</code> instance for your
 * default locale that will display exactly two fractional decimal
 * places and a currency code.  For example, if you happen to be in
 * the USA:
 *
 * <blockquote><pre>
 * BtcFormat f = BtcFormat.getInstance();
 * String s = f.format(Coin.COIN); <strong>// "BTC 1.00"</strong>
 * </pre></blockquote>
 *
 * <p>The first argument to <code>getInstance()</code> can determine
 * whether you get an auto- or fixed-denominating formatter.  If the
 * type of the first argument is an <code>int</code>, then the value
 * of that <code>int</code> will be interpreted as the decimal-place scale of
 * the {@link BtcFixedFormat} instance that is returned, and thus will
 * determine its denomination.  For example, if you want to format
 * values in units of microbitcoins:
 *
 * <blockquote><pre>BtcFormat m = BtcFormat.getInstance(6);
 *String s = m.format(Coin.COIN); <strong>// "1,000,000.00"</strong>
 * </blockquote>
 *
 * <p>This class provides several constants bound to common scale values:
 *
 * <blockquote><pre>BtcFormat milliFormat = BtcFormat.getInstance(MILLICOIN_SCALE);</pre></blockquote>
 *
 * <p>Alternatively, if the type of the first argument to
 * <code>getInstance()</code> is one of the enumerated values of the
 * {@link BtcAutoFormat.Style} type, either <code>CODE</code> or
 * <code>SYMBOL</code>, then you will get a {@link BtcAutoFormat}
 * instance that uses either a currency code or symbol, respectively,
 * to indicate the results of its auto-denomination.
 *
 * <blockquote><pre>
 * BtcFormat s = BtcFormat.getInstance(SYMBOL);
 * Coin value = Coin.parseCoin("0.1234");
 * String mil = s.format(value);              <strong>// "₥฿123.40"</strong>
 * String mic = s.format(value.divide(1000)); <strong>// "µ฿123.40"</strong>
 * </blockquote>
 *
 * <p>An alternative way to specify whether you want an auto- or fixed-denomination formatter
 * is to use one of the factory methods that is named to indicate that characteristics of the
 * new instance returned.  For fixed-denomination formatters, these methods are {@link
 * #getCoinInstance()}, {@link #getMilliInstance()}, and {@link #getMicroInstance()}.  These
 * three methods are equivalent to invoking <code>getInstance()</code> with a first argument of
 * <code>0</code>, <code>3</code> and <code>6</code>, respectively.  For auto-denominating
 * formatters the relevant factory methods are {@link #getCodeInstance()} and {@link
 * #getSymbolInstance()}, which are equivalent to <code>getInstance(Style.CODE)</code>, and
 * <code>getInstance(Style.SYMBOL)</code>.
 *
 * <p>Regardless of how you specify whether your new formatter is to be of automatic- or
 * fixed-denomination, the next (and possibly first) parameter to each of the factory methods
 * is an optional <code>Locale</code> value.
 *
 * For example, here we construct four instances for the same locale that each format
 * differently the same one-bitcoin value:
 *
 * <blockquote><pre>
 * <strong>// Next line returns "1,00 BTC"</strong>
 * BtcFormat.getInstance(Locale.GERMANY).format(Coin.COIN);
 * <strong>// Next line returns "1,00 ฿"</strong>
 * BtcFormat.getInstance(SYMBOL, Locale.GERMANY).format(Coin.COIN);
 * <strong>// Next line returns "1.000,00"</strong>
 * BtcFormat.getMilliInstance(Locale.GERMANY).format(Coin.COIN);
 * <strong>// Next line returns "10.000,00"</strong>
 * BtcFormat.getInstance(4, Locale.GERMANY).format(Coin.COIN);
 * </pre></blockquote>
 *
 * Omitting such a <code>Locale</code> parameter will give you a
 * formatter for your default locale.
 *
 * <p>The final (and possibly only) arguments to the factory methods serve to set the default
 * number of fractional decimal places that will be displayed when formatting monetary values.
 * In the case of an auto-denominating formatter, this can be a single <code>int</code> value,
 * which will determine the number of fractional decimal places to be used in all cases, except
 * where either (1) doing so would provide a place for fractional satoshis, or (2) that default
 * value is overridden when invoking the <code>format()</code> method as described below.
 *
 * <p>In the case of a fixed-denomination formatter, you can pass any number of
 * <code>int</code> values.  The first will determine the minimum number of fractional decimal
 * places, and each following <code>int</code> value specifies the size of an optional group of
 * decimal-places to be displayed only if useful for expressing precision.  As with auto-denominating
 * formatters, numbers will never be formatted with a decimal place that represents a
 * fractional quantity of satoshis, and these defaults can be overridden by arguments to the
 * <code>format()</code> method.  See below for examples.
 *
 * <h5>The <code>Builder</code> Class</h5>
 *
 * A new {@link BtcFormat.Builder} instance is returned by the {@link #builder()} method.  Such
 * an object has methods that set the configuration parameters of a <code>BtcFormat</code>
 * object.  Its {@link Builder#build()} method constructs and returns a <code>BtcFormat</code> instance
 * configured according to those settings.
 *
 * <p>In addition to setter-methods that correspond to the factory-method parameters explained
 * above, a <code>Builder</code> also allows you to specify custom formatting and parsing
 * patterns and currency symbols and codes.  For example, rather than using the default
 * currency symbol, which has the same unicode character point as the national currency symbol of
 * Thailand, some people prefer to use a capital letter "B" with a vertical overstrike.
 *
 * <blockquote><pre>
 * BtcFormat.Builder builder = BtcFormat.builder();
 * builder.style(SYMBOL);
 * builder.symbol("B&#x5c;u20e6"); <strong>// unicode char "double vertical stroke overlay"</strong>
 * BtcFormat f = builder.build();
 * String out = f.format(COIN); <strong>// "B⃦1.00" depending on locale</strong>
 * </pre></blockquote>
 *
 * The <code>Builder</code> methods are chainable.  So, for example, if you are
 * deferential to ISO 4217, you might construct a formatter in a single line this way:
 *
 * <blockquote><pre>
 * BtcFormat f = BtcFormat.builder().style(CODE).code("XBT").build();
 * String out = f.format(COIN); <strong>// "XBT 1.00"</strong>
 * </pre></blockquote>
 *
 * <p>See the documentation of the {@link BtcFormat.Builder} class for details.
 *
 * <h3>Formatting</h3>
 *
 * <p>You format a Bitcoin monetary value by passing it to the {@link BtcFormat#format(Object)}
 * method.  This argument can be either a {@link org.bitcoinj.core.Coin}-type object or a
 * numerical object such as {@link java.lang.Long} or {@link java.math.BigDecimal}.
 * Integer-based types such as {@link java.math.BigInteger} are interpreted as representing a
 * number of satoshis, while a {@link java.math.BigDecimal} is interpreted as representing a
 * number of bitcoins.  A value having a fractional amount of satoshis is rounded to the
 * nearest whole satoshi at least, and possibly to a greater unit depending on the number of
 * fractional decimal-places displayed.  The <code>format()</code> method will not accept an
 * argument whose type is <code>String</code>, <code>Float</code> nor <code>Double</code>.
 *
 * <p>Subsequent to the monetary value to be formatted, the {@link #format(Object)} method also
 * accepts as arguments optional <code>int</code> values that specify the number of decimal
 * places to use to represent the fractional portion of the number.  This overrides the
 * default, and enables a single formatter instance to be reused, formatting different values
 * that require different numbers of fractional decimal places.  These parameters have the same
 * meaning as those that set the default values in the factory methods as described above.
 * Namely, a single <code>int</code> value determines the minimum number of fractional decimal
 * places that will be used in all cases, to a precision limit of satoshis.  Instances of
 * {@link BtcFixedFormat} also accept a variable-length sequence of additional <code>int</code>
 * values, each of which specifies the size of a group of fractional decimal-places to be used
 * in addition to all preceding places, only if useful to express precision, and only to a
 * maximum precision of satoshis.  For example:
 *
 * <blockquote><pre>
 * BtcFormat f = BtcFormat.getCoinInstance();
 * Coin value = COIN.add(Coin.valueOf(5)); <strong>// 100000005 satoshis</strong>
 * f.format(value, 2);       <strong>// "1.00"</strong>
 * f.format(value, 3);       <strong>// "1.000"</strong>
 * f.format(value, 2, 3);    <strong>// "1.00" three more zeros doesn't help </strong>
 * f.format(value, 2, 3, 3); <strong>// "1.00000005" </strong>
 * f.format(value, 2, 3, 4); <strong>// "1.00000005" fractions of satoshis have no place</strong>
 * f.format(value, 2, 3, 2); <strong>// "1.0000001" rounds to nearest usable place</strong>
 * </pre></blockquote>
 *
 * <p>Note that if using all the fractional decimal places in a specified group would give a
 * place to fractions of satoshis, then the size of that group will be reduced to a maximum
 * precision of satoshis.  Either all or none of the allowed decimal places of that group will
 * still be applied as doing so is useful for expressing the precision of the value being
 * formatted.
 *
 * <p>Several convenient constants of repeating group-size sequences are provided:
 * {@link BtcFixedFormat#REPEATING_PLACES}, {@link
 * BtcFixedFormat#REPEATING_DOUBLETS} and {@link
 * BtcFixedFormat#REPEATING_TRIPLETS}.  These signify repeating groups
 * of one, two and three decimals places, respectively.  For example,
 * to display only as many fractional places as useful in order to
 * prevent hanging zeros on the least-significant end of formatted
 * numbers:
 *
 * <blockquote><pre>
 * format(value, 0, REPEATING_PLACES);
 * </pre></blockquote>
 *
 * <p>When using an automatically-denominating formatter, you might
 * want to know what denomination was chosen.  You can get the
 * currency-units indicator, as well as any other field in the
 * formatted output, by using a {@link java.text.FieldPosition} instance
 * constructed using an appropriate constant from the {@link
 * java.text.NumberFormat.Field} class:
 *
 * <blockquote><pre>
 * BtcFormat de = BtcFormat.getInstance(Locale.GERMANY);
 * FieldPosition currField = new FieldPosition(NumberFormat.Field.CURRENCY);
 * <strong>// next line formats the value as "987.654.321,23 µBTC"</strong>
 * String output = de.format(valueOf(98765432123L), new StringBuffer(), currField);
 * <strong>// next line sets variable currencyCode to "µBTC"</strong>
 * String currencyCode = output.substring(currField.getBeginIndex(), currField.getEndIndex()));
 * </pre></blockquote>
 *
 * <p>When using a fixed-denomination formatter whose scale can be expressed as a standard
 * "metric" prefix, you can invoke the <code>code()</code> and <code>symbol()</code> methods to
 * obtain a <code>String</code> whose value is the appropriate currency code or symbol,
 * respectively, for that formatter.
 *
 * <blockquote><pre>
 * BtcFixedFormat kilo = (BtcFixedFormat)BtcFormat(-3); <strong>// scale -3 for kilocoins</strong>
 * Coin value = Coin.parseCoin("1230");
 * <strong>// variable coded will be set to "kBTC 1.23"</strong>
 * String coded = kilo.code() + " " + kilo.format(value);
 * <strong>// variable symbolic will be set to "k฿1.23"</strong>
 * String symbolic = kilo.symbol() + kilo.format(value);
 * BtcFormat(4).code(); <strong>// unnamed denomination has no code; raises exception</strong>
 * </pre></blockquote>
 *
 * <h5>Formatting for Tabular Columns</h5>
 *
 * When displaying tables of monetary values, you can lessen the
 * risk of human misreading-error by vertically aligning the decimal
 * separator of those values.  This example demonstrates one way to do that:
 *
 * <blockquote><pre>
 * <strong>// The elements of this array are the values we will format:</strong>
 * Coin[] rows = {MAX_MONEY, MAX_MONEY.subtract(SATOSHI), Coin.parseCoin("1234"),
 *                COIN, COIN.divide(1000),
 *                valueOf(10000), valueOf(1000), valueOf(100),
 *                SATOSHI};
 * BtcFormat f = BtcFormat.getCoinInstance(2, REPEATING_PLACES);
 * FieldPosition fp = new FieldPosition(DECIMAL_SEPARATOR); <strong>// see java.text.NumberFormat.Field</strong>
 * String[] output = new String[rows.length];
 * int[] indexes = new int[rows.length];
 * int maxIndex = 0;
 * for (int i = 0; i < rows.length; i++) {
 *     output[i] = f.format(rows[i], new StringBuffer(), fp).toString();
 *     indexes[i] = fp.getBeginIndex();
 *     if (indexes[i] > maxIndex) maxIndex = indexes[i];
 * }
 * for (int i = 0; i < output.length; i++) {
 *     System.out.println(repeat(" ", (maxIndex - indexes[i])) + output[i]);
 * }
 * </pre></blockquote>
 *
 * Assuming you are using a monospaced font, and depending on your
 * locale, the foregoing will print the following:
 *
 * <blockquote><pre>
 * 21,000,000.00
 * 20,999,999.99999999
 *      1,234.00
 *          1.00
 *          0.001
 *          0.0001
 *          0.00001
 *          0.000001
 *          0.00000001
 * </pre></blockquote>
 *
 * If you need to vertically-align columns printed in a proportional font,
 * then see the documentation for the {@link java.text.NumberFormat} class
 * for an explanation of how to do that.
 *
 * <h3>Parsing</h3>
 *
 * <p>The {@link #parse(String)} method accepts a <code>String</code> argument, and returns a
 * {@link Coin}-type value.  The difference in parsing behavior between instances of {@link
 * BtcFixedFormat} and {@link BtcAutoFormat} is analogous to the difference in formatting
 * behavior between instances of those classes.  Instances of {@link BtcAutoFormat} recognize
 * currency codes and symbols in the <code>String</code> being parsed, and interpret them as
 * indicators of the units in which the number being parsed is denominated.  On the other hand,
 * instances of {@link BtcFixedFormat} by default recognize no codes nor symbols, but rather
 * interpret every number as being denominated in the units that were specified when
 * constructing the instance doing the parsing.  This default behavior of {@link
 * BtcFixedFormat} can be overridden by setting a parsing pattern that includes a currency sign
 * using the {@link BtcFormat.Builder#pattern()} method.
 *
 * <p>The {@link BtcAutoFormat#parse(String)}</code> method of {@link BtcAutoFormat} (and of
 * {@link BtcAutoFormat} configured with applicable non-default pattern) will recognize a
 * variety of currency symbols and codes, including all standard international (metric)
 * prefixes from micro to mega.  For example, denominational units of microcoins may be
 * specified by <code>µ฿</code>, <code>u฿</code>, <code>µB⃦</code>, <code>µɃ</code>,
 * <code>µBTC</code> or other appropriate permutations of those characters.  Additionally, if
 * either or both of a custom currency code or symbol is configured using {@link
 * BtcFormat.Builder#code} or {@link BtcFormat.Builder#code}, then such code or symbol will
 * be recognized in addition to those recognized by default..
 *
 * <p>Instances of this class that recognize currency signs will recognize both currency
 * symbols and codes, regardless of which that instance uses for formatting.  However, if the
 * style is <code>CODE</code> (and unless overridden by a custom pattern) then a space character must
 * separate the units indicator from the number.  When parsing with a <code>SYMBOL</code>-style
 * <code>BtcFormat</code> instance, on the other hand, whether or not the units indicator must
 * be separated by a space from the number is determined by the locale.  The {@link
 * BtcFormat#pattern()} method returns a representation of the pattern that
 * can be examined to determine whether a space must separate currency signs from numbers in
 * parsed <code>String</code>s.
 *
 * <p>When parsing, if the currency-units indicator is absent, then a {@link BtcAutoFormat}
 * instance will infer a denomination of bitcoins while a {@link BtcFixedFormat} will infer the
 * denomination in which it expresses formatted values.  Note: by default (unless overridden by
 * a custom pattern), if the locale or style requires a space to separate the number from the
 * units indicator, that space must be present in the String to be parsed, even if the units
 * indicator is absent.
 *
 * <p>The <code>parse()</code> method returns an instance of the
 * {@link Coin} class.  Therefore, attempting to parse a value greater
 * than the maximum that a <code>Coin</code> object can represent will
 * raise a <code>ParseException</code>, as will any other detected
 * parsing error.
 *
 *  <h3>Limitations</h3>
 *
 *  <h5>Parsing</h5>
 *
 * Parsing is performed by an underlying {@link java.text.NumberFormat} object.  While this
 * delivers the benefit of recognizing locale-specific patterns, some have criticized other
 * aspects of its behavior.  For example, see <a
 * href="http://www.ibm.com/developerworks/library/j-numberformat/">this article by Joe Sam
 * Shirah</a>.  In particular, explicit positive-signs are not recognized.  If you are parsing
 * input from end-users, then you should consider whether you would benefit from any of the
 * work-arounds mentioned in that article.
 *
 * <h5>Exotic Locales</h5>
 *
 * This class is not well-tested in locales that use non-ascii
 * character sets, especially those where writing proceeds from
 * right-to-left.  Helpful feedback in that regard is appreciated.
 *
 * <h3>Thread-Safety</h3>
 *
 * <p>Instances of this class are immutable.
 *
 * @see          java.text.Format
 * @see          java.text.NumberFormat
 * @see          java.text.DecimalFormat
 * @see          java.text.DecimalFormatSymbols
 * @see          java.text.FieldPosition
 * @see          org.bitcoinj.core.Coin
 */

public abstract class BtcFormat extends Format {

    /* CONCURRENCY NOTES
     *
     * There is one mutable member of this class, the `DecimalFormat` object bound to variable
     * `numberFormat`.  The relevant methods invoked on it are: setMinimumFractionDigits(),
     * setMaximumFractionDigits(), and setDecimalFormatSymbols(), along with the respective
     * getter methods corresponding to each.  The first two methods are used to set the number
     * of fractional decimal places displayed when formatting, which is reflected in the
     * patterns returned by the public pattern() and localizedPattern() methods.  The last
     * method sets the value of that object's member `DecimalFormatSymbols` object for
     * formatting and parsing, which is also reflected in the aforementioned patterns.  The
     * patterns, which are the passed-through return values of the DecimalFormat object's
     * toPattern() and toLocalizedPattern() methods, and the value of the DecimalFormat
     * object's DecimalFormatSymbols member are among the values compared between instances of
     * this class in determining the return values of the `equals()` and `hashCode()` methods.
     *
     * From the foregoing, you can understand that immutability is achieved as follows: access
     * to the variable `numberFormat` referent's fraction-digits and format-symbols fields are
     * synchronized on that DecimalFormat object.  The state of those fraction-digits limits
     * and decimal-format symbols must be returned to a static state after being changed for
     * formatting or parsing since the user can see them reflected in the return values of
     * above-mentioned methods and because `equals()` and `hashCode()` use them for
     * comparisons.
     */

    /** The conventional international currency code for bitcoins: "BTC" */
    private static final String COIN_CODE = "BTC";
    /** The default currency symbols for bitcoins */
    private static final String COIN_SYMBOL = "฿";
    /** An alternative currency symbol to use in locales where the default symbol is used for the national currency. */
    protected static final String COIN_SYMBOL_ALT = "Ƀ";

    protected final DecimalFormat numberFormat; // warning: mutable
    protected final int minimumFractionDigits;
    protected final List<Integer> decimalGroups;

    /* Scale is the number of decimal-places difference from same value in bitcoins */
    /** A constant useful for specifying a denomination of bitcoins, the <code>int</code> value
     *  <code>0</code>. */
    public static final int COIN_SCALE = 0;

    /** A constant useful for specifying a denomination of millibitcoins, the <code>int</code>
     *  value <code>3</code>. */
    public static final int MILLICOIN_SCALE = 3;

    /** A constant useful for specifying a denomination of microbitcoins, the <code>int</code>
     *  value <code>6</code>. */
    public static final int MICROCOIN_SCALE = 6;

    /** Return the number of decimal places by which any value denominated in the
     *  units indicated by the given scale differs from that same value denominated in satoshis */
    private static int offSatoshis(int scale) { return Coin.SMALLEST_UNIT_EXPONENT - scale; }

    private static Locale defaultLocale() { return Locale.getDefault(); }

    /**
     * <p>This class constructs new instances of {@link BtcFormat}, allowing for the
     * configuration of those instances before they are constructed.  After obtaining a
     * <code>Builder</code> object from the {@link BtcFormat#builder()} method, invoke the
     * necessary setter methods to obtain your desired configuration.  Finaly, the {@link
     * #build()} method returns a new <code>BtcFormat</code> object that has the specified
     * configuration.
     *
     * <p>All the setter methods override defaults.  Invoking <code>build()</code> without invoking any
     * of the setting methods is equivalent to invoking {@link BtcFormat#getInstance()} with no arguments.
     *
     * <p>Each setter methods returns the same instance on which it is invoked,
     *  thus these methods can be chained.
     *
     * <p>Instances of this class are <strong>not</strong> thread-safe.
     */
    public static class Builder {

        private enum Variant {
            AUTO { @Override BtcFormat newInstance(Builder b) {
                       return getInstance(b.style, b.locale, b.minimumFractionDigits);
                   }},
            FIXED,
            UNSET;
            BtcFormat newInstance(Builder b) {
                return getInstance(b.scale, b.locale, b.minimumFractionDigits, b.fractionGroups);
            }
        }
        // Parameters are initialized to default or unset values
        private Variant variant = Variant.UNSET;
        private Locale locale = defaultLocale();
        private int minimumFractionDigits = 2;
        private int[] fractionGroups = {};
        private Style style = BtcAutoFormat.Style.CODE;
        private int scale = 0;
        private String symbol = "",code = "",pattern = "",localizedPattern = "";

        private Builder() {}

        /** Specify the new <code>BtcFormat</code> is to be automatically-denominating.
         * The argument determines which of either codes or symbols the new <code>BtcFormat</code>
         * will use by default to indicate the denominations it chooses when formatting values.
         *
         * <p>Note that the <code>Style</code> argument specifies the
         * <em>default</em> style, which is overridden by invoking
         * either {@link #pattern(String)} or {@link #localizedPattern(String)}.
         *
         * @throws IllegalArgumentException if {@link #scale(int)} has
         *         previously been invoked on this instance.*/
        public Builder style(BtcAutoFormat.Style val) {
            if (variant == Variant.FIXED)
                throw new IllegalStateException("You cannot invoke both style() and scale()");
            variant = Variant.AUTO;
            style = val;
            return this;
        }

        /** Specify the number of decimal places in the fraction part of formatted numbers.
         * This is equivalent to the {@link #minimumFractionDigits(int)} method, but named
         * appropriately for the context of generating {@link BtcAutoFormat} instances.
         *
         *  <p>If neither this method nor <code>minimumFactionDigits()</code> is invoked, the default value
         *  will be <code>2</code>. */
        public Builder fractionDigits(int val) { return minimumFractionDigits(val); }

        /** Specify a fixed-denomination of units to use when formatting and parsing values.
         *  The argument specifies the number of decimal places, in increasing
         *  precision, by which each formatted value will differ from that same value
         *  denominated in bitcoins.  For example, a denomination of millibitcoins is specified
         *  with a value of <code>3</code>.
         *
         * <p>The <code>BtcFormat</code> class provides appropriately named
         * <code>int</code>-type constants for the three common values, {@link BtcFormat#COIN_SCALE},
         * {@link BtcFormat#MILLICOIN_SCALE} {@link BtcFormat#MICROCOIN_SCALE}.
         *
         * <p>If neither this method nor {@link #style(BtcAutoFormat.Style)} is invoked on a
         * <code>Builder</code>, then the <code>BtcFormat</code> will default to a
         * fixed-denomination of bitcoins, equivalent to invoking this method with an argument
         * of <code>0</code>. */
        public Builder scale(int val) {
            if (variant == Variant.AUTO)
                throw new IllegalStateException("You cannot invoke both scale() and style()");
            variant = Variant.FIXED;
            scale = val;
            return this;
        }

        /** Specify the minimum number of decimal places in the fraction part of formatted values.
         *  This method is equivalent to {@link #fractionDigits(int)}, but named appropriately for
         *  the context of generating a fixed-denomination formatter.
         *
         *  <p>If neither this method nor <code>fractionDigits()</code> is invoked, the default value
         *  will be <code>2</code>.  */
        public Builder minimumFractionDigits(int val) { minimumFractionDigits = val;  return this; }

        /** Specify the sizes of a variable number of optional decimal-place groups in the
         *  fraction part of formatted values.  A group of each specified size will be used in
         *  addition to all previously applied decimal places only if doing so is useful for
         *  expressing precision.  The size of each group is limited to a maximum precision of
         *  satoshis.
         *
         *  <p>If this method is not invoked, then the number of fractional decimal places will
         *  be limited to the value passed to {@link #minimumFractionDigits}, or <code>2</code>
         *  if that method is not invoked. */
        public Builder fractionGroups(int... val) { fractionGroups = val; return this; }

        /** Specify the {@link java.util.Locale} for formatting and parsing.
         *  If this method is not invoked, then the runtime default locale will be used. */
        public Builder locale(Locale val) { locale = val; return this; }

        /** Specify a currency symbol to be used in the denomination-unit indicators
         *  of formatted values.  This method only sets the symbol, but does not cause
         *  it to be used.  You must also invoke either <code>style(SYMBOL)</code>, or else apply
         *  a custom pattern that includes a single currency-sign character by invoking either
         *  {@link #pattern(String)} or {@link #localizedPattern(String)}.
         *
         *  <p>Specify only the base symbol.  The appropriate prefix will be applied according
         *  to the denomination of formatted and parsed values. */
        public Builder symbol(String val) { symbol = val; return this; }

        /** Specify a custom currency code to be used in the denomination-unit indicators
         *  of formatted values.  This method only sets the code, but does not cause
         *  it to be used.  You must also invoke either <code>style(CODE)</code>, or else apply
         *  a custom pattern that includes a double currency-sign character by invoking either
         *  {@link #pattern(String)} or {@link #localizedPattern(String)}.
         *
         *  <p>Specify only the base code.  The appropriate prefix will be applied according
         *  to the denomination of formatted and parsed values. */
        public Builder code(String val) { code = val; return this; }

        /** Use the given pattern when formatting and parsing.  The format of this pattern is
         *  identical to that used by the {@link java.text.DecimalFormat} class.
         *
         *  <p>If the pattern lacks a negative subpattern, then the formatter will indicate
         *  negative values by placing a minus sign immediately preceding the number part of
         *  formatted values.
         *
         *  <p>Note that while the pattern format specified by the {@link
         *  java.text.DecimalFormat} class includes a mechanism for setting the number of
         *  fractional decimal places, that part of the pattern is ignored.  Instead, use the
         *  {@link #fractionDigits(int)}, {@link #minimumFractionDigits(int)} and {@link
         *  #fractionGroups(int...)} methods.
         *
         *  <p>Warning: if you set a pattern that includes a currency-sign for a
         *  fixed-denomination formatter that uses a non-standard scale, then an exception will
         *  be raised when you try to format a value.  The standard scales include all for
         *  which a metric prefix exists from micro to mega.
         *
         *  <p>Note that by applying a pattern you override the configured formatting style of
         *  {@link BtcAutoFormat} instances.  */
        public Builder pattern(String val) {
            if (localizedPattern != "")
                throw new IllegalStateException("You cannot invoke both pattern() and localizedPattern()");
            pattern = val;
            return this;
        } 

        /** Use the given localized-pattern for formatting and parsing.  The format of this
         *  pattern is identical to the patterns used by the {@link java.text.DecimalFormat}
         *  class.
         *
         *  <p>The pattern is localized according to the locale of the <code>BtcFormat</code>
         *  instance, the symbols for which can be examined by inspecting the {@link
         *  java.text.DecimalFormatSymbols} object returned by {@link BtcFormat#symbols()}.
         *  So, for example, if you are in Germany, then the non-localized pattern of
         *  <pre>"#,##0.###"</pre> would be localized as <pre>"#.##0,###"</pre>
         *
         *  <p>If the pattern lacks a negative subpattern, then the formatter will indicate
         *  negative values by placing a minus sign immediately preceding the number part of
         *  formatted values.
         *
         *  <p>Note that while the pattern format specified by the {@link
         *  java.text.DecimalFormat} class includes a mechanism for setting the number of
         *  fractional decimal places, that part of the pattern is ignored.  Instead, use the
         *  {@link #fractionDigits(int)}, {@link #minimumFractionDigits(int)} and {@link
         *  #fractionGroups(int...)} methods.
         *
         *  <p>Warning: if you set a pattern that includes a currency-sign for a
         *  fixed-denomination formatter that uses a non-standard scale, then an exception will
         *  be raised when you try to format a value.  The standard scales include all for
         *  which a metric prefix exists from micro to mega.
         *
         *  <p>Note that by applying a pattern you override the configured formatting style of
         *  {@link BtcAutoFormat} instances.         */
        public Builder localizedPattern(String val) {
            if (pattern != "")
                throw new IllegalStateException("You cannot invoke both pattern() and localizedPattern().");
            localizedPattern = val;
            return this;
        }

        /** Return a new {@link BtcFormat} instance.  The object returned will be configured according
         *  to the state of this <code>Builder</code> instance at the time this method is invoked. */
        public BtcFormat build() {
            BtcFormat f = variant.newInstance(this);
            if (symbol != "" || code != "") { synchronized(f.numberFormat) {
                DecimalFormatSymbols defaultSigns = f.numberFormat.getDecimalFormatSymbols();
                setSymbolAndCode(f.numberFormat,
                    symbol != "" ? symbol : defaultSigns.getCurrencySymbol(),
                    code != "" ? code : defaultSigns.getInternationalCurrencySymbol()
                );
            }}
            if (localizedPattern != "" || pattern != "") {
                int places = f.numberFormat.getMinimumFractionDigits();
                if (localizedPattern != "") f.numberFormat.applyLocalizedPattern(negify(localizedPattern));
                else f.numberFormat.applyPattern(negify(pattern));
                f.numberFormat.setMinimumFractionDigits(places);
                f.numberFormat.setMaximumFractionDigits(places);
            }
            return f;
        }

    }

    /** Return a new {@link Builder} object.  See the documentation of that class for usage details. */
    public static Builder builder() { return new Builder(); }

    /** This single constructor is invoked by the overriding subclass constructors. */
    protected BtcFormat(DecimalFormat numberFormat, int minDecimals, List<Integer> groups) {
        checkArgument(minDecimals >= 0, "There can be no fewer than zero fractional decimal places");
        this.numberFormat = numberFormat;
        this.numberFormat.setParseBigDecimal(true);
        this.numberFormat.setRoundingMode(HALF_UP);
        this.minimumFractionDigits = minDecimals;
        this.numberFormat.setMinimumFractionDigits(this.minimumFractionDigits);
        this.numberFormat.setMaximumFractionDigits(this.minimumFractionDigits);
        this.decimalGroups = groups;
        synchronized (this.numberFormat) { setSymbolAndCode(
            this.numberFormat,
            (this.numberFormat.getDecimalFormatSymbols().getCurrencySymbol().contains(COIN_SYMBOL))
                ? COIN_SYMBOL_ALT
                : COIN_SYMBOL,
            COIN_CODE
        );}
    }

    /**
     * Return a new instance of this class using all defaults.  The returned formatter will
     * auto-denominate values so as to minimize zeros without loss of precision and display a
     * currency code, for example "<code>BTC</code>", to indicate that denomination.  The
     * returned object will uses the default locale for formatting the number and placement of
     * the currency-code.  Two fractional decimal places will be displayed in all formatted numbers.
     */
    public static BtcFormat getInstance() { return getInstance(defaultLocale()); }

    /**
     * Return a new auto-denominating instance that will indicate units using a currency
     * symbol, for example, <code>"฿"</code>.  Formatting and parsing will be done
     * according to the default locale.
     */
    public static BtcFormat getSymbolInstance() { return getSymbolInstance(defaultLocale()); }

    /**
     * Return a new auto-denominating instance that will indicate units using a currency
     * code, for example, <code>"BTC"</code>.  Formatting and parsing will be done
     * according to the default locale.
     */
    public static BtcFormat getCodeInstance() { return getCodeInstance(defaultLocale()); }

    /**
     * Return a new symbol-style auto-formatter with the given number of fractional decimal
     * places.  Denominational units will be indicated using a currency symbol, for example,
     * <code>"฿"</code>.  The returned object will format the fraction-part of numbers using
     * the given number of decimal places, or fewer as necessary to avoid giving a place to
     * fractional satoshis.  Formatting and parsing will be done according to the default
     * locale.
     */
    public static BtcFormat getSymbolInstance(int fractionPlaces) {
        return getSymbolInstance(defaultLocale(), fractionPlaces);
    }

    /**
     * Return a new code-style auto-formatter with the given number of fractional decimal
     * places.  Denominational units will be indicated using a currency code, for example,
     * <code>"BTC"</code>.  The returned object will format the fraction-part of numbers using
     * the given number of decimal places, or fewer as necessary to avoid giving a place to
     * fractional satoshis.  Formatting and parsing will be done according to the default
     * locale.
     */
    public static BtcFormat getCodeInstance(int minDecimals) {
	return getCodeInstance(defaultLocale(), minDecimals);
    }

    /**
     * Return a new code-style auto-formatter for the given locale.  The returned object will
     * select denominational units based on each value being formatted, and will indicate those
     * units using a currency code, for example, <code>"mBTC"</code>.
     */
    public static BtcFormat getInstance(Locale locale) { return getCodeInstance(locale); }

    /**
     * Return a new code-style auto-formatter for the given locale.  The returned object will
     * select denominational units based on each value being formatted, and will indicate those
     * units using a currency code, for example, <code>"mBTC"</code>.
     */
    public static BtcFormat getCodeInstance(Locale locale) { return getInstance(CODE, locale); }

    /**
     * Return a new code-style auto-formatter for the given locale with the given number of
     * fraction places.  The returned object will select denominational units based on each
     * value being formatted, and will indicate those units using a currency code, for example,
     * <code>"mBTC"</code>.  The returned object will format the fraction-part of numbers using
     * the given number of decimal places, or fewer as necessary to avoid giving a place to
     * fractional satoshis.
     */
    public static BtcFormat getInstance(Locale locale, int minDecimals) {
	return getCodeInstance(locale, minDecimals);
    }

    /**
     * Return a new code-style auto-formatter for the given locale with the given number of
     * fraction places.  The returned object will select denominational units based on each
     * value being formatted, and will indicate those units using a currency code, for example,
     * <code>"mBTC"</code>.  The returned object will format the fraction-part of numbers using
     * the given number of decimal places, or fewer as necessary to avoid giving a place to
     * fractional satoshis.
     */
    public static BtcFormat getCodeInstance(Locale locale, int minDecimals) {
	return getInstance(CODE, locale, minDecimals);
    }

    /**
     * Return a new symbol-style auto-formatter for the given locale.  The returned object will
     * select denominational units based on each value being formatted, and will indicate those
     * units using a currency symbol, for example, <code>"µ฿"</code>.
     */
    public static BtcFormat getSymbolInstance(Locale locale) {
	return getInstance(SYMBOL, locale);
    }

    /**
     * Return a new symbol-style auto-formatter for the given locale with the given number of
     * fraction places.  The returned object will select denominational units based on each
     * value being formatted, and will indicate those units using a currency symbol, for example,
     * <code>"µ฿"</code>.  The returned object will format the fraction-part of numbers using
     * the given number of decimal places, or fewer as necessary to avoid giving a place to
     * fractional satoshis.
     */
    public static BtcFormat getSymbolInstance(Locale locale, int fractionPlaces) {
	return getInstance(SYMBOL, locale, fractionPlaces);
    }

    /**
     * Return a new auto-denominating formatter.  The returned object will indicate the
     * denominational units of formatted values using either a currency symbol, such as,
     * <code>"฿"</code>, or code, such as <code>"mBTC"</code>, depending on the value of
     * the argument.  Formatting and parsing will be done according to the default locale.
     */
    public static BtcFormat getInstance(Style style) { return getInstance(style, defaultLocale()); }

    /**
     * Return a new auto-denominating formatter with the given number of fractional decimal
     * places.  The returned object will indicate the denominational units of formatted values
     * using either a currency symbol, such as, <code>"฿"</code>, or code, such as
     * <code>"mBTC"</code>, depending on the value of the first argument.  The returned object
     * will format the fraction-part of numbers using the given number of decimal places, or
     * fewer as necessary to avoid giving a place to fractional satoshis.  Formatting and
     * parsing will be done according to the default locale.
     */
    public static BtcFormat getInstance(Style style, int fractionPlaces) {
	return getInstance(style, defaultLocale(), fractionPlaces);
    }

    /**
     * Return a new auto-formatter with the given style for the given locale.
     * The returned object that will auto-denominate each formatted value, and
     * will indicate that denomination using either a currency code, such as
     * "<code>BTC</code>", or symbol, such as "<code>฿</code>", depending on the value
     * of the first argument. 
     * <p>The number of fractional decimal places in formatted number will be two, or fewer
     * as necessary to avoid giving a place to fractional satoshis.
     */
    public static BtcFormat getInstance(Style style, Locale locale) {
	return getInstance(style, locale, 2);
    }

    /**
     * Return a new auto-formatter for the given locale with the given number of fraction places.
     * The returned object will automatically-denominate each formatted
     * value, and will indicate that denomination using either a currency code,
     * such as <code>"mBTC"</code>, or symbol, such as "<code>฿</code>",
     * according to the given style argument.  It will format each number
     * according to the given locale.
     *
     * <p>The third parameter is the number of fractional decimal places to use for each
     * formatted number, reduced as neccesary when formatting to avoid giving a place to
     * fractional satoshis.
     */
    public static BtcFormat getInstance(Style style, Locale locale, int fractionPlaces) {
	return new BtcAutoFormat(locale, style, fractionPlaces);
    }

    /**
     * Return a new coin-denominated formatter.  The returned object will format and parse
     * values according to the default locale, and will format numbers with two fractional
     * decimal places, rounding values as necessary.
     */
    public static BtcFormat getCoinInstance() { return getCoinInstance(defaultLocale()); }

    private static List<Integer> boxAsList(int[] elements) throws IllegalArgumentException {
        List<Integer> list = new ArrayList<Integer>(elements.length);
        for (int e : elements) {
            checkArgument(e > 0, "Size of decimal group must be at least one.");
            list.add(e);
        }
        return list;
    }

    /**
     * Return a new coin-denominated formatter with the specified fraction-places.  The
     * returned object will format and parse values according to the default locale, and will
     * format the fraction part of numbers with at least two decimal places.  The sizes of
     * additional groups of decimal places can be specified by a variable number of
     * <code>int</code> arguments.  Each optional decimal-place group will be applied only if
     * useful for expressing precision, and will be only partially applied if necessary to
     * avoid giving a place to fractional satoshis.
     */
    public static BtcFormat getCoinInstance(int minFractionPlaces, int... groups) {
        return getInstance(COIN_SCALE, defaultLocale(), minFractionPlaces, boxAsList(groups));
    }

    /**
     * Return a new coin-denominated formatter for the given locale.  The returned object will
     * format the fractional part of numbers with two decimal places, rounding as necessary.
     */
    public static BtcFormat getCoinInstance(Locale locale) {
        return getInstance(COIN_SCALE, locale, 2);
    }

    /**
     * Return a newly-constructed instance for the given locale that will format
     * values in terms of bitcoins, with the given minimum number of fractional
     * decimal places.  Optionally, repeating integer arguments can be passed, each
     * indicating the size of an additional group of fractional decimal places to be
     * used as necessary to avoid rounding, to a limiting precision of satoshis.
     */
    public static BtcFormat getCoinInstance(Locale locale, int scale, int... groups) {
        return getInstance(COIN_SCALE, locale, scale, boxAsList(groups));
    }

    /**
     * Return a new millicoin-denominated formatter.  The returned object will format and
     * parse values for the default locale, and will format the fractional part of numbers with
     * two decimal places, rounding as necessary.
     */
    public static BtcFormat getMilliInstance() { return getMilliInstance(defaultLocale()); }

    /**
     * Return a new millicoin-denominated formatter for the given locale.  The returned object
     * will format the fractional part of numbers with two decimal places, rounding as
     * necessary.
     */
    public static BtcFormat getMilliInstance(Locale locale) {
        return getInstance(MILLICOIN_SCALE, locale, 2);
    }

    /**
     * Return a new millicoin-denominated formatter with the specified fractional decimal
     * placing.  The returned object will format and parse values according to the default
     * locale, and will format the fractional part of numbers with the given minimum number of
     * fractional decimal places.  Optionally, repeating integer arguments can be passed, each
     * indicating the size of an additional group of fractional decimal places to be used as
     * necessary to avoid rounding, to a limiting precision of satoshis.
     */
    public static BtcFormat getMilliInstance(int scale, int... groups) {
        return getInstance(MILLICOIN_SCALE, defaultLocale(), scale, boxAsList(groups));
    }

    /**
     * Return a new millicoin-denominated formatter for the given locale with the specified
     * fractional decimal placing.  The returned object will format the fractional part of
     * numbers with the given minimum number of fractional decimal places.  Optionally,
     * repeating integer arguments can be passed, each indicating the size of an additional
     * group of fractional decimal places to be used as necessary to avoid rounding, to a
     * limiting precision of satoshis.
     */
    public static BtcFormat getMilliInstance(Locale locale, int scale, int... groups) {
        return getInstance(MILLICOIN_SCALE, locale, scale, boxAsList(groups));
    }

    /**
     * Return a new microcoin-denominated formatter for the default locale.  The returned object
     * will format the fractional part of numbers with two decimal places, rounding as
     * necessary.
     */
    public static BtcFormat getMicroInstance() { return getMicroInstance(defaultLocale()); }

    /**
     * Return a new microcoin-denominated formatter for the given locale.  The returned object
     * will format the fractional part of numbers with two decimal places, rounding as
     * necessary.
     */
    public static BtcFormat getMicroInstance(Locale locale) {
        return getInstance(MICROCOIN_SCALE, locale);
    }

    /**
     * Return a new microcoin-denominated formatter with the specified fractional decimal
     * placing.  The returned object will format and parse values according to the default
     * locale, and will format the fractional part of numbers with the given minimum number of
     * fractional decimal places.  Optionally, repeating integer arguments can be passed, each
     * indicating the size of an additional group of fractional decimal places to be used as
     * necessary to avoid rounding, to a limiting precision of satoshis.
     */
    public static BtcFormat getMicroInstance(int scale, int... groups) {
        return getInstance(MICROCOIN_SCALE, defaultLocale(), scale, boxAsList(groups));
    }

    /**
     * Return a new microcoin-denominated formatter for the given locale with the specified
     * fractional decimal placing.  The returned object will format the fractional part of
     * numbers with the given minimum number of fractional decimal places.  Optionally,
     * repeating integer arguments can be passed, each indicating the size of an additional
     * group of fractional decimal places to be used as necessary to avoid rounding, to a
     * limiting precision of satoshis.
     */
    public static BtcFormat getMicroInstance(Locale locale, int scale, int... groups) {
        return getInstance(MICROCOIN_SCALE, locale, scale, boxAsList(groups));
    }

    /**
     * Return a new fixeed-denomination formatter with the specified fractional decimal
     * placing.  The first argument specifies the denomination as the size of the
     * shift from coin-denomination in increasingly-precise decimal places.  The returned object will format
     * and parse values according to the default locale, and will format the fractional part of
     * numbers with the given minimum number of fractional decimal places.  Optionally,
     * repeating integer arguments can be passed, each indicating the size of an additional
     * group of fractional decimal places to be used as necessary to avoid rounding, to a
     * limiting precision of satoshis.
     */
    public static BtcFormat getInstance(int scale, int minDecimals, int... groups) {
        return getInstance(scale, defaultLocale(), minDecimals, boxAsList(groups));
    }

    /**
     * Return a new fixeed-denomination formatter.  The argument specifies the denomination as
     * the size of the shift from coin-denomination in increasingly-precise decimal places.
     * The returned object will format and parse values according to the default locale, and
     * will format the fractional part of numbers with two decimal places, or fewer as
     * necessary to avoid giving a place to fractional satoshis.
     */
    public static BtcFormat getInstance(int scale) {
        return getInstance(scale, defaultLocale());
    }

    /**
     * Return a new fixeed-denomination formatter for the given locale.  The first argument
     * specifies the denomination as the size of the shift from coin-denomination in
     * increasingly-precise decimal places.  The returned object will format and parse values
     * according to the locale specified by the second argument, and will format the fractional
     * part of numbers with two decimal places, or fewer as necessary to avoid giving a place
     * to fractional satoshis.
     */
    public static BtcFormat getInstance(int scale, Locale locale) {
        return getInstance(scale, locale, 2);
    }

    /**
     * Return a new fixed-denomination formatter for the given locale, with the specified
     * fractional decimal placing.  The first argument specifies the denomination as the size
     * of the shift from coin-denomination in increasingly-precise decimal places.  The third
     * parameter is the minimum number of fractional decimal places to use, followed by
     * optional repeating integer parameters each specifying the size of an additional group of
     * fractional decimal places to use as necessary to avoid rounding, down to a maximum
     * precision of satoshis.
     */
    public static BtcFormat getInstance(int scale, Locale locale, int minDecimals, int... groups) {
        return getInstance(scale, locale, minDecimals, boxAsList(groups));
    }

    /**
     * Return a new fixed-denomination formatter for the given locale, with the specified
     * fractional decimal placing.  The first argument specifies the denomination as the size
     * of the shift from coin-denomination in increasingly-precise decimal places.  The third
     * parameter is the minimum number of fractional decimal places to use.  The third argument
     * specifies the minimum number of fractional decimal places in formatted numbers.  The
     * last argument is a <code>List</code> of <code>Integer</code> values, each of which
     * specifies the size of an additional group of fractional decimal places to use as
     * necessary to avoid rounding, down to a maximum precision of satoshis.
     */
    public static BtcFormat getInstance(int scale, Locale locale, int minDecimals, List<Integer> groups) {
        return new BtcFixedFormat(locale, scale, minDecimals, groups);
    }

    /***********************/
    /****** FORMATTING *****/
    /***********************/

    /**
     * Formats a bitcoin monetary value and returns an {@link java.text.AttributedCharacterIterator}.
     * By iterating, you can examine what fields apply to each character.  This can be useful
     * since a character may be part of more than one field, for example a grouping separator
     * that is also part of the integer field.
     *
     * @see java.text.AttributedCharacterIterator
     */
    @Override
    public AttributedCharacterIterator formatToCharacterIterator(Object obj) { synchronized(numberFormat) {
        DecimalFormatSymbols anteSigns = numberFormat.getDecimalFormatSymbols();
        BigDecimal units = denominateAndRound(inSatoshis(obj), minimumFractionDigits, decimalGroups);
        List<Integer> anteDigits = setFormatterDigits(numberFormat, units.scale(), units.scale());
        AttributedCharacterIterator i = numberFormat.formatToCharacterIterator(units);
        numberFormat.setDecimalFormatSymbols(anteSigns);
        setFormatterDigits(numberFormat, anteDigits.get(0), anteDigits.get(1));
	return i;
    }}

    /**
     * Formats a bitcoin value as a number and possibly a units indicator and appends the
     * resulting text to the given string buffer.  The type of monetary value argument can be
     * any one of any of the following classes: <code>{@link Coin}</code>,
     * <code>Integer</code>, <code>Long</code>, <code>BigInteger</code>,
     * <code>BigDecimal</code>.  Numeric types that can represent only an integer are interpreted
     * as that number of satoshis.  The value of a <code>BigDecimal</code> is interpreted as that
     * number of bitcoins, rounded to the nearest satoshi as necessary.
     *
     * @return the <code>StringBuffer</code> passed in as <code>toAppendTo</code>
     */
    @Override
    public StringBuffer format(Object qty, StringBuffer toAppendTo, FieldPosition pos) {
        return format(qty, toAppendTo, pos, minimumFractionDigits, decimalGroups);
    }

    /**
     * Formats a bitcoin value as a number and possibly a units indicator to a
     * <code>String</code>.The type of monetary value argument can be any one of any of the
     * following classes: <code>{@link Coin}</code>, <code>Integer</code>, <code>Long</code>,
     * <code>BigInteger</code>, <code>BigDecimal</code>.  Numeric types that can represent only
     * an integer are interpreted as that number of satoshis.  The value of a
     * <code>BigDecimal</code> is interpreted as that number of bitcoins, rounded to the
     * nearest satoshi as necessary.
     *
     * @param minDecimals The minimum number of decimal places in the fractional part of the formatted number
     * @param fractionGroups The sizes of optional additional fractional decimal-place groups
     * @throws IllegalArgumentException if the number of fraction places is negative.
     */
    public String format(Object qty, int minDecimals, int... fractionGroups) {
        return format(qty, new StringBuffer(), new FieldPosition(0), minDecimals, boxAsList(fractionGroups)).toString();
    }

    /**
     * Formats a bitcoin value as a number and possibly a units indicator and appends the
     * resulting text to the given string buffer.  The type of monetary value argument can be
     * any one of any of the following classes: <code>{@link Coin}</code>,
     * <code>Integer</code>, <code>Long</code>, <code>BigInteger</code>,
     * <code>BigDecimal</code>.  Numeric types that can represent only an integer are interpreted
     * as that number of satoshis.  The value of a <code>BigDecimal</code> is interpreted as that
     * number of bitcoins, rounded to the nearest satoshi as necessary.
     *
     * @param minDecimals The minimum number of decimal places in the fractional part of the formatted number
     * @param fractionGroups The sizes of optional additional fractional decimal-place groups
     * @throws IllegalArgumentException if the number of fraction places is negative.
     */
    public StringBuffer format(Object qty, StringBuffer toAppendTo, FieldPosition pos,
                                            int minDecimals, int... fractionGroups) {
        return format(qty, toAppendTo, pos, minDecimals, boxAsList(fractionGroups));
    }

    private StringBuffer format(Object qty, StringBuffer toAppendTo, FieldPosition pos,
                                            int minDecimals, List<Integer> fractionGroups) {
        checkArgument(minDecimals >= 0, "There can be no fewer than zero fractional decimal places");
        synchronized (numberFormat) {
            DecimalFormatSymbols anteSigns = numberFormat.getDecimalFormatSymbols();
            BigDecimal denominatedUnitCount = denominateAndRound(inSatoshis(qty), minDecimals, fractionGroups);
            List<Integer> antePlaces =
                setFormatterDigits(numberFormat, denominatedUnitCount.scale(), denominatedUnitCount.scale());
            StringBuffer s = numberFormat.format(denominatedUnitCount, toAppendTo, pos);
            numberFormat.setDecimalFormatSymbols(anteSigns);
            setFormatterDigits(numberFormat, antePlaces.get(0), antePlaces.get(1));
            return s;
        }
    }    

    /**
     * Return the denomination for formatting the given value.  The returned <code>int</code>
     * is the size of the decimal-place shift between the given Bitcoin-value denominated in
     * bitcoins and that same value as formatted.  A fixed-denomination formatter will ignore
     * the arguments.
     *
     * @param satoshis The number of satoshis having the value for which the shift is calculated
     * @param fractionPlaces The number of decimal places available for displaying the
                             fractional part of the denominated value
     * @return The size of the shift in increasingly-precise decimal places
     */
    protected abstract int scale(BigInteger satoshis, int fractionPlaces);

    /** Return the denomination of this object.  Fixed-denomination formatters will override
     *  with their configured denomination, auto-formatters with coin denomination.  This
     *  determines the interpretation of parsed numbers lacking a units-indicator. */
    protected abstract int scale();

    /**
     * Takes a bitcoin monetary value that the client wants to format and returns the number of
     * denominational units having the equal value, rounded to the appropriate number of
     * decimal places.  Calls the scale() method of the subclass, which may have the
     * side-effect of changing the currency symbol and code of the underlying `NumberFormat`
     * object, therefore only invoke this from a synchronized method that resets the NumberFormat.
     */
    private BigDecimal denominateAndRound(BigInteger satoshis, int minDecimals, List<Integer> fractionGroups) {
        int scale = scale(satoshis, minDecimals);
        BigDecimal denominatedUnitCount = new BigDecimal(satoshis).movePointLeft(offSatoshis(scale));
        int places = calculateFractionPlaces(denominatedUnitCount, scale, minDecimals, fractionGroups);
        return denominatedUnitCount.setScale(places, HALF_UP);
    }

    /** Sets the number of fractional decimal places to be displayed on the given
     *  NumberFormat object to the value of the given integer.
     *  @return The minimum and maximum fractional places settings that the
     *          formatter had before this change, as an ImmutableList. */
    private static ImmutableList<Integer> setFormatterDigits(DecimalFormat formatter, int min, int max) {
        ImmutableList<Integer> ante = ImmutableList.of(
            formatter.getMinimumFractionDigits(),
            formatter.getMaximumFractionDigits()
        );
        formatter.setMinimumFractionDigits(min);
        formatter.setMaximumFractionDigits(max);
        return ante;
    }

    /** Return the number of fractional decimal places to be displayed when formatting
     *  the given number of monetory units of the denomination indicated by the given decimal scale value,
     *  where 0 = coin, 3 = millicoin, and so on.
     *
     *  @param unitCount      the number of monetary units to be formatted
     *  @param scale          the denomination of those units as the decimal-place shift from coins
     *  @param minDecimals    the minimum number of fractional decimal places
     *  @param fractionGroups the sizes of option fractional decimal-place groups
     */
    private static int calculateFractionPlaces(
        BigDecimal unitCount, int scale, int minDecimals, List<Integer> fractionGroups)
    {
        /* Taking into account BOTH the user's preference for decimal-place groups, AND the prohibition
         * against displaying a fractional number of satoshis, determine the maximum possible number of
         * fractional decimal places. */
        int places = minDecimals;
        for (int group : fractionGroups) { places += group; }
        int max = Math.min(places, offSatoshis(scale));

        places = Math.min(minDecimals,max);
        for (int group : fractionGroups) {
            /* Compare the value formatted using only this many decimal places to the
             * same value using as many places as possible.  If there's no difference, then
             * there's no reason to continue adding more places.  */
            if (unitCount.setScale(places, HALF_UP).compareTo(unitCount.setScale(max, HALF_UP)) == 0) break;
            places += group;
            if (places > max) places = max;
        }
        return places;
    }

    /**
     * Takes an object representing a bitcoin quantity of any type the
     * client is permitted to pass us, and return a BigInteger representing the
     * number of satoshis having the equivalent value. */
    private static BigInteger inSatoshis(Object qty) {
	BigInteger satoshis;
        // the value might be bitcoins or satoshis
	if (qty instanceof Long || qty instanceof Integer)
	    satoshis = BigInteger.valueOf(((Number)qty).longValue());
	else if (qty instanceof BigInteger)
	    satoshis = (BigInteger)qty;
	else if (qty instanceof BigDecimal)
	    satoshis = ((BigDecimal)qty).movePointRight(Coin.SMALLEST_UNIT_EXPONENT).
                       setScale(0,BigDecimal.ROUND_HALF_UP).unscaledValue();
	else if (qty instanceof Coin)
	    satoshis = BigInteger.valueOf(((Coin)qty).value);
	else
	    throw new IllegalArgumentException("Cannot format a " + qty.getClass().getSimpleName() +
                                               " as a Bicoin value");
        return satoshis;
    }

    /********************/
    /****** PARSING *****/
    /********************/

    /**
      * Parse a <code>String</code> representation of a Bitcoin monetary value.  Returns a
      * {@link org.bitcoinj.core.Coin} object that represents the parsed value.
      * @see java.text.NumberFormat */
    @Override
    public final Object parseObject(String source, ParsePosition pos) { return parse(source, pos); }

    private class ScaleMatcher {
        public Pattern pattern;
        public int scale;
        ScaleMatcher(Pattern p, int s) { pattern = p; scale = s; }
    }

    /* Lazy initialization;  No reason to create all these objects unless needed for parsing */
    // coin indicator regex String; TODO: does this need to be volatile?
    private volatile String ci = "(" + COIN_SYMBOL + "|" + COIN_SYMBOL_ALT + "|B⃦|" + COIN_CODE + "|XBT)";
    private Pattern coinPattern;
    private volatile ScaleMatcher[] denoms;
    ScaleMatcher[] denomMatchers() {
        ScaleMatcher[] result = denoms;
        if (result == null) { synchronized(this) {
            result = denoms;
            if (result == null) {
                if (! coinSymbol().matches(ci)) ci = ci.replaceFirst("\\(", "(" + coinSymbol() + "|");
                if (! coinCode().matches(ci))  {
                    ci = ci.replaceFirst("\\)", "|" + coinCode() + ")");
                }
                coinPattern = Pattern.compile(ci + "?");
                result = denoms = new ScaleMatcher[]{
                    new ScaleMatcher(Pattern.compile("¢" + ci + "?|c" + ci), 2), // centi 
                    new ScaleMatcher(Pattern.compile("₥" + ci + "?|m" + ci), MILLICOIN_SCALE),
                    new ScaleMatcher(Pattern.compile("([µu]" + ci + ")"),    MICROCOIN_SCALE),
                    new ScaleMatcher(Pattern.compile("(da" + ci + ")"),     -1), // deka
                    new ScaleMatcher(Pattern.compile("(h" + ci + ")"),      -2), // hekto
                    new ScaleMatcher(Pattern.compile("(k" + ci + ")"),      -3), // kilo
                    new ScaleMatcher(Pattern.compile("(M" + ci + ")"),      -6)  // mega
                };
            }
        }}
        return result;
    }

    /** Set both the currency symbol and international code of the underlying {@link
      * java.text.NumberFormat} object to the value of the given <code>String</code>.
      * This method is invoked in the process of parsing, not formatting.
      *
      * Only invoke this from code synchronized on the value of the first argument, and don't
      * forget to put the symbols back otherwise equals(), hashCode() and immutability will
      * break.  */
    private static DecimalFormatSymbols setSymbolAndCode(DecimalFormat numberFormat, String sign) {
        return setSymbolAndCode(numberFormat, sign, sign);
    }

    /** Set the currency symbol and international code of the underlying {@link
      * java.text.NumberFormat} object to the values of the last two arguments, respectively.
      * This method is invoked in the process of parsing, not formatting.
      *
      * Only invoke this from code synchronized on value of the first argument, and don't
      * forget to put the symbols back otherwise equals(), hashCode() and immutability will
      * break.  */
    private static DecimalFormatSymbols setSymbolAndCode(DecimalFormat numberFormat, String symbol, String code) {
        assert Thread.holdsLock(numberFormat);
        DecimalFormatSymbols fs = numberFormat.getDecimalFormatSymbols();
        DecimalFormatSymbols ante = (DecimalFormatSymbols)fs.clone();
        fs.setInternationalCurrencySymbol(code);
        fs.setCurrencySymbol(symbol);
        numberFormat.setDecimalFormatSymbols(fs);
        return ante;
    }

    /**
     * Set both the currency symbol and code of the underlying, mutable NumberFormat object
     * according to the given denominational units scale factor.  This is for formatting, not parsing.
     *
     * <p>Set back to zero when you're done formatting otherwise immutability, equals() and
     * hashCode() will break!
     *
     * @param scale Number of places the decimal point will be shifted when formatting
     *              a quantity of satoshis.
     * @return The DecimalFormatSymbols before changing
     */
    protected static void prefixUnitsIndicator(DecimalFormat numberFormat, int scale) {
        assert Thread.holdsLock(numberFormat); // make sure caller intends to reset before changing
        DecimalFormatSymbols fs = numberFormat.getDecimalFormatSymbols();
        setSymbolAndCode(numberFormat,
            prefixSymbol(fs.getCurrencySymbol(), scale), prefixCode(fs.getInternationalCurrencySymbol(), scale)
        );
    }

    /** Parse a <code>String</code> representation of a Bitcoin monetary value.  If this
     * object's pattern includes a currency sign, either symbol or code, as by default is true
     * for instances of {@link BtcAutoFormat} and false for instances of {@link
     * BtcFixedFormat}, then denominated (i.e., prefixed) currency signs in the parsed String
     * will be recognized, and the parsed number will be interpreted as a quantity of units
     * having that recognized denomination.
     * <p>If the pattern includes a currency sign but no currency sign is detected in the parsed
     * String, then the number is interpreted as a quatity of bitcoins.
     * <p>If the pattern contains neither a currency symbol nor sign, then instances of {@link
     * BtcAutoFormat} will interpret the parsed number as a quantity of bitcoins, and instances
     * of {@link BtcAutoFormat} will interpret the number as a quantity of that instance's
     * configured denomination, which can be ascertained by invoking the {@link
     * BtcFixedFormat#symbol()} or {@link BtcFixedFormat#code()} method.
     *
     * <p>Consider using the single-argument version of this overloaded method unless you need to
     * keep track of the current parse position.
     *
     * @return a Coin object representing the parsed value
     * @see java.text.ParsePosition
     */
    public Coin parse(String source, ParsePosition pos) {
        DecimalFormatSymbols anteSigns = null;
        int parseScale = COIN_SCALE; // default
        Coin coin = null;
        synchronized (numberFormat) {
            if (numberFormat.toPattern().contains("¤")) {
                for(ScaleMatcher d : denomMatchers()) {
                    Matcher matcher = d.pattern.matcher(source);
                    if (matcher.find()) {
                        anteSigns = setSymbolAndCode(numberFormat, matcher.group());
                        parseScale = d.scale;
                        break;
                    }
                }
                if (parseScale == COIN_SCALE) {
                    Matcher matcher = coinPattern.matcher(source);
                    matcher.find();
                    anteSigns = setSymbolAndCode(numberFormat, matcher.group());
                }
            } else parseScale = scale();

            Number number = numberFormat.parse(source, pos);
            if (number != null) try {
                    coin = Coin.valueOf(
                        ((BigDecimal)number).movePointRight(offSatoshis(parseScale)).setScale(0, HALF_UP).longValue()
                    );
                } catch (IllegalArgumentException e) {
                    pos.setIndex(0);
                }
            if (anteSigns != null) numberFormat.setDecimalFormatSymbols(anteSigns);
        }
        return coin;
    }

    /** Parse a <code>String</code> representation of a Bitcoin monetary value.  If this
     * object's pattern includes a currency sign, either symbol or code, as by default is true
     * for instances of {@link BtcAutoFormat} and false for instances of {@link
     * BtcFixedFormat}, then denominated (i.e., prefixed) currency signs in the parsed String
     * will be recognized, and the parsed number will be interpreted as a quantity of units
     * having that recognized denomination.
     * <p>If the pattern includes a currency sign but no currency sign is detected in the parsed
     * String, then the number is interpreted as a quatity of bitcoins.
     * <p>If the pattern contains neither a currency symbol nor sign, then instances of {@link
     * BtcAutoFormat} will interpret the parsed number as a quantity of bitcoins, and instances
     * of {@link BtcAutoFormat} will interpret the number as a quantity of that instance's
     * configured denomination, which can be ascertained by invoking the {@link
     * BtcFixedFormat#symbol()} or {@link BtcFixedFormat#code()} method.
     *
     * @return a Coin object representing the parsed value
     */
    public Coin parse(String source) throws ParseException {
        return (Coin)parseObject(source);
    }

    /*********************************/
    /****** END OF PARSING STUFF *****/
    /*********************************/

    protected static String prefixCode(String code, int scale) {
        switch (scale) {
        case COIN_SCALE:      return code;
        case 1:               return "d" + code;
        case 2:               return "c" + code;
        case MILLICOIN_SCALE: return "m" + code;
        case MICROCOIN_SCALE: return "µ" + code;
        case -1:              return "da" + code;
        case -2:              return "h" + code;
        case -3:              return "k" + code;
        case -6:              return "M" + code;
        default: throw new IllegalStateException("No known prefix for scale " + String.valueOf(scale));
        }
    }

    protected static String prefixSymbol(String symbol, int scale) {
        switch (scale) {
        case COIN_SCALE:      return symbol;
        case 1:               return "d" + symbol;
        case 2:               return "¢" + symbol;
        case MILLICOIN_SCALE: return "₥" + symbol;
        case MICROCOIN_SCALE: return "µ" + symbol;
        case -1:              return "da" + symbol;
        case -2:              return "h" + symbol;
        case -3:              return "k" + symbol;
        case -6:              return "M" + symbol;
        default: throw new IllegalStateException("No known prefix for scale " + String.valueOf(scale));
        }
    }

    /** Guarantee a formatting pattern has a subpattern for negative values.  This method takes
     *  a pattern that may be missing a negative subpattern, and returns the same pattern with
     *  a negative subpattern appended as needed.
     *
     *  <p>This method accommodates an imperfection in the Java formatting code and distributed
     *  locale data.  To wit: the subpattern for negative numbers is optional and not all
     *  locales have one. In those cases, {@link java.text.DecimalFormat} will indicate numbers
     *  less than zero by adding a negative sign as the first character of the prefix of the
     *  positive subpattern.
     *
     *  <p>We don't like this, since we claim the negative sign applies to the number not the
     *  units, and therefore it ought to be adjacent to the number, displacing the
     *  currency-units indicator if necessary.
     */
    protected static String negify(String pattern) {
        if (pattern.contains(";")) return pattern;
        else {
            if (pattern.contains("-"))
                throw new IllegalStateException("Positive pattern contains negative sign");
            // the regex matches everything until the first non-quoted number character
            return pattern + ";" + pattern.replaceFirst("^([^#0,.']*('[^']*')?)*", "$0-");
        }
    }

    /**
     * Return an array of all locales for which the getInstance() method of this class can
     * return localized instances.  See {@link java.text.NumberFormat#getAvailableLocales()}
     */
    public static Locale[] getAvailableLocales() { return NumberFormat.getAvailableLocales(); }

    /** Return the unprefixed currency symbol for bitcoins configured for this object.  The
     *  return value of this method is constant throughough the life of an instance.  */
    public String coinSymbol() { synchronized(numberFormat) {
        return numberFormat.getDecimalFormatSymbols().getCurrencySymbol();
    }}

    /** Return the unprefixed international currency code for bitcoins configured for this
     * object.  The return value of this method is constant throughough the life of an instance.  */
    public String coinCode() { synchronized(numberFormat) {
        return numberFormat.getDecimalFormatSymbols().getInternationalCurrencySymbol();
    }}

    /** Return a representation of the pattern used by this instance for formatting and
     *  parsing.  The format is similar to, but not the same as the format recognized by the
     *  {@link Builder#pattern} and {@link Builder#localizedPattern} methods.  The pattern
     *  returned by this method is localized, any currency signs expressed are literally, and
     *  optional fractional decimal places are shown grouped in parentheses. */
    public String pattern() { synchronized(numberFormat) {
        StringBuilder groups = new StringBuilder();
        for (int group : decimalGroups) {
            groups.append("(").append(Strings.repeat("#", group)).append(")");
        }
        DecimalFormatSymbols s = numberFormat.getDecimalFormatSymbols();
        String digit = String.valueOf(s.getDigit());
        String exp = s.getExponentSeparator();
        String groupSep = String.valueOf(s.getGroupingSeparator());
        String moneySep = String.valueOf(s.getMonetaryDecimalSeparator());
        String zero = String.valueOf(s.getZeroDigit());
        String boundary = String.valueOf(s.getPatternSeparator());
        String minus = String.valueOf(s.getMinusSign());
        String decSep = String.valueOf(s.getDecimalSeparator());

        String prefixAndNumber = "(^|" + boundary+ ")" +
            "([^" + Matcher.quoteReplacement(digit + zero + groupSep + decSep + moneySep) + "']*('[^']*')?)*" +
            "[" + Matcher.quoteReplacement(digit + zero + groupSep + decSep + moneySep + exp) + "]+";

        return numberFormat.toLocalizedPattern().
            replaceAll(prefixAndNumber, "$0" + groups.toString()).
               replaceAll("¤¤", Matcher.quoteReplacement(coinCode())).
               replaceAll("¤", Matcher.quoteReplacement(coinSymbol()));
    }}

    /** Return a copy of the localized symbols used by this instance for formatting and parsing.  */
    public DecimalFormatSymbols symbols() { synchronized(numberFormat) {
        return numberFormat.getDecimalFormatSymbols();
    }}

    /** Return true if the given object is equivalent to this one.
      * Formatters for different locales will never be equal, even
      * if they behave identically. */
    @Override public boolean equals(Object o) {
        if (o == this) return true;
        if (!(o instanceof BtcFormat)) return false;
        BtcFormat other = (BtcFormat)o;
        return other.pattern().equals(pattern()) &&
               other.symbols().equals(symbols()) &&
               other.minimumFractionDigits == minimumFractionDigits;
    }

    /** Return a hash code value for this instance.
     *  @see java.lang.Object#hashCode
     */
    @Override public int hashCode() {
        int result = 17;
        result = 31 * result + pattern().hashCode();
        result = 31 * result + symbols().hashCode();
        result = 31 * result + minimumFractionDigits;
        result = 31 * result + decimalGroups.hashCode();
        return result;
    }

}
