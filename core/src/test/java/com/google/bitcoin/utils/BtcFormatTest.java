/**
 * Placed in the public domain by the author Adam Mackler
 * Use at your own risk.
 */

package com.google.bitcoin.utils;

import org.junit.Test;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;

import java.text.AttributedCharacterIterator;
import java.text.AttributedCharacterIterator.Attribute;
import java.text.CharacterIterator;
import java.text.DecimalFormat;
import java.text.DecimalFormatSymbols;
import java.text.FieldPosition;
import java.text.NumberFormat;
import java.text.ParseException;

import java.util.Locale;
import java.util.Currency;

import static com.google.bitcoin.core.NetworkParameters.MAX_MONEY;
import static com.google.bitcoin.core.Coin.valueOf;
import static com.google.bitcoin.core.Coin.COIN;
import static com.google.bitcoin.utils.BtcFormat.CODED;

public class BtcFormatTest {
 
    @Test
    public void prefixTest() {
        BtcFormat usFormat = BtcFormat.getInstance(Locale.US);
        // int
        assertEquals("฿1.00", usFormat.format(100000000));
        assertEquals("฿1.01", usFormat.format(101000000));
        assertEquals("₥฿1,011.00", usFormat.format(101100000));
        assertEquals("₥฿1,000.01", usFormat.format(100001000));
        assertEquals("µ฿1,000,001", usFormat.format(100000100));
        assertEquals("µ฿1,000,000.10", usFormat.format(100000010));
        assertEquals("µ฿1,000,000.01", usFormat.format(100000001));
        // Double
        assertEquals("฿1.00", usFormat.format(new Double(1)));
        assertEquals("฿1.01", usFormat.format(new Double(1.01)));
        assertEquals("₥฿1,001.00", usFormat.format(new Double(1.001)));
        assertEquals("฿1,000.01", usFormat.format(new Double(1000.01)));
        assertEquals("₥฿1,000.01", usFormat.format(new Double(1.00001)));
        assertEquals("µ฿1,000,001", usFormat.format(new Double(1.000001)));
        assertEquals("µ฿1,000,000.10", usFormat.format(new Double(1.0000001)));
        assertEquals("µ฿1,000,000.01", usFormat.format(new Double(1.00000001)));
        assertEquals("฿0.00", usFormat.format(new Double(0.000000001)));
        assertEquals("µ฿0.01", usFormat.format(new Double(0.000000005)));
    }

    @Test
    public void suffixTest() {
        BtcFormat deFormat = BtcFormat.getInstance(Locale.GERMANY);
        // int
        assertEquals("1,00 ฿", deFormat.format(100000000));
        assertEquals("1,01 ฿", deFormat.format(101000000));
        assertEquals("1.011,00 ₥฿", deFormat.format(101100000));
        assertEquals("1.000,01 ₥฿", deFormat.format(100001000));
        assertEquals("1.000.001 µ฿", deFormat.format(100000100));
        assertEquals("1.000.000,10 µ฿", deFormat.format(100000010));
        assertEquals("1.000.000,01 µ฿", deFormat.format(100000001));
        // Double
        assertEquals("1,00 ฿", deFormat.format(new Double(1)));
        assertEquals("1,01 ฿", deFormat.format(new Double(1.01)));
        assertEquals("1.001,00 ₥฿", deFormat.format(new Double(1.001)));
        assertEquals("1.000,01 ฿", deFormat.format(new Double(1000.01)));
        assertEquals("1.000,01 ₥฿", deFormat.format(new Double(1.00001)));
        assertEquals("1.000.001 µ฿", deFormat.format(new Double(1.000001)));
        assertEquals("1.000.000,10 µ฿", deFormat.format(new Double(1.0000001)));
        assertEquals("1.000.000,01 µ฿", deFormat.format(new Double(1.00000001)));
        assertEquals("0,00 ฿", deFormat.format(new Double(0.000000001)));
        assertEquals("0,01 µ฿", deFormat.format(new Double(0.000000005)));

    }

    @Test
    public void defaultLocaleTest() {
        /* Test different factory methods:
         * Number pattern is the same with no locale or default locale */
        assertEquals(
            ((DecimalFormat)BtcFormat.getInstance().getNumberFormat()).toLocalizedPattern(),
            ((DecimalFormat)BtcFormat.getInstance(Locale.getDefault()).getNumberFormat()).toLocalizedPattern()
        );
        /* Likewise for currency-code pattern */
        assertEquals(
            ((DecimalFormat)BtcFormat.getInstance(CODED).getNumberFormat()).toLocalizedPattern(),
            ((DecimalFormat)BtcFormat.getInstance(CODED, Locale.getDefault()).getNumberFormat()).toLocalizedPattern()
        );
    }

    @Test
    public void symbolCollisionTest() {
        Locale[] locales = BtcFormat.getAvailableLocales();
        for (int i = 0; i < locales.length; ++i) {
            String cs = ((DecimalFormat)NumberFormat.getCurrencyInstance(locales[i])).
                        getDecimalFormatSymbols().getCurrencySymbol();
            if (cs.contains("฿")) {
                BtcFormat bf = BtcFormat.getInstance(locales[i]);
                String coin = bf.format(COIN);
                assertTrue(coin.contains("Ƀ"));
                assertFalse(coin.contains("฿"));
                String milli = bf.format(valueOf(10000));
                assertTrue(milli.contains("₥Ƀ"));
                assertFalse(milli.contains("฿"));
                String micro = bf.format(valueOf(100));
                assertTrue(micro.contains("µɃ"));
                assertFalse(micro.contains("฿"));
            }
            if (cs.contains("Ƀ")) {  // NB: We don't know of any such existing locale, but check anyway.
                BtcFormat bf = BtcFormat.getInstance(locales[i]);
                String coin = bf.format(COIN);
                assertTrue(coin.contains("฿"));
                assertFalse(coin.contains("Ƀ"));
                String milli = bf.format(valueOf(10000));
                assertTrue(milli.contains("₥฿"));
                assertFalse(milli.contains("Ƀ"));
                String micro = bf.format(valueOf(100));
                assertTrue(micro.contains("µ฿"));
                assertFalse(micro.contains("Ƀ"));
            }
        }
    }

    @Test
    public void argumentTypeTest() {
        BtcFormat usFormat = BtcFormat.getInstance(Locale.US);
        // longs are tested above
        // Coin
        assertEquals("µ฿1,000,000.01", usFormat.format(COIN.add(valueOf(1))));
        // Integer
        assertEquals("µ฿21,474,836.47" ,usFormat.format(Integer.MAX_VALUE));
        assertEquals("(µ฿21,474,836.48)" ,usFormat.format(Integer.MIN_VALUE));
        // Long
        assertEquals("µ฿92,233,720,368,547,758.07" ,usFormat.format(Long.MAX_VALUE));
        assertEquals("(µ฿92,233,720,368,547,758.08)" ,usFormat.format(Long.MIN_VALUE));
        // BigInteger
        assertEquals("µ฿0.10" ,usFormat.format(java.math.BigInteger.TEN));
        assertEquals("฿0.00" ,usFormat.format(java.math.BigInteger.ZERO));
        // BigDecimal
        assertEquals("฿1.00" ,usFormat.format(java.math.BigDecimal.ONE));
        assertEquals("฿0.00" ,usFormat.format(java.math.BigDecimal.ZERO));
        // Double, Float
        assertEquals(
            "฿179,769,313,486,231,570,000,000,000,000,000,000,000,000,000,000,000,000,000,000,000,000,000,000,000,000,000,000,000,000,000,000,000,000,000,000,000,000,000,000,000,000,000,000,000,000,000,000,000,000,000,000,000,000,000,000,000,000,000,000,000,000,000,000,000,000,000,000,000,000,000,000,000,000,000,000,000,000,000,000,000,000,000,000,000,000,000,000,000,000,000,000,000,000,000,000,000,000,000,000,000,000,000.00",
            usFormat.format(java.math.BigDecimal.valueOf(Double.MAX_VALUE)));
        assertEquals("฿0.00", usFormat.format(java.math.BigDecimal.valueOf(Double.MIN_VALUE)));
        assertEquals(
            "฿340,282,346,638,528,860,000,000,000,000,000,000,000.00",
            usFormat.format(java.math.BigDecimal.valueOf(Float.MAX_VALUE)));
        // Bad type
        try {
            usFormat.format("1");
            org.junit.Assert.fail("should not have tried to format a String");
        } catch (IllegalArgumentException e) {
        }
    }

    @Test
    public void characterIteratorTest() {
        BtcFormat usFormat = BtcFormat.getInstance(Locale.US);
        AttributedCharacterIterator i = usFormat.formatToCharacterIterator(1234.5);
        java.util.Set<Attribute> a = i.getAllAttributeKeys();
        assertTrue("Missing currency attribute", a.contains(NumberFormat.Field.CURRENCY));
        assertTrue("Missing integer attribute", a.contains(NumberFormat.Field.INTEGER));
        assertTrue("Missing fraction attribute", a.contains(NumberFormat.Field.FRACTION));
        assertTrue("Missing decimal separator attribute", a.contains(NumberFormat.Field.DECIMAL_SEPARATOR));
        assertTrue("Missing grouping separator attribute", a.contains(NumberFormat.Field.GROUPING_SEPARATOR));
        assertTrue("Missing currency attribute", a.contains(NumberFormat.Field.CURRENCY));

        char c;
        i = BtcFormat.getCodedInstance(Locale.US).formatToCharacterIterator(0.19246362747414458);
        // formatted as "µBTC 192,463.63"
        assertEquals(0, i.getBeginIndex());
        assertEquals(15, i.getEndIndex());
        int n = 0;
        for(c = i.first(); i.getAttribute(NumberFormat.Field.CURRENCY) != null; c = i.next()) {
            n++;
        }
        assertEquals(4, n);
        n = 0;
        for(i.next(); i.getAttribute(NumberFormat.Field.INTEGER) != null && i.getAttribute(NumberFormat.Field.GROUPING_SEPARATOR) != NumberFormat.Field.GROUPING_SEPARATOR; c = i.next()) {
            n++;
        }
        assertEquals(3, n);
        assertEquals(NumberFormat.Field.INTEGER, i.getAttribute(NumberFormat.Field.INTEGER));
        n = 0;
        for(c = i.next(); i.getAttribute(NumberFormat.Field.INTEGER) != null; c = i.next()) {
            n++;
        }
        assertEquals(3, n);
        assertEquals(NumberFormat.Field.DECIMAL_SEPARATOR, i.getAttribute(NumberFormat.Field.DECIMAL_SEPARATOR));
        n = 0;
        for(c = i.next(); c != CharacterIterator.DONE; c = i.next()) {
            n++;
            assertNotNull(i.getAttribute(NumberFormat.Field.FRACTION));
        }
        assertEquals(2,n);
    }

    @Test
    public void parseTest() throws java.text.ParseException {
        BtcFormat us = BtcFormat.getInstance(Locale.US);
        BtcFormat usCoded = BtcFormat.getInstance(BtcFormat.CODED, Locale.US);
        // Coins
        assertEquals(valueOf(200000000), us.parseObject("BTC2"));
        assertEquals(valueOf(200000000), us.parseObject("฿2"));
        assertEquals(valueOf(200000000), us.parseObject("Ƀ2"));
        assertEquals(valueOf(200000000), us.parseObject("2"));
        assertEquals(valueOf(200000000), usCoded.parseObject("BTC 2"));
        assertEquals(valueOf(200000000), us.parseObject("฿2.0"));
        assertEquals(valueOf(200000000), us.parseObject("Ƀ2.0"));
        assertEquals(valueOf(200000000), us.parseObject("2.0"));
        assertEquals(valueOf(200000000), us.parseObject("BTC2.0"));
        assertEquals(valueOf(200000000), usCoded.parseObject("฿ 2"));
        assertEquals(valueOf(200000000), usCoded.parseObject("Ƀ 2"));
        assertEquals(valueOf(200000000), usCoded.parseObject(" 2"));
        assertEquals(valueOf(200000000), usCoded.parseObject("BTC 2"));
        assertEquals(valueOf(202222420000000L), us.parseObject("2,022,224.20"));
        assertEquals(valueOf(202222420000000L), us.parseObject("฿2,022,224.20"));
        assertEquals(valueOf(202222420000000L), us.parseObject("Ƀ2,022,224.20"));
        assertEquals(valueOf(202222420000000L), us.parseObject("BTC2,022,224.20"));
        assertEquals(valueOf(220200000000L), us.parseObject("2,202.0"));
        assertEquals(valueOf(2100000000000000L), us.parseObject("21000000.00000000"));
        // MilliCoins
        assertEquals(valueOf(200000), usCoded.parseObject("mBTC 2"));
        assertEquals(valueOf(200000), usCoded.parseObject("m฿ 2"));
        assertEquals(valueOf(200000), usCoded.parseObject("mɃ 2"));
        assertEquals(valueOf(200000), us.parseObject("mBTC2"));
        assertEquals(valueOf(200000), us.parseObject("₥฿2"));
        assertEquals(valueOf(200000), us.parseObject("₥Ƀ2"));
        assertEquals(valueOf(200000), us.parseObject("₥2"));
        assertEquals(valueOf(200000), usCoded.parseObject("₥BTC 2.00"));
        assertEquals(valueOf(200000), usCoded.parseObject("₥BTC 2"));
        assertEquals(valueOf(200000), usCoded.parseObject("₥฿ 2"));
        assertEquals(valueOf(200000), usCoded.parseObject("₥Ƀ 2"));
        assertEquals(valueOf(200000), usCoded.parseObject("₥ 2"));
        assertEquals(valueOf(202222400000L), us.parseObject("₥฿2,022,224"));
        assertEquals(valueOf(202222420000L), us.parseObject("₥Ƀ2,022,224.20"));
        assertEquals(valueOf(202222400000L), us.parseObject("m฿2,022,224"));
        assertEquals(valueOf(202222420000L), us.parseObject("mɃ2,022,224.20"));
        assertEquals(valueOf(202222400000L), us.parseObject("₥BTC2,022,224"));
        assertEquals(valueOf(202222400000L), us.parseObject("mBTC2,022,224"));
        assertEquals(valueOf(202222420000L), us.parseObject("₥2,022,224.20"));
        assertEquals(valueOf(202222400000L), usCoded.parseObject("₥฿ 2,022,224"));
        assertEquals(valueOf(202222420000L), usCoded.parseObject("₥Ƀ 2,022,224.20"));
        assertEquals(valueOf(202222400000L), usCoded.parseObject("m฿ 2,022,224"));
        assertEquals(valueOf(202222420000L), usCoded.parseObject("mɃ 2,022,224.20"));
        assertEquals(valueOf(202222400000L), usCoded.parseObject("₥BTC 2,022,224"));
        assertEquals(valueOf(202222400000L), usCoded.parseObject("mBTC 2,022,224"));
        assertEquals(valueOf(202222420000L), usCoded.parseObject("₥ 2,022,224.20"));
        // Microcoins
        assertEquals(valueOf(435), us.parseObject("µ฿4.35"));
        assertEquals(valueOf(435), us.parseObject("uɃ4.35"));
        assertEquals(valueOf(435), us.parseObject("u฿4.35"));
        assertEquals(valueOf(435), us.parseObject("µɃ4.35"));
        assertEquals(valueOf(435), us.parseObject("uBTC4.35"));
        assertEquals(valueOf(435), us.parseObject("µBTC4.35"));
        assertEquals(valueOf(435), usCoded.parseObject("uBTC 4.35"));
        assertEquals(valueOf(435), usCoded.parseObject("µBTC 4.35"));
        // fractional satoshi; round up
        assertEquals(valueOf(435), us.parseObject("uBTC4.345"));
        // negative with mu symbol
        assertEquals(valueOf(-1), usCoded.parseObject("(µ฿ 0.01)"));
        assertEquals(valueOf(-10), us.parseObject("(µBTC0.100)"));
    }

    @Test
    public void parsePositionTest() {
        BtcFormat usCoded = BtcFormat.getCodedInstance(Locale.US);
        // Test the field constants
        FieldPosition intField = new FieldPosition(NumberFormat.Field.INTEGER);
        assertEquals(
          "987,654,321",
          usCoded.format(valueOf(98765432123L), new StringBuffer(), intField).
          substring(intField.getBeginIndex(), intField.getEndIndex())
        );
        FieldPosition fracField = new FieldPosition(NumberFormat.Field.FRACTION);
        assertEquals(
          "23",
          usCoded.format(valueOf(98765432123L), new StringBuffer(), fracField).
          substring(fracField.getBeginIndex(), fracField.getEndIndex())
        );

        // for currency we use a locale that puts the units at the end
        BtcFormat de = BtcFormat.getInstance(Locale.GERMANY);
        BtcFormat deCoded = BtcFormat.getCodedInstance(Locale.GERMANY);
        FieldPosition currField = new FieldPosition(NumberFormat.Field.CURRENCY);
        assertEquals(
          "µ฿",
          de.format(valueOf(98765432123L), new StringBuffer(), currField).
          substring(currField.getBeginIndex(), currField.getEndIndex())
        );
        assertEquals(
          "µBTC",
          deCoded.format(valueOf(98765432123L), new StringBuffer(), currField).
          substring(currField.getBeginIndex(), currField.getEndIndex())
        );
        assertEquals(
          "₥฿",
          de.format(valueOf(98765432000L), new StringBuffer(), currField).
          substring(currField.getBeginIndex(), currField.getEndIndex())
        );
        assertEquals(
          "mBTC",
          deCoded.format(valueOf(98765432000L), new StringBuffer(), currField).
          substring(currField.getBeginIndex(), currField.getEndIndex())
        );
        assertEquals(
          "฿",
          de.format(valueOf(98765000000L), new StringBuffer(), currField).
          substring(currField.getBeginIndex(), currField.getEndIndex())
        );
        assertEquals(
          "BTC",
          deCoded.format(valueOf(98765000000L), new StringBuffer(), currField).
          substring(currField.getBeginIndex(), currField.getEndIndex())
        );
    }

    @Test
    public void currencyCodeTest() {
        /* Insert needed space AFTER currency-code */
        BtcFormat usCoded = BtcFormat.getInstance(BtcFormat.CODED, Locale.US);
        assertEquals("µBTC 0.01", usCoded.format(1));
        assertEquals("BTC 1.00", usCoded.format(COIN));

        /* Do not insert unneeded space BEFORE currency-code */
        BtcFormat frCoded = BtcFormat.getInstance(BtcFormat.CODED, Locale.FRANCE);
        assertEquals("0,01 µBTC", frCoded.format(1));
        assertEquals("1,00 BTC", frCoded.format(COIN));

        /* Insert needed space BEFORE currency-code: no known currency pattern does this? */

        /* Do not insert unneeded space AFTER currency-code */
        BtcFormat deCoded = BtcFormat.getInstance(BtcFormat.CODED, Locale.ITALY);
        assertEquals("µBTC 0,01", deCoded.format(1));
        assertEquals("BTC 1,00", deCoded.format(COIN));
    }

}
