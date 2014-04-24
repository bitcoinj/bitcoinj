package com.subgraph.orchid.crypto;

import static org.junit.Assert.*;

import java.math.BigInteger;
import java.nio.ByteBuffer;

import org.junit.Before;
import org.junit.Test;

import com.subgraph.orchid.crypto.ASN1Parser.ASN1BitString;
import com.subgraph.orchid.crypto.ASN1Parser.ASN1Integer;
import com.subgraph.orchid.encoders.Hex;

public class ASN1ParserTest {

	private ASN1Parser parser;
	
	@Before
	public void setup() {
		parser = new ASN1Parser();
	}
	
	ByteBuffer createBuffer(String hexData) {
		final byte[] bs = Hex.decode(hexData);
		return ByteBuffer.wrap(bs);
	}
	
	
	
	@Test
	public void testParseASN1Length() {
		assertEquals(20, parser.parseASN1Length(createBuffer("14000000")));
		assertEquals(23, parser.parseASN1Length(createBuffer("81170000")));
		assertEquals(256, parser.parseASN1Length(createBuffer("82010000")));
		assertEquals(65535, parser.parseASN1Length(createBuffer("82FFFF00")));
	}
	
	@Test(expected=IllegalArgumentException.class)
	public void testParseASN1LengthException() {
		parser.parseASN1Length(createBuffer("80ACDCACDC"));
	}
	
	@Test(expected=IllegalArgumentException.class)
	public void testParseASN1LengthException2() {
		parser.parseASN1Length(createBuffer("88ABCDABCD"));
	}
	
	@Test
	public void testParseASN1Integer() {
		ASN1Integer asn1Integer = parser.parseASN1Integer(createBuffer("01020304"));
		assertEquals(new BigInteger("01020304", 16), asn1Integer.getValue());
	}
	
	@Test
	public void testParseASN1BitString() {
		ASN1BitString bitString = parser.parseASN1BitString(createBuffer("0001020304"));
		assertArrayEquals(new byte[] {1, 2, 3, 4}, bitString.getBytes());
	}
	
	@Test(expected=IllegalArgumentException.class)
	public void testParseASN1BitStringException() {
		parser.parseASN1BitString(createBuffer("01020304"));
	}
}
