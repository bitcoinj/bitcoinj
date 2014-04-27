package com.subgraph.orchid.crypto;

import static org.junit.Assert.assertEquals;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.interfaces.RSAPublicKey;

import org.junit.Before;
import org.junit.Test;

public class RSAKeyEncoderTest {

	private RSAKeyEncoder encoder;
	
	final static String PEM_ENCODED_PUBKEY =
			
			"-----BEGIN RSA PUBLIC KEY-----\n"+
			"MIGJAoGBAMuf0v+d3HUNk5jbYJuZA+q30NlqFStNBmB/BA4y6h9DTpJ2ULhdy6I8\n"+
			"5tLq76TSTbGl2wiWpDjW73OkAfpbUyb+2fIFz4Ildth18ZA4dqNvnYNCnckO1p+B\n"+
			"x6e+8YoafedZhXsv1Z9RMl6WK6WGXpmgCSTTlLnXlrsJLrG/mW9dAgMBAAE=\n"+
			"-----END RSA PUBLIC KEY-----\n";
	
	final static String MODULUS_STRING =
			
			"142989855534119842624281223201112183062179043858844190077277374317180853428"+
			"067855510754484639210124041049484315690046733530717435491654607786952431473"+
			"291786675652833142146809594339105386135143284841697658385761023403765912288"+
			"684940376854709443039663769117423844056151668935507268155717373127166136614"+
			"724923229";
	
	final static BigInteger MODULUS = new BigInteger(MODULUS_STRING);
	final static BigInteger EXPONENT = BigInteger.valueOf(65537);
	
	@Before
	public void setup() {
		encoder = new RSAKeyEncoder();
	}
	
	@Test
	public void testParsePEMPublicKey() throws GeneralSecurityException {
		final RSAPublicKey publicKey = encoder.parsePEMPublicKey(PEM_ENCODED_PUBKEY);
		assertEquals(MODULUS, publicKey.getModulus());
		assertEquals(EXPONENT, publicKey.getPublicExponent());
	}
	
	@Test(expected=InvalidKeyException.class)
	public void testParsePEMPublicKeyException() throws GeneralSecurityException {
		encoder.parsePEMPublicKey(PEM_ENCODED_PUBKEY.substring(1));
	}

}
