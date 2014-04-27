package com.subgraph.orchid.crypto;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.List;

import com.subgraph.orchid.crypto.ASN1Parser.ASN1BitString;
import com.subgraph.orchid.crypto.ASN1Parser.ASN1Integer;
import com.subgraph.orchid.crypto.ASN1Parser.ASN1Object;
import com.subgraph.orchid.crypto.ASN1Parser.ASN1Sequence;
import com.subgraph.orchid.encoders.Base64;

public class RSAKeyEncoder {
	private final static String HEADER = "-----BEGIN RSA PUBLIC KEY-----";
	private final static String FOOTER = "-----END RSA PUBLIC KEY-----";
	
	private final ASN1Parser asn1Parser = new ASN1Parser();
	
	/**
	 * Parse a PKCS1 PEM encoded RSA public key into the modulus/exponent components
	 * and construct a new RSAPublicKey
	 *  
	 * @param pem The PEM encoded string to parse.
	 * @return a new RSAPublicKey
	 * 
	 * @throws GeneralSecurityException If an error occurs while parsing the pem argument or creating the RSA key.
	 */
	public RSAPublicKey parsePEMPublicKey(String pem) throws GeneralSecurityException {
		try {
			byte[] bs = decodeAsciiArmoredPEM(pem);
			ByteBuffer data = ByteBuffer.wrap(bs);
			final ASN1Object ob = asn1Parser.parseASN1(data);
			final List<ASN1Object> seq = asn1ObjectToSequence(ob, 2);
			final BigInteger modulus = asn1ObjectToBigInt(seq.get(0));
			final BigInteger exponent = asn1ObjectToBigInt(seq.get(1));
			return createKeyFromModulusAndExponent(modulus, exponent);
		} catch (IllegalArgumentException e) {
			throw new InvalidKeyException();
		}
	}

	private RSAPublicKey createKeyFromModulusAndExponent(BigInteger modulus, BigInteger exponent) throws GeneralSecurityException {
		RSAPublicKeySpec spec = new RSAPublicKeySpec(modulus, exponent);
		KeyFactory fac = KeyFactory.getInstance("RSA");
		return (RSAPublicKey) fac.generatePublic(spec);
	}

	/**
	 * Return the PKCS1 encoded representation of the specified RSAPublicKey.  Since 
	 * the primary encoding format for RSA public keys is X.509 SubjectPublicKeyInfo,
	 * this needs to be converted to PKCS1 by extracting the needed field.
	 * 
	 * @param publicKey The RSA public key to encode.
	 * @return The PKCS1 encoded representation of the publicKey argument
	 */
	public byte[] getPKCS1Encoded(RSAPublicKey publicKey) {
		return extractPKCS1KeyFromSubjectPublicKeyInfo(publicKey.getEncoded());
	}

	/*
	 * SubjectPublicKeyInfo encoding looks like this:
	 * 
	 * SEQUENCE {
	 *     SEQUENCE {
	 *         OBJECT IDENTIFIER rsaEncryption (1 2 840 113549 1 1 1)
	 *         NULL
	 *     }
	 *     BIT STRING (encapsulating) {  <-- contains PKCS1 encoded key
	 *         SEQUENCE {
	 *             INTEGER (modulus)
	 *             INTEGER (exponent)
	 *         }
	 *     }
	 * }
	 * 
	 * See: http://www.jensign.com/JavaScience/dotnet/JKeyNet/index.html
	 */
	private byte[] extractPKCS1KeyFromSubjectPublicKeyInfo(byte[] input) {
		final ASN1Object ob = asn1Parser.parseASN1(ByteBuffer.wrap(input));
		final List<ASN1Object> seq = asn1ObjectToSequence(ob, 2);
		return asn1ObjectToBitString(seq.get(1));
	}
	
	private BigInteger asn1ObjectToBigInt(ASN1Object ob) {
		if(!(ob instanceof ASN1Integer)) {
			throw new IllegalArgumentException();
		}
		final ASN1Integer n = (ASN1Integer) ob;
		return n.getValue();
	}
	

	private List<ASN1Object> asn1ObjectToSequence(ASN1Object ob, int expectedSize) {
		if(ob instanceof ASN1Sequence) {
			final ASN1Sequence seq = (ASN1Sequence) ob;
			if(seq.getItems().size() != expectedSize) {
				throw new IllegalArgumentException();
			}
			return seq.getItems();
		}
		throw new IllegalArgumentException();
	}

	private byte[] asn1ObjectToBitString(ASN1Object ob) {
		if(!(ob instanceof ASN1BitString)) {
			throw new IllegalArgumentException();
		}
		final ASN1BitString bitstring = (ASN1BitString) ob;
		return bitstring.getBytes();
	}

	private byte[] decodeAsciiArmoredPEM(String pem) {
		final String trimmed = removeDelimiters(pem);
		return Base64.decode(trimmed);
	}
	
	private String removeDelimiters(String pem) {
		final int headerIdx = pem.indexOf(HEADER);
		final int footerIdx = pem.indexOf(FOOTER);
		if(headerIdx == -1 || footerIdx == -1 || footerIdx <= headerIdx) {
			throw new IllegalArgumentException("PEM object not formatted with expected header and footer");
		}
		return pem.substring(headerIdx + HEADER.length(), footerIdx);
	}

}
