package com.subgraph.orchid.crypto;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.StringReader;
import java.util.Arrays;

import com.subgraph.orchid.TorException;
import com.subgraph.orchid.TorParsingException;
import com.subgraph.orchid.encoders.Base64;
import com.subgraph.orchid.encoders.Hex;

public class TorSignature {
	private final static String SIGNATURE_BEGIN = "-----BEGIN SIGNATURE-----";
	private final static String ID_SIGNATURE_BEGIN = "-----BEGIN ID SIGNATURE-----"; 
	private final static String SIGNATURE_END = "-----END SIGNATURE-----";
	private final static String ID_SIGNATURE_END = "-----END ID SIGNATURE-----";

	static public TorSignature createFromPEMBuffer(String buffer) {
		BufferedReader reader = new BufferedReader(new StringReader(buffer));
		final String header = nextLine(reader);
		if(!(SIGNATURE_BEGIN.equals(header) || ID_SIGNATURE_BEGIN.equals(header)))
			throw new TorParsingException("Did not find expected signature BEGIN header");
		return new TorSignature(Base64.decode(parseBase64Data(reader)), DigestAlgorithm.DIGEST_SHA1);	
	}
	static private String parseBase64Data(BufferedReader reader) {
		final StringBuilder base64Data = new StringBuilder();
		while(true) {
			final String line = nextLine(reader);
			if(SIGNATURE_END.equals(line) || ID_SIGNATURE_END.equals(line))
				return base64Data.toString();
			base64Data.append(line);
		}
	}
	static String nextLine(BufferedReader reader) {
		try {
			final String line = reader.readLine();
			if(line == null) 
				throw new TorParsingException("Did not find expected signature END header");
			return line;
		} catch (IOException e) {
			throw new TorException(e);
		}
	}

	public enum DigestAlgorithm { DIGEST_SHA1, DIGEST_SHA256 };

	private final byte[] signatureBytes;
	private final DigestAlgorithm digestAlgorithm;
	
	private TorSignature(byte[] signatureBytes, DigestAlgorithm digestAlgorithm) {
		this.signatureBytes = signatureBytes;
		this.digestAlgorithm = digestAlgorithm;
	}

	
	public byte[] getSignatureBytes() {
		return Arrays.copyOf(signatureBytes, signatureBytes.length);
	}
	
	public boolean verify(TorPublicKey publicKey, TorMessageDigest digest) {
		return publicKey.verifySignature(this, digest);
	}
	
	public DigestAlgorithm getDigestAlgorithm() {
		return digestAlgorithm;
	}

	public String toString() {
		return "TorSignature: (" + signatureBytes.length + " bytes) " + new String(Hex.encode(signatureBytes));
	}
	
	

}
