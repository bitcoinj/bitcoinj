package com.subgraph.orchid.directory.certificate;

import com.subgraph.orchid.KeyCertificate;
import com.subgraph.orchid.TorParsingException;
import com.subgraph.orchid.crypto.TorPublicKey;
import com.subgraph.orchid.crypto.TorSignature;
import com.subgraph.orchid.data.IPv4Address;
import com.subgraph.orchid.directory.parsing.BasicDocumentParsingResult;
import com.subgraph.orchid.directory.parsing.DocumentFieldParser;
import com.subgraph.orchid.directory.parsing.DocumentParser;
import com.subgraph.orchid.directory.parsing.DocumentParsingHandler;
import com.subgraph.orchid.directory.parsing.DocumentParsingResult;
import com.subgraph.orchid.directory.parsing.DocumentParsingResultHandler;

public class KeyCertificateParser implements DocumentParser<KeyCertificate> {
	private final static int CURRENT_CERTIFICATE_VERSION = 3;
	private final DocumentFieldParser fieldParser;
	private KeyCertificateImpl currentCertificate;
	private DocumentParsingResultHandler<KeyCertificate> resultHandler;
	
	public KeyCertificateParser(DocumentFieldParser fieldParser) {
		this.fieldParser = fieldParser;
		this.fieldParser.setHandler(createParsingHandler());
	}
	
	private DocumentParsingHandler createParsingHandler() {
		return new DocumentParsingHandler() {
			public void parseKeywordLine() {
				processKeywordLine();
			}
			
			public void endOfDocument() {
			}
		};
	}
	
	private void processKeywordLine() {
		final KeyCertificateKeyword keyword = KeyCertificateKeyword.findKeyword(fieldParser.getCurrentKeyword());
		/*
		 * dirspec.txt (1.2)
		 * When interpreting a Document, software MUST ignore any KeywordLine that
		 * starts with a keyword it doesn't recognize;
		 */
		if(!keyword.equals(KeyCertificateKeyword.UNKNOWN_KEYWORD))
			processKeyword(keyword);
	}
	
	private void startNewCertificate() {
		fieldParser.resetRawDocument();
		fieldParser.startSignedEntity();
		currentCertificate = new KeyCertificateImpl();
	}
	
	public boolean parse(DocumentParsingResultHandler<KeyCertificate> resultHandler) {
		this.resultHandler = resultHandler;
		startNewCertificate();
		try {
			fieldParser.processDocument();
			return true;
		} catch(TorParsingException e) {
			resultHandler.parsingError(e.getMessage());
			return false;
		}
	}
	
	public DocumentParsingResult<KeyCertificate> parse() {
		final BasicDocumentParsingResult<KeyCertificate> result = new BasicDocumentParsingResult<KeyCertificate>();
		parse(result);
		return result;
	}

	private void processKeyword(KeyCertificateKeyword keyword) {
		switch(keyword) {
		case DIR_KEY_CERTIFICATE_VERSION:
			processCertificateVersion();
			break;
		case DIR_ADDRESS:
			processDirectoryAddress();
			break;
		case FINGERPRINT:
			currentCertificate.setAuthorityFingerprint(fieldParser.parseHexDigest());
			break;
		case DIR_IDENTITY_KEY:
			currentCertificate.setAuthorityIdentityKey(fieldParser.parsePublicKey());
			break;
		case DIR_SIGNING_KEY:
			currentCertificate.setAuthoritySigningKey(fieldParser.parsePublicKey());
			break;
		case DIR_KEY_PUBLISHED:
			currentCertificate.setKeyPublishedTime(fieldParser.parseTimestamp());
			break;
		case DIR_KEY_EXPIRES:
			currentCertificate.setKeyExpiryTime(fieldParser.parseTimestamp());
			break;
		case DIR_KEY_CROSSCERT:
			verifyCrossSignature(fieldParser.parseSignature());
			break;
		case DIR_KEY_CERTIFICATION:
			processCertificateSignature();
			break;
		case UNKNOWN_KEYWORD:
			break;
		}
	}
	
	private void processCertificateVersion() {
		final int version = fieldParser.parseInteger();
		if(version != CURRENT_CERTIFICATE_VERSION)
			throw new TorParsingException("Unexpected certificate version: " + version);
	}
	
	private void processDirectoryAddress() {
		final String addrport = fieldParser.parseString();
		final String[] args = addrport.split(":");
		if(args.length != 2)
			throw new TorParsingException("Address/Port string incorrectly formed: " + addrport);
		currentCertificate.setDirectoryAddress(IPv4Address.createFromString(args[0]));
		currentCertificate.setDirectoryPort(fieldParser.parsePort(args[1]));
	}
	
	private void verifyCrossSignature(TorSignature crossSignature) {
		TorPublicKey identityKey = currentCertificate.getAuthorityIdentityKey();
		TorPublicKey signingKey = currentCertificate.getAuthoritySigningKey();
		if(!signingKey.verifySignature(crossSignature, identityKey.getFingerprint())) 
			throw new TorParsingException("Cross signature on certificate failed.");
	}

	private boolean verifyCurrentCertificate(TorSignature signature) {
		if(!fieldParser.verifySignedEntity(currentCertificate.getAuthorityIdentityKey(), signature)) {
			resultHandler.documentInvalid(currentCertificate, "Signature failed");
			fieldParser.logWarn("Signature failed for certificate with fingerprint: "+ currentCertificate.getAuthorityFingerprint());
			return false;
		}
		currentCertificate.setValidSignature();
		final boolean isValid = currentCertificate.isValidDocument();
		if(!isValid) {
			resultHandler.documentInvalid(currentCertificate, "Certificate data is invalid");
			fieldParser.logWarn("Certificate data is invalid for certificate with fingerprint: "+ currentCertificate.getAuthorityFingerprint());
		}
		return isValid;
	}
	
	private void processCertificateSignature() {
		fieldParser.endSignedEntity();
		if(verifyCurrentCertificate(fieldParser.parseSignature())) {
			currentCertificate.setRawDocumentData(fieldParser.getRawDocument());
			resultHandler.documentParsed(currentCertificate);
		}
		startNewCertificate();
	}
}
