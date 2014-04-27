package com.subgraph.orchid.circuits.hs;

import java.nio.ByteBuffer;
import java.util.logging.Logger;

import com.subgraph.orchid.TorParsingException;
import com.subgraph.orchid.crypto.TorSignature;
import com.subgraph.orchid.directory.DocumentFieldParserImpl;
import com.subgraph.orchid.directory.parsing.BasicDocumentParsingResult;
import com.subgraph.orchid.directory.parsing.DocumentFieldParser;
import com.subgraph.orchid.directory.parsing.DocumentObject;
import com.subgraph.orchid.directory.parsing.DocumentParser;
import com.subgraph.orchid.directory.parsing.DocumentParsingHandler;
import com.subgraph.orchid.directory.parsing.DocumentParsingResult;
import com.subgraph.orchid.directory.parsing.DocumentParsingResultHandler;
import com.subgraph.orchid.encoders.Base64;

public class HSDescriptorParser implements DocumentParser<HSDescriptor>{
	private static final Logger logger = Logger.getLogger(HSDescriptor.class.getName());
	
	private final DocumentFieldParser fieldParser;
	private final HSDescriptor descriptor;
	private final HSAuthentication authentication;
	
	private DocumentParsingResultHandler<HSDescriptor> resultHandler;
	
	public HSDescriptorParser(HiddenService hiddenService, DocumentFieldParser fieldParser) {
		this(hiddenService, fieldParser, null);
	}

	public HSDescriptorParser(HiddenService hiddenService, DocumentFieldParser fieldParser, HSDescriptorCookie cookie) {
		this.fieldParser = fieldParser;
		this.fieldParser.setHandler(createParsingHandler());
		this.descriptor = new HSDescriptor(hiddenService);
		this.authentication = new HSAuthentication(cookie);
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

	public boolean parse(DocumentParsingResultHandler<HSDescriptor> resultHandler) {
		this.resultHandler = resultHandler;
		fieldParser.startSignedEntity();
		try {
			fieldParser.processDocument();
			return true;
		} catch(TorParsingException e) {
			resultHandler.parsingError(e.getMessage());
			return false;
		}
	}
	
	
	public DocumentParsingResult<HSDescriptor> parse() {
		final BasicDocumentParsingResult<HSDescriptor> result = new BasicDocumentParsingResult<HSDescriptor>();
		parse(result);
		return result;
	}

	private void processKeywordLine() {
		final HSDescriptorKeyword keyword = HSDescriptorKeyword.findKeyword(fieldParser.getCurrentKeyword());
		if(!keyword.equals(HSDescriptorKeyword.UNKNOWN_KEYWORD)) {
			processKeyword(keyword);
		}
	}
	
	private void processKeyword(HSDescriptorKeyword keyword) {
		switch(keyword) {
		case RENDEZVOUS_SERVICE_DESCRIPTOR:
			descriptor.setDescriptorId(fieldParser.parseBase32Digest());
			break;
		case VERSION:
			if(fieldParser.parseInteger() != 2) {
				throw new TorParsingException("Unexpected Descriptor version");
			}
			break;
			
		case PERMANENT_KEY:
			descriptor.setPermanentKey(fieldParser.parsePublicKey());
			break;
			
		case SECRET_ID_PART:
			descriptor.setSecretIdPart(fieldParser.parseBase32Digest());
			break;
			
		case PUBLICATION_TIME:
			descriptor.setPublicationTime(fieldParser.parseTimestamp());
			break;
			
		case PROTOCOL_VERSIONS:
			descriptor.setProtocolVersions(fieldParser.parseIntegerList());
			break;
			
		case INTRODUCTION_POINTS:
			processIntroductionPoints();
			break;
			
		case SIGNATURE:
			processSignature();
			break;
		case UNKNOWN_KEYWORD:
			break;
		}
	}
	
	private void processIntroductionPoints() {
		final DocumentObject ob = fieldParser.parseObject();
		final ByteBuffer buffer = createIntroductionPointBuffer(ob);
		final IntroductionPointParser parser = new IntroductionPointParser(new DocumentFieldParserImpl(buffer));
		parser.parse(new DocumentParsingResultHandler<IntroductionPoint>() {

			public void documentParsed(IntroductionPoint document) {
				logger.fine("adding intro point "+ document.getIdentity());
				descriptor.addIntroductionPoint(document);
			}

			public void documentInvalid(IntroductionPoint document, String message) {
				logger.info("Invalid introduction point received");
			}

			public void parsingError(String message) {
				logger.info("Error parsing introduction points: "+ message);
			} 
		});
	}

	private ByteBuffer createIntroductionPointBuffer(DocumentObject ob) {
		final byte[] content = Base64.decode(ob.getContent(false));
		if(content[0] == 'i') {
			return ByteBuffer.wrap(content);
		} else {
			try {
				byte[] decrypted = authentication.decryptIntroductionPoints(content);
				return ByteBuffer.wrap(decrypted);
			} catch (HSAuthenticationException e) {
				throw new TorParsingException("Failed to decrypt introduction points: "+ e.getMessage());
			}
		}
	}

	private void processSignature() {
		fieldParser.endSignedEntity();
		final TorSignature signature = fieldParser.parseSignature();
		if(!fieldParser.verifySignedEntity(descriptor.getPermanentKey(), signature)) {
			resultHandler.documentInvalid(descriptor, "Signature verification failed");
			fieldParser.logWarn("Signature failed for descriptor: "+ descriptor.getDescriptorId().toBase32());
			return;
		}
		resultHandler.documentParsed(descriptor);
	}
}
