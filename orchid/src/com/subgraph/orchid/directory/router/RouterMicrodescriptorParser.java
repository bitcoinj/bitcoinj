package com.subgraph.orchid.directory.router;

import com.subgraph.orchid.RouterMicrodescriptor;
import com.subgraph.orchid.TorParsingException;
import com.subgraph.orchid.crypto.TorMessageDigest;
import com.subgraph.orchid.directory.parsing.BasicDocumentParsingResult;
import com.subgraph.orchid.directory.parsing.DocumentFieldParser;
import com.subgraph.orchid.directory.parsing.DocumentParser;
import com.subgraph.orchid.directory.parsing.DocumentParsingHandler;
import com.subgraph.orchid.directory.parsing.DocumentParsingResult;
import com.subgraph.orchid.directory.parsing.DocumentParsingResultHandler;

public class RouterMicrodescriptorParser implements DocumentParser<RouterMicrodescriptor>{

	
	private final DocumentFieldParser fieldParser;
	
	private RouterMicrodescriptorImpl currentDescriptor;
	private DocumentParsingResultHandler<RouterMicrodescriptor> resultHandler;
	
	public RouterMicrodescriptorParser(DocumentFieldParser fieldParser) {
		this.fieldParser = fieldParser;
		this.fieldParser.setHandler(createParsingHandler());
	}

	private DocumentParsingHandler createParsingHandler() {
		return new DocumentParsingHandler() {
			public void parseKeywordLine() {
				processKeywordLine();
			}
			public void endOfDocument() { 
				if(currentDescriptor != null) {
					finalizeDescriptor(currentDescriptor);
				}
			}
		};
	}
	
	public boolean parse(DocumentParsingResultHandler<RouterMicrodescriptor> resultHandler) {
		this.resultHandler = resultHandler;
		try {
			fieldParser.processDocument();
			return true;
		} catch(TorParsingException e) {
			resultHandler.parsingError(e.getMessage());
			return false;
		}
	}

	public DocumentParsingResult<RouterMicrodescriptor> parse() {
		final BasicDocumentParsingResult<RouterMicrodescriptor> result = new BasicDocumentParsingResult<RouterMicrodescriptor>();
		parse(result);
		return result;
	}

	private void processKeywordLine() {
		final RouterMicrodescriptorKeyword keyword = RouterMicrodescriptorKeyword.findKeyword(fieldParser.getCurrentKeyword());
		if(!keyword.equals(RouterMicrodescriptorKeyword.UNKNOWN_KEYWORD)) {
			processKeyword(keyword);
		}
		if(currentDescriptor != null) {
			currentDescriptor.setRawDocumentData(fieldParser.getRawDocument());
		}

	}
	

	private void processKeyword(RouterMicrodescriptorKeyword keyword) {
		fieldParser.verifyExpectedArgumentCount(keyword.getKeyword(), keyword.getArgumentCount());
		switch(keyword) {
		case ONION_KEY:
			processOnionKeyLine();
			break;
			
		case NTOR_ONION_KEY:
			if(currentDescriptor != null) {
				currentDescriptor.setNtorOnionKey(fieldParser.parseNtorPublicKey());
			}
			break;
			
		case FAMILY:
			while(fieldParser.argumentsRemaining() > 0 && currentDescriptor != null) {
				currentDescriptor.addFamilyMember(fieldParser.parseString());
			}
			break;
		
		case P:
			processP();
			break;
	
		case A:
		default:
			break;
		}
	}
	
	private void processOnionKeyLine() {
		if(currentDescriptor != null) {
			finalizeDescriptor(currentDescriptor);
		}
		currentDescriptor = new RouterMicrodescriptorImpl();
		fieldParser.resetRawDocument(RouterMicrodescriptorKeyword.ONION_KEY.getKeyword() + "\n");
		currentDescriptor.setOnionKey(fieldParser.parsePublicKey());
	}

	private void finalizeDescriptor(RouterMicrodescriptorImpl descriptor) {
		final TorMessageDigest digest = new TorMessageDigest(true);
		digest.update(descriptor.getRawDocumentData());
		descriptor.setDescriptorDigest(digest.getHexDigest());
		if(!descriptor.isValidDocument()) {
			resultHandler.documentInvalid(descriptor, "Microdescriptor data invalid");
		} else {
			resultHandler.documentParsed(descriptor);
		}
	}

	private void processP() {
		if(currentDescriptor == null) {
			return;
		}
		final String ruleType = fieldParser.parseString();
		if("accept".equals(ruleType)) {
			currentDescriptor.addAcceptPorts(fieldParser.parseString());
		} else if("reject".equals(ruleType)) {
			currentDescriptor.addRejectPorts(fieldParser.parseString());
		} else {
			fieldParser.logWarn("Unexpected P field in microdescriptor: "+ ruleType);
		}
	}
}
