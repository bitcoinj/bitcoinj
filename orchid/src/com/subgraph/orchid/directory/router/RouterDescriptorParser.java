package com.subgraph.orchid.directory.router;

import com.subgraph.orchid.RouterDescriptor;
import com.subgraph.orchid.TorParsingException;
import com.subgraph.orchid.crypto.TorSignature;
import com.subgraph.orchid.data.BandwidthHistory;
import com.subgraph.orchid.data.Timestamp;
import com.subgraph.orchid.directory.parsing.BasicDocumentParsingResult;
import com.subgraph.orchid.directory.parsing.DocumentFieldParser;
import com.subgraph.orchid.directory.parsing.DocumentParser;
import com.subgraph.orchid.directory.parsing.DocumentParsingHandler;
import com.subgraph.orchid.directory.parsing.DocumentParsingResult;
import com.subgraph.orchid.directory.parsing.DocumentParsingResultHandler;

public class RouterDescriptorParser implements DocumentParser<RouterDescriptor> {
	private final DocumentFieldParser fieldParser;
	private final boolean verifySignatures;
	
	private RouterDescriptorImpl currentDescriptor;
	private DocumentParsingResultHandler<RouterDescriptor> resultHandler;
	
	public RouterDescriptorParser(DocumentFieldParser fieldParser, boolean verifySignatures) {
		this.fieldParser = fieldParser;
		this.fieldParser.setHandler(createParsingHandler());
		this.fieldParser.setRecognizeOpt();
		this.verifySignatures = verifySignatures;
	}
	
	private DocumentParsingHandler createParsingHandler() {
		return new DocumentParsingHandler() {
			public void endOfDocument() {
			}
			public void parseKeywordLine() {
				processKeywordLine();				
			}
		};
	}
	
	private void processKeywordLine() {
		final RouterDescriptorKeyword keyword = RouterDescriptorKeyword.findKeyword(fieldParser.getCurrentKeyword());
		/*
		 * dirspec.txt (1.2)
		 * When interpreting a Document, software MUST ignore any KeywordLine that
		 * starts with a keyword it doesn't recognize;
		 */
		if(!keyword.equals(RouterDescriptorKeyword.UNKNOWN_KEYWORD))
			processKeyword(keyword);	
	}
	
	private void startNewDescriptor() {
		fieldParser.resetRawDocument();
		fieldParser.startSignedEntity();
		currentDescriptor = new RouterDescriptorImpl();
	}
	
	public boolean parse(DocumentParsingResultHandler<RouterDescriptor> resultHandler) {
		this.resultHandler = resultHandler;
		startNewDescriptor();
		try {
			fieldParser.processDocument();
			return true;
		} catch(TorParsingException e) {
			resultHandler.parsingError(e.getMessage());
			return false;
		}
	}
	
	public DocumentParsingResult<RouterDescriptor> parse() {
		final BasicDocumentParsingResult<RouterDescriptor> result = new BasicDocumentParsingResult<RouterDescriptor>();
		parse(result);
		return result;
	}

	private void processKeyword(RouterDescriptorKeyword keyword) {
		fieldParser.verifyExpectedArgumentCount(keyword.getKeyword(), keyword.getArgumentCount());

		switch(keyword) {
		case ROUTER:
			processRouter();
			return;
		case BANDWIDTH:
			processBandwidth();
			break;
		case PLATFORM:
			currentDescriptor.setPlatform(fieldParser.parseConcatenatedString());
			break;
		case PUBLISHED:
			currentDescriptor.setPublished(fieldParser.parseTimestamp());
			break;
		case FINGERPRINT:
			currentDescriptor.setFingerprint(fieldParser.parseFingerprint());
			break;
		case HIBERNATING:
			currentDescriptor.setHibernating(fieldParser.parseBoolean());
			break;
		case UPTIME:
			currentDescriptor.setUptime(fieldParser.parseInteger());
			break;
		case ONION_KEY:
			currentDescriptor.setOnionKey(fieldParser.parsePublicKey());
			break;
		case NTOR_ONION_KEY:
			currentDescriptor.setNtorOnionKey(fieldParser.parseNtorPublicKey());
			break;
		case SIGNING_KEY:
			currentDescriptor.setIdentityKey(fieldParser.parsePublicKey());
			break;			
		case ROUTER_SIGNATURE:
			processSignature();
			break;
		case ACCEPT:
			currentDescriptor.addAcceptRule(fieldParser.parseString());
			break;
		case REJECT:
			currentDescriptor.addRejectRule(fieldParser.parseString());
			break;
		case CONTACT:
			currentDescriptor.setContact(fieldParser.parseConcatenatedString());
			break;
		case FAMILY:
			while(fieldParser.argumentsRemaining() > 0) 
				currentDescriptor.addFamilyMember(fieldParser.parseString());
			break;
		case EVENTDNS:
			if(fieldParser.parseBoolean())
				currentDescriptor.setEventDNS();
			break;		
		case PROTOCOLS:
			processProtocols();
			break;			
		case CACHES_EXTRA_INFO:
			currentDescriptor.setCachesExtraInfo();
			break;			
		case HIDDEN_SERVICE_DIR:
			currentDescriptor.setHiddenServiceDir();
			break;			
		case ALLOW_SINGLE_HOP_EXITS:
			currentDescriptor.setAllowSingleHopExits();
			break;
		case EXTRA_INFO_DIGEST:
			currentDescriptor.setExtraInfoDigest(fieldParser.parseHexDigest());
			break;		
		case READ_HISTORY:
			currentDescriptor.setReadHistory(parseHistory());
			break;
		case WRITE_HISTORY:
			currentDescriptor.setWriteHistory(parseHistory());
			break;
		default:
			break;
		}
	}
	
	private BandwidthHistory parseHistory() {
		final Timestamp ts = fieldParser.parseTimestamp();
		final String nsec = fieldParser.parseString();
		fieldParser.parseString();
		final int interval = fieldParser.parseInteger(nsec.substring(1));
		final BandwidthHistory history = new BandwidthHistory(ts, interval);
		if(fieldParser.argumentsRemaining() == 0)
			return history;
		final String[] samples = fieldParser.parseString().split(",");
		for(String s: samples)
			history.addSample(fieldParser.parseInteger(s));
		return history;
	}
	
	private void processRouter() {
		currentDescriptor.setNickname(fieldParser.parseNickname());
		currentDescriptor.setAddress(fieldParser.parseAddress());
		currentDescriptor.setRouterPort(fieldParser.parsePort());
		/* 2.1 SOCKSPort is deprecated and should always be 0 */
		fieldParser.parsePort();
		currentDescriptor.setDirectoryPort(fieldParser.parsePort());
	}
	
	private boolean verifyCurrentDescriptor(TorSignature signature) {
		if(verifySignatures && !fieldParser.verifySignedEntity(currentDescriptor.getIdentityKey(), signature)) {
			resultHandler.documentInvalid(currentDescriptor, "Signature failed.");
			fieldParser.logWarn("Signature failed for router: " + currentDescriptor.getNickname());
			return false;
		}
		currentDescriptor.setValidSignature();
		if(!currentDescriptor.isValidDocument()) {
			resultHandler.documentInvalid(currentDescriptor, "Router data invalid");
			fieldParser.logWarn("Router data invalid for router: " + currentDescriptor.getNickname());
		}
		return currentDescriptor.isValidDocument();
	}
	
	private void processBandwidth() {
		final int average = fieldParser.parseInteger();
		final int burst = fieldParser.parseInteger();
		final int observed = fieldParser.parseInteger();
		currentDescriptor.setBandwidthValues(average, burst, observed);
	}
	
	private void processProtocols() {
		String kw = fieldParser.parseString();
		if(!kw.equals("Link")) 
			throw new TorParsingException("Expected 'Link' token in protocol line got: " + kw);
		while(true) {
			kw = fieldParser.parseString();
			if(kw.equals("Circuit"))
				break;
			currentDescriptor.addLinkProtocolVersion(fieldParser.parseInteger(kw));
		}
		while(fieldParser.argumentsRemaining() > 0)
			currentDescriptor.addCircuitProtocolVersion(fieldParser.parseInteger());
		
	}
	
	private void processSignature() {
		fieldParser.endSignedEntity();
		currentDescriptor.setDescriptorHash(fieldParser.getSignatureMessageDigest().getHexDigest());
		final TorSignature signature = fieldParser.parseSignature();
		currentDescriptor.setRawDocumentData(fieldParser.getRawDocument());
		
		if(verifyCurrentDescriptor(signature))
			resultHandler.documentParsed(currentDescriptor);
		startNewDescriptor();
	}
}
