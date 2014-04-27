package com.subgraph.orchid.directory.consensus;

import java.util.Arrays;
import java.util.List;

import com.subgraph.orchid.ConsensusDocument.ConsensusFlavor;
import com.subgraph.orchid.TorParsingException;
import com.subgraph.orchid.directory.consensus.ConsensusDocumentParser.DocumentSection;
import com.subgraph.orchid.directory.parsing.DocumentFieldParser;
import com.subgraph.orchid.directory.parsing.NameIntegerParameter;

public class PreambleSectionParser extends ConsensusDocumentSectionParser {
	private final static int CURRENT_DOCUMENT_VERSION = 3;
	private boolean isFirstLine = true;
	
	PreambleSectionParser(DocumentFieldParser parser, ConsensusDocumentImpl document) {
		super(parser, document);
	}
	
	String getNextStateKeyword() {
		return "dir-source";
	}
	
	DocumentSection getSection() {
		return DocumentSection.PREAMBLE;
	}
	
	DocumentSection nextSection() {
		return DocumentSection.AUTHORITY;
	}
	
	@Override
	void parseLine(DocumentKeyword keyword) {
		if(isFirstLine) {
			parseFirstLine(keyword);
		} else {
			processKeyword(keyword);
		}
	}
	
	private void processKeyword(DocumentKeyword keyword) {
		switch(keyword) {
		case NETWORK_STATUS_VERSION:
			throw new TorParsingException("Network status version may only appear on the first line of status document");
		case VOTE_STATUS:
			final String voteStatus = fieldParser.parseString();
			if(!voteStatus.equals("consensus"))
				throw new TorParsingException("Unexpected vote-status type: "+ voteStatus);
			break;
		case CONSENSUS_METHOD:
			document.setConsensusMethod(fieldParser.parseInteger());
			break;
			
		case VALID_AFTER:
			document.setValidAfter(fieldParser.parseTimestamp());
			break;
			
		case FRESH_UNTIL:
			document.setFreshUntil(fieldParser.parseTimestamp());
			break;
			
		case VALID_UNTIL:
			document.setValidUntil(fieldParser.parseTimestamp());
			break;
			
		case VOTING_DELAY:
			document.setVoteDelaySeconds(fieldParser.parseInteger());
			document.setDistDelaySeconds(fieldParser.parseInteger());
			break;
			
		case CLIENT_VERSIONS:
			for(String version: parseVersions(fieldParser.parseString())) 
				document.addClientVersion(version);
			break;
		case SERVER_VERSIONS:
			for(String version: parseVersions(fieldParser.parseString()))
				document.addServerVersion(version);
			break;
		case KNOWN_FLAGS:
			while(fieldParser.argumentsRemaining() > 0) 
				document.addKnownFlag(fieldParser.parseString());
			break;
			
		case PARAMS:
			parseParams();
			break;
			
		default:
			break;
		}
		
	}
	
	private void parseFirstLine(DocumentKeyword keyword) {
		if(keyword != DocumentKeyword.NETWORK_STATUS_VERSION) 		
			throw new TorParsingException("network-status-version not found at beginning of consensus document as expected.");
			
		final int documentVersion = fieldParser.parseInteger();
		
		if(documentVersion != CURRENT_DOCUMENT_VERSION)
			throw new TorParsingException("Unexpected consensus document version number: " + documentVersion);
		
		if(fieldParser.argumentsRemaining() > 0) {
			parseConsensusFlavor();
		}
		isFirstLine = false;
	}
	
	private void parseConsensusFlavor() {
		final String flavor = fieldParser.parseString();
		if("ns".equals(flavor)) {
			document.setConsensusFlavor(ConsensusFlavor.NS);
		} else if("microdesc".equals(flavor)) {
			document.setConsensusFlavor(ConsensusFlavor.MICRODESC);
		} else {
			fieldParser.logWarn("Unknown consensus flavor: "+ flavor);
		}
	}

	private List<String> parseVersions(String versions) {		
		return Arrays.asList(versions.split(","));
	}
	
	private void parseParams() {
		final int remaining = fieldParser.argumentsRemaining();
		for(int i = 0; i < remaining; i++) {
			NameIntegerParameter p = fieldParser.parseParameter();
			document.addParameter(p.getName(), p.getValue());
		}
	}
}
