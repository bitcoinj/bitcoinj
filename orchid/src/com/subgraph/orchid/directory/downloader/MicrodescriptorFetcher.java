package com.subgraph.orchid.directory.downloader;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import com.subgraph.orchid.RouterMicrodescriptor;
import com.subgraph.orchid.data.HexDigest;
import com.subgraph.orchid.directory.parsing.DocumentParser;

public class MicrodescriptorFetcher extends DocumentFetcher<RouterMicrodescriptor>{

	private final List<HexDigest> fingerprints;
	
	public MicrodescriptorFetcher(Collection<HexDigest> fingerprints) {
		this.fingerprints = new ArrayList<HexDigest>(fingerprints);
	}

	@Override
	String getRequestPath() {
		return "/tor/micro/d/"+ fingerprintsToRequestString();
	}
	
	private String fingerprintsToRequestString() {
		final StringBuilder sb = new StringBuilder();
		for(HexDigest fp: fingerprints) {
			appendFingerprint(sb, fp);
		}
		return sb.toString();
	}

	private void appendFingerprint(StringBuilder sb, HexDigest fp) {
		if(sb.length() > 0) {
			sb.append("-");
		}
		sb.append(fp.toBase64(true));
	}

	@Override
	DocumentParser<RouterMicrodescriptor> createParser(ByteBuffer response) {
		return PARSER_FACTORY.createRouterMicrodescriptorParser(response);
	}
}
