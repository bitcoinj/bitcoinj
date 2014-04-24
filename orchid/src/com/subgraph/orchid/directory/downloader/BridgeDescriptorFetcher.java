package com.subgraph.orchid.directory.downloader;

import java.nio.ByteBuffer;

import com.subgraph.orchid.RouterDescriptor;
import com.subgraph.orchid.directory.parsing.DocumentParser;

public class BridgeDescriptorFetcher extends DocumentFetcher<RouterDescriptor>{

	@Override
	String getRequestPath() {
		return "/tor/server/authority";
	}

	@Override
	DocumentParser<RouterDescriptor> createParser(ByteBuffer response) {
		return PARSER_FACTORY.createRouterDescriptorParser(response, true);
	}
}
