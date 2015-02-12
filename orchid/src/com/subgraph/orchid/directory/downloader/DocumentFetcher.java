package com.subgraph.orchid.directory.downloader;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Collections;
import java.util.List;

import com.subgraph.orchid.directory.DocumentParserFactoryImpl;
import com.subgraph.orchid.directory.parsing.BasicDocumentParsingResult;
import com.subgraph.orchid.directory.parsing.DocumentParser;
import com.subgraph.orchid.directory.parsing.DocumentParserFactory;

public abstract class DocumentFetcher<T> {
	protected final static DocumentParserFactory PARSER_FACTORY = new DocumentParserFactoryImpl();

	
	abstract String getRequestPath();
	abstract DocumentParser<T> createParser(ByteBuffer response);

	public List<T> requestDocuments(HttpConnection httpConnection) throws IOException, DirectoryRequestFailedException {
		final ByteBuffer body = makeRequest(httpConnection);
		if(body.hasRemaining()) {
			return processResponse(body);
		}else {
			return Collections.emptyList();
		}
	}

	private ByteBuffer makeRequest(HttpConnection httpConnection) throws IOException, DirectoryRequestFailedException {
		
		httpConnection.sendGetRequest(getRequestPath());
		httpConnection.readResponse();
		if(httpConnection.getStatusCode() == 200) {
			return httpConnection.getMessageBody();
		}
		
		throw new DirectoryRequestFailedException("Request "+ getRequestPath() +" to directory "+
                httpConnection.getHost() +" returned error code: "+
                httpConnection.getStatusCode() + " "+ httpConnection.getStatusMessage());

	}

	private List<T> processResponse(ByteBuffer response) throws DirectoryRequestFailedException {
		final DocumentParser<T> parser = createParser(response);
		final BasicDocumentParsingResult<T> result = new BasicDocumentParsingResult<T>();
		final boolean success = parser.parse(result);
		if(success) {
			return result.getParsedDocuments();
		}
		throw new DirectoryRequestFailedException("Failed to parse response from directory: "+ result.getMessage());
	}
}
