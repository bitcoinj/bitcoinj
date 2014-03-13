package com.subgraph.orchid.directory.parsing;

import java.util.ArrayList;
import java.util.List;

public class BasicDocumentParsingResult<T> implements DocumentParsingResultHandler<T>, DocumentParsingResult<T> {

	private final List<T> documents;
	private T invalidDocument;
	private boolean isOkay;
	private boolean isInvalid;
	private boolean isError;
	private String message;

	public BasicDocumentParsingResult() {
		documents = new ArrayList<T>();
		isOkay = true;
		isInvalid = false;
		isError = false;
		message = "";
	}
	
	public T getDocument() {
		if(documents.size() != 1) {
			throw new IllegalStateException();
		}
		return documents.get(0);
	}

	public List<T> getParsedDocuments() {
		return new ArrayList<T>(documents);
	}

	public boolean isOkay() {
		return isOkay;
	}
	
	public boolean isInvalid() {
		return isInvalid;
	}
	
	public T getInvalidDocument() {
		return invalidDocument;
	}

	public boolean isError() {
		return isError;
	}
	
	public String getMessage() {
		return message;
	}
	
	public void documentParsed(T document) {
		documents.add(document);
	}

	public void documentInvalid(T document, String message) {
		isOkay = false;
		isInvalid = true;
		invalidDocument = document;
		this.message = message;
	}

	public void parsingError(String message) {
		isOkay = false;
		isError = true;
		this.message = message;
	}
}
