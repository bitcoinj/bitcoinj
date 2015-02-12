package com.subgraph.orchid.directory.parsing;

public class DocumentObject {
	
	final private String keyword;
	final private String headerLine;
	private String footerLine;
	private String bodyContent;
	final private StringBuilder stringContent;
	
	public DocumentObject(String keyword, String headerLine) {
		this.keyword = keyword;
		this.headerLine = headerLine;
		this.stringContent = new StringBuilder();
	}

	public String getKeyword() {
		return keyword;
	}
	
	public void addContent(String content) {
		stringContent.append(content);
		stringContent.append("\n");
	}
	
	public void addFooterLine(String footer) {
		footerLine = footer;
		bodyContent = stringContent.toString();
	}
	
	public String getContent() {
		return getContent(true);
	}
	
	public String getContent(boolean includeHeaders) {
		if(includeHeaders) {
			return headerLine + "\n" + bodyContent + footerLine + "\n";
		} else {
			return bodyContent;
		}
	}

}
