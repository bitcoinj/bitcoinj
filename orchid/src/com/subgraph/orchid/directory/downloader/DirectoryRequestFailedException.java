package com.subgraph.orchid.directory.downloader;

public class DirectoryRequestFailedException extends Exception {

	private static final long serialVersionUID = 1L;
	
	public DirectoryRequestFailedException(String message) {
		super(message);
	}
	
	public DirectoryRequestFailedException(String message, Throwable cause) {
		super(message, cause);
	}

}
