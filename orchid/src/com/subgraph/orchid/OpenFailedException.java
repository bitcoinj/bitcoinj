package com.subgraph.orchid;

public class OpenFailedException extends Exception {

	private static final long serialVersionUID = 1989001056577214666L;

	public OpenFailedException() {
	}

	public OpenFailedException(String message) {
		super(message);
	}
}
