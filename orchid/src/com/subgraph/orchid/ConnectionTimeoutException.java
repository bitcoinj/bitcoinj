package com.subgraph.orchid;

public class ConnectionTimeoutException extends ConnectionIOException {

	private static final long serialVersionUID = -6098661610150140151L;

	public ConnectionTimeoutException() {
		super();
	}

	public ConnectionTimeoutException(String message) {
		super(message);
	}
}
