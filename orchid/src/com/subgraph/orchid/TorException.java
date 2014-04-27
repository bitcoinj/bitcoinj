package com.subgraph.orchid;

public class TorException extends RuntimeException {

	private static final long serialVersionUID = 2462760291055303580L;

	public TorException() {
		super();
	}
	
	public TorException(String message) {
		super(message);
	}
	
	public TorException(String message, Throwable ex) {
		super(message, ex);
	}
	
	public TorException(Throwable ex) {
		super(ex);
	}
}
