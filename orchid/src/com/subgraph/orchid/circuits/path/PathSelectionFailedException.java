package com.subgraph.orchid.circuits.path;

public class PathSelectionFailedException extends Exception {
	private static final long serialVersionUID = -8855252756021674268L;

	public PathSelectionFailedException() {}
	
	public PathSelectionFailedException(String message) {
		super(message);
	}
}
