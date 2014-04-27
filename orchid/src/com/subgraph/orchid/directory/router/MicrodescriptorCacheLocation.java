package com.subgraph.orchid.directory.router;

public class MicrodescriptorCacheLocation {
	
	private final int offset;
	private final int length;
	
	public MicrodescriptorCacheLocation(int offset, int length) {
		this.offset = offset;
		this.length = length;
	}
	
	public int getOffset() {
		return offset;
	}
	
	public int getLength() {
		return length;
	}
	
	public String toString() {
		return "MD Cache offset: "+ offset + " length: "+ length;
	}

}
