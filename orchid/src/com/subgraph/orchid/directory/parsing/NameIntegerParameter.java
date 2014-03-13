package com.subgraph.orchid.directory.parsing;

public class NameIntegerParameter {
	
	private final String name;
	private final int value;
	
	public NameIntegerParameter(String name, int value) {
		this.name = name;
		this.value = value;
	}
	
	public String getName() {
		return name;
	}
	
	public int getValue() {
		return value;
	}
	
	public String toString() {
		return name +"="+ value;
	}
}
