package com.google.bitcoin.core;

public abstract class Manipulator<M extends Message> {
	
	public abstract void manipulate(BitcoinSerializer bs, M message) throws Exception;
	
	public abstract void manipulate(BitcoinSerializer bs, byte[] bytes) throws Exception;
	
	public abstract String getDescription();
	
	public void beforeTest() {}
	
	public void afterTest() {}
	
	public long timeForR224Test() {return -1l;}
}