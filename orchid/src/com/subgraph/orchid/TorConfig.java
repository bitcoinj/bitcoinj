package com.subgraph.orchid;

import java.io.File;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.util.List;
import java.util.concurrent.TimeUnit;

import com.subgraph.orchid.circuits.hs.HSDescriptorCookie;
import com.subgraph.orchid.config.TorConfigBridgeLine;
import com.subgraph.orchid.data.HexDigest;
import com.subgraph.orchid.data.IPv4Address;


public interface TorConfig {
	
	@ConfigVar(type=ConfigVarType.PATH, defaultValue="~/.orchid")
	File getDataDirectory();
	void setDataDirectory(File directory);
	
	@ConfigVar(type=ConfigVarType.INTERVAL, defaultValue="60 seconds")
	long getCircuitBuildTimeout();
	void setCircuitBuildTimeout(long time, TimeUnit unit);
	
	@ConfigVar(type=ConfigVarType.INTERVAL, defaultValue="0")
	long getCircuitStreamTimeout();
	void setCircuitStreamTimeout(long time, TimeUnit unit);
	
	@ConfigVar(type=ConfigVarType.INTERVAL, defaultValue="1 hour")
	long getCircuitIdleTimeout();
	void setCircuitIdleTimeout(long time, TimeUnit unit);
	
	@ConfigVar(type=ConfigVarType.INTERVAL, defaultValue="30 seconds")
	long getNewCircuitPeriod();
	void setNewCircuitPeriod(long time, TimeUnit unit);
	
	@ConfigVar(type=ConfigVarType.INTERVAL, defaultValue="10 minutes")
	long getMaxCircuitDirtiness();
	void setMaxCircuitDirtiness(long time, TimeUnit unit);
	
	
	@ConfigVar(type=ConfigVarType.INTEGER, defaultValue="32")
	int getMaxClientCircuitsPending();
	void setMaxClientCircuitsPending(int value);
	
	@ConfigVar(type=ConfigVarType.BOOLEAN, defaultValue="true")
	boolean getEnforceDistinctSubnets();
	void setEnforceDistinctSubnets(boolean value);
	
	@ConfigVar(type=ConfigVarType.INTERVAL, defaultValue="2 minutes")
	long getSocksTimeout();
	void setSocksTimeout(long value);
	
	@ConfigVar(type=ConfigVarType.INTEGER, defaultValue="3")
	int getNumEntryGuards();
	void setNumEntryGuards(int value);
	
	@ConfigVar(type=ConfigVarType.BOOLEAN, defaultValue="true")
	boolean getUseEntryGuards();
	void setUseEntryGuards(boolean value);
	
	@ConfigVar(type=ConfigVarType.PORTLIST, defaultValue="21,22,706,1863,5050,5190,5222,5223,6523,6667,6697,8300")
	List<Integer> getLongLivedPorts();
	void setLongLivedPorts(List<Integer> ports);

	@ConfigVar(type=ConfigVarType.STRINGLIST)
	List<String> getExcludeNodes();
	void setExcludeNodes(List<String> nodes);
	
	@ConfigVar(type=ConfigVarType.STRINGLIST)
	List<String> getExcludeExitNodes();
	
	void setExcludeExitNodes(List<String> nodes);
	
	@ConfigVar(type=ConfigVarType.STRINGLIST)
	List<String> getExitNodes();
	void setExitNodes(List<String> nodes);
	
	@ConfigVar(type=ConfigVarType.STRINGLIST)
	List<String> getEntryNodes();
	void setEntryNodes(List<String> nodes);
	
	@ConfigVar(type=ConfigVarType.BOOLEAN, defaultValue="false")
	boolean getStrictNodes();
	void setStrictNodes(boolean value);
	
	@ConfigVar(type=ConfigVarType.BOOLEAN, defaultValue="false")
	boolean getFascistFirewall();
	void setFascistFirewall(boolean value);
	
	@ConfigVar(type=ConfigVarType.PORTLIST, defaultValue="80,443")
	List<Integer> getFirewallPorts();
	void setFirewallPorts(List<Integer> ports);
	
	@ConfigVar(type=ConfigVarType.BOOLEAN, defaultValue="false")
	boolean getSafeSocks();
	void setSafeSocks(boolean value);
	
	@ConfigVar(type=ConfigVarType.BOOLEAN, defaultValue="true")
	boolean getSafeLogging();
	void setSafeLogging(boolean value);

	@ConfigVar(type=ConfigVarType.BOOLEAN, defaultValue="true")
	boolean getWarnUnsafeSocks();
	void setWarnUnsafeSocks(boolean value);

	@ConfigVar(type=ConfigVarType.BOOLEAN, defaultValue="true")
	boolean getClientRejectInternalAddress();
	void setClientRejectInternalAddress(boolean value);
	
	@ConfigVar(type=ConfigVarType.BOOLEAN, defaultValue="true")
	boolean getHandshakeV3Enabled();
	void setHandshakeV3Enabled(boolean value);
	
	@ConfigVar(type=ConfigVarType.BOOLEAN, defaultValue="true")
	boolean getHandshakeV2Enabled();
	void setHandshakeV2Enabled(boolean value);
	
	@ConfigVar(type=ConfigVarType.HS_AUTH)
	HSDescriptorCookie getHidServAuth(String key);
	void addHidServAuth(String key, String value);
	
	@ConfigVar(type=ConfigVarType.AUTOBOOL, defaultValue="auto")
	AutoBoolValue getUseNTorHandshake();
	void setUseNTorHandshake(AutoBoolValue value);
	
	@ConfigVar(type=ConfigVarType.AUTOBOOL, defaultValue="auto")
	AutoBoolValue getUseMicrodescriptors();
	void setUseMicrodescriptors(AutoBoolValue value);

	@ConfigVar(type=ConfigVarType.BOOLEAN, defaultValue="false")
	boolean getUseBridges();
	void setUseBridges(boolean value);
	
	@ConfigVar(type=ConfigVarType.BRIDGE_LINE)
	List<TorConfigBridgeLine> getBridges();
	void addBridge(IPv4Address address, int port);
	void addBridge(IPv4Address address, int port, HexDigest fingerprint);
	
	enum ConfigVarType { INTEGER, STRING, HS_AUTH, BOOLEAN, INTERVAL, PORTLIST, STRINGLIST, PATH, AUTOBOOL, BRIDGE_LINE };
	enum AutoBoolValue { TRUE, FALSE, AUTO }
	
	@Retention(RetentionPolicy.RUNTIME)
	@Target(ElementType.METHOD)
	@interface ConfigVar {
		ConfigVarType type();
		String defaultValue() default "";
	}
}