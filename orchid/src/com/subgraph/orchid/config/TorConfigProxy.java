package com.subgraph.orchid.config;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import com.subgraph.orchid.TorConfig;
import com.subgraph.orchid.TorConfig.ConfigVar;
import com.subgraph.orchid.TorConfig.ConfigVarType;
import com.subgraph.orchid.data.HexDigest;
import com.subgraph.orchid.data.IPv4Address;

public class TorConfigProxy implements InvocationHandler {
	
	private final Map<String, Object> configValues;
	private final List<TorConfigBridgeLine> bridges;
	private final TorConfigParser parser;
	
	public TorConfigProxy() {
		this.configValues = new HashMap<String, Object>();
		this.bridges = new ArrayList<TorConfigBridgeLine>();
		this.configValues.put("Bridges", bridges);
		this.parser = new TorConfigParser();
	}
	
	public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
		if(method.getName().startsWith("set")) {
			invokeSetMethod(method, args);
			return null;
		} else if(method.getName().startsWith("get")) {
			if(args == null) {
				return invokeGetMethod(method);
			} else {
				return invokeGetMethodWithArgs(method, args);
			}
		} else if(method.getName().startsWith("add")) { 
			invokeAddMethod(method, args);
			return null;
		} else {
			throw new IllegalArgumentException();
		}
	}
	
	void invokeSetMethod(Method method, Object[] args) {
		final String name = getVariableNameForMethod(method);
		final ConfigVar annotation = getAnnotationForVariable(name);
		if(annotation != null && annotation.type() == ConfigVarType.INTERVAL) {
			setIntervalValue(name, args);
		} else {
			configValues.put(name, args[0]);
		}
	}
	
	private void setIntervalValue(String varName, Object[] args) {
		if(!(args[0] instanceof Long && args[1] instanceof TimeUnit)) {
			throw new IllegalArgumentException();
		}
		final long time = (Long) args[0];
		final TimeUnit unit = (TimeUnit) args[1];
		final TorConfigInterval interval = new TorConfigInterval(time, unit);
		configValues.put(varName, interval);
	}

	
	private Object invokeGetMethodWithArgs(Method method, Object[] args) {
		final String varName = getVariableNameForMethod(method);
		if(getVariableType(varName) == ConfigVarType.HS_AUTH) {
			return invokeHSAuthGet(varName, args);
		} else {
			throw new IllegalArgumentException();
		}
	}
	
	private Object invokeGetMethod(Method method) {
		final String varName = getVariableNameForMethod(method);
		final Object value = getVariableValue(varName);
		
		if(value instanceof TorConfigInterval) {
			final TorConfigInterval interval = (TorConfigInterval) value;
			return interval.getMilliseconds();
		} else {
			return value;
		}
	}
	
	private Object invokeHSAuthGet(String varName, Object[] args) {
		if(!(args[0] instanceof String)) {
			throw new IllegalArgumentException();
		}
		final TorConfigHSAuth hsAuth = getHSAuth(varName);		
		return hsAuth.get((String) args[0]);
	}

	private void invokeAddMethod(Method method, Object[] args) {
		final String name = getVariableNameForMethod(method);
		final ConfigVarType type = getVariableType(name);
		switch(type) {
		case HS_AUTH:
			invokeHSAuthAdd(name, args);
			break;
			
		case BRIDGE_LINE:
			invokeBridgeAdd(args);
			break;
			
		default:
			throw new UnsupportedOperationException("addX configuration methods only supported for HS_AUTH or BRIDGE_LINE type");
		}
	}
	
	private void invokeBridgeAdd(Object[] args) {
		if(args.length >= 2 && (args[0] instanceof IPv4Address) && (args[1] instanceof Integer)) {
			if(args.length == 2) {
				bridges.add(new TorConfigBridgeLine((IPv4Address)args[0], (Integer)args[1], null));
				return;
			} else if(args.length == 3 && (args[2] instanceof HexDigest)) {
				bridges.add(new TorConfigBridgeLine((IPv4Address) args[0], (Integer) args[1], (HexDigest) args[2]));
				return;
			}
		}
		throw new IllegalArgumentException();
	}
	
	private void invokeHSAuthAdd(String name, Object[] args) {
		if(!(args.length == 2 && (args[0] instanceof String) && (args[1] instanceof String))) {
			throw new IllegalArgumentException();
		}
		final TorConfigHSAuth hsAuth = getHSAuth(name);
		hsAuth.add((String)args[0], (String)args[1]);
	}
	
	private TorConfigHSAuth getHSAuth(String keyName) {
		if(!configValues.containsKey(keyName)) {
			configValues.put(keyName, new TorConfigHSAuth());
		}
		return (TorConfigHSAuth) configValues.get(keyName);
	}

	private Object getVariableValue(String varName) {
		if(configValues.containsKey(varName)) {
			return configValues.get(varName);
		} else {
			return getDefaultVariableValue(varName);
		}
	}

	private Object getDefaultVariableValue(String varName) {
		final String defaultValue = getDefaultValueString(varName);
		final ConfigVarType type = getVariableType(varName);
		if(defaultValue == null || type == null) {
			return null;
		}
		return parser.parseValue(defaultValue, type);
	}
	
	private String getDefaultValueString(String varName) {
		final ConfigVar var = getAnnotationForVariable(varName);
		if(var == null) {
			return null;
		} else {
			return var.defaultValue();
		}
	}

	private ConfigVarType getVariableType(String varName) {
		if("Bridge".equals(varName)) {
			return ConfigVarType.BRIDGE_LINE;
		}
		
		final ConfigVar var = getAnnotationForVariable(varName);
		if(var == null) {
			return null;
		} else {
			return var.type();
		}
	}
	
	private String getVariableNameForMethod(Method method) {
		final String methodName = method.getName();
		if(methodName.startsWith("get") || methodName.startsWith("set") || methodName.startsWith("add")) {
			return methodName.substring(3);
		}
		throw new IllegalArgumentException();
	}
	
	private ConfigVar getAnnotationForVariable(String varName) {
		final String getName = "get"+ varName;
		for(Method m: TorConfig.class.getDeclaredMethods()) {
			if(getName.equals(m.getName())) {
				return m.getAnnotation(TorConfig.ConfigVar.class);
			}
		}
		return null;
	}
}
