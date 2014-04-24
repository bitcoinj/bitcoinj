package com.subgraph.orchid.data;

import java.net.InetAddress;
import java.net.UnknownHostException;

import com.subgraph.orchid.TorException;
import com.subgraph.orchid.TorParsingException;

public class IPv4Address {
	
	public static IPv4Address createFromString(String addressString) {
		return new IPv4Address(parseStringToAddressData(addressString));		
	}
	
	private static int parseStringToAddressData(String ipString) {
		final String[] octets = ipString.split("\\.");
		final int[] shifts = {24, 16, 8, 0};
		int addressData = 0;
		int i = 0;
		for(String o: octets)
			addressData |= (octetStringToInt(o) << shifts[i++]);
		
		return addressData;
	}
	
	private static int octetStringToInt(String octet) {
		try {
			int result = Integer.parseInt(octet);
			if(result < 0 || result > 255)
				throw new TorParsingException("Octet out of range: " + octet);
			return result;
		} catch(NumberFormatException e) {
			throw new TorParsingException("Failed to parse octet: " + octet);
		}	
	}
	
	public static boolean isValidIPv4AddressString(String addressString) {
		try {
			createFromString(addressString);
			return true;
		} catch (Exception e) {
			return false;
		}
	}

	private final int addressData;
	
	public IPv4Address(int addressData) {
		this.addressData = addressData;
	
	}
	public int getAddressData() {
		return addressData;
	}
	
	public byte[] getAddressDataBytes() {
		final byte[] result = new byte[4];
		result[0] = (byte)((addressData >> 24) & 0xFF);
		result[1] = (byte)((addressData >> 16) & 0xFF);
		result[2] = (byte)((addressData >> 8) & 0xFF);
		result[3] = (byte)(addressData & 0xFF);
		return result;
	}
	
	public InetAddress toInetAddress() {
		try {
			return InetAddress.getByAddress(getAddressDataBytes());
		} catch (UnknownHostException e) {
			throw new TorException(e);
		}
	}
	
	public static String stringFormat(int addressData) {
		return ((addressData >> 24) & 0xFF) +"."+
			((addressData >> 16) & 0xFF) +"."+
			((addressData >> 8) & 0xFF) +"."+
			(addressData & 0xFF);
	}
	
	public String toString() {
		return stringFormat(addressData);
	}
	
	public boolean equals(Object ob) {
		if(this == ob)
			return true;
		if(!(ob instanceof IPv4Address))
			return false;
		IPv4Address other = (IPv4Address)ob;
		return (other.addressData == addressData);
	}
	
	public int hashCode() {
		int n = 0;
		for(int i = 0; i < 4; i++) {
			n <<= 4;
			n ^= ((addressData >> (i * 8)) & 0xFF);
		}
		return n;
	}

}
