package com.subgraph.orchid.socks;

import java.net.Socket;

import com.subgraph.orchid.TorConfig;

public class Socks4Request extends SocksRequest {
	final static int SOCKS_COMMAND_CONNECT = 1;
	final static int SOCKS_COMMAND_RESOLV = 0xF0;
	private final static int SOCKS_STATUS_SUCCESS = 0x5a;
	private final static int SOCKS_STATUS_FAILURE = 0x5b;
	private int command;

	Socks4Request(TorConfig config, Socket socket) {
		super(config, socket);
	}

	public boolean isConnectRequest() {
		return command == SOCKS_COMMAND_CONNECT;
	}

	public int getCommandCode() {
		return command;
	}

	public void sendConnectionRefused() throws SocksRequestException {
		sendError(false);
	}

	public void sendError(boolean isUnsupportedCommand) throws SocksRequestException  {
		sendResponse(SOCKS_STATUS_FAILURE);
	}

	public void sendSuccess() throws SocksRequestException {
		sendResponse(SOCKS_STATUS_SUCCESS);
	}

	public void readRequest() throws SocksRequestException {
		command = readByte();
		setPortData(readPortData());
		byte[] ipv4Data = readIPv4AddressData();
		readNullTerminatedString(); // Username
		if(isVersion4aHostname(ipv4Data))
			setHostname(readNullTerminatedString());
		else
			setIPv4AddressData(ipv4Data);
	}

	private boolean isVersion4aHostname(byte[] data) {
		/*
		 * For version 4A, if the client cannot resolve the destination host's
		 * domain name to find its IP address, it should set the first three bytes
         * of DSTIP to NULL and the last byte to a non-zero value. (This corresponds
         * to IP address 0.0.0.x, with x nonzero.
		 */
		if(data.length != 4)
			return false;
		for(int i = 0; i < 3; i++)
			if(data[i] != 0)
				return false;
		return data[3] != 0;
	}

	private void sendResponse(int code) throws SocksRequestException {
		final byte[] responseBuffer = new byte[8];
		responseBuffer[0] = 0;
		responseBuffer[1] = (byte) code;
		socketWrite(responseBuffer);
	}
}
