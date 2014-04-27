package com.subgraph.orchid.xmlrpc;

import javax.net.SocketFactory;
import javax.net.ssl.SSLContext;

import org.apache.xmlrpc.client.XmlRpcClient;
import org.apache.xmlrpc.client.XmlRpcTransport;
import org.apache.xmlrpc.client.XmlRpcTransportFactory;
import com.subgraph.orchid.TorClient;
import com.subgraph.orchid.sockets.OrchidSocketFactory;

public class OrchidXmlRpcTransportFactory implements XmlRpcTransportFactory {
	private final XmlRpcClient client;
	private final SSLContext sslContext;
	private final SocketFactory socketFactory;
		
	public OrchidXmlRpcTransportFactory(XmlRpcClient client, TorClient torClient) {
		this(client, torClient, null);
	}

	public OrchidXmlRpcTransportFactory(XmlRpcClient client, TorClient torClient, SSLContext sslContext) {
		this.client = client;
		this.socketFactory = new OrchidSocketFactory(torClient);
		this.sslContext = sslContext;
	}

	public XmlRpcTransport getTransport() {
		return new OrchidXmlRpcTransport(client, socketFactory, sslContext);
	}
}
