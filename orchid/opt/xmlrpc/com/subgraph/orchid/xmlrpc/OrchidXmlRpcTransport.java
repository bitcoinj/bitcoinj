package com.subgraph.orchid.xmlrpc;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.net.ConnectException;
import java.net.Socket;
import java.net.URL;
import java.net.UnknownHostException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.StringTokenizer;
import java.util.logging.Logger;

import javax.net.SocketFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

import org.apache.xmlrpc.XmlRpcException;
import org.apache.xmlrpc.XmlRpcRequest;
import org.apache.xmlrpc.client.XmlRpcClient;
import org.apache.xmlrpc.client.XmlRpcClientException;
import org.apache.xmlrpc.client.XmlRpcHttpClientConfig;
import org.apache.xmlrpc.client.XmlRpcHttpTransport;
import org.apache.xmlrpc.client.XmlRpcHttpTransportException;
import org.apache.xmlrpc.client.XmlRpcLiteHttpTransport;
import org.apache.xmlrpc.common.XmlRpcStreamRequestConfig;
import org.apache.xmlrpc.util.HttpUtil;
import org.apache.xmlrpc.util.LimitedInputStream;
import org.xml.sax.SAXException;

import com.subgraph.orchid.Tor;
import com.subgraph.orchid.sockets.AndroidSSLSocketFactory;

public class OrchidXmlRpcTransport extends XmlRpcHttpTransport {
	
	private final static Logger logger = Logger.getLogger(OrchidXmlRpcTransport.class.getName());
	
	private final SocketFactory socketFactory;
	private final SSLContext sslContext;

	private SSLSocketFactory sslSocketFactory;

	public OrchidXmlRpcTransport(XmlRpcClient pClient, SocketFactory socketFactory, SSLContext sslContext) {
		super(pClient, userAgent);
		this.socketFactory = socketFactory;
		this.sslContext = sslContext;
	}
	
	public synchronized SSLSocketFactory getSSLSocketFactory() {
		if(sslSocketFactory == null) {
			sslSocketFactory = createSSLSocketFactory();
		}
		return sslSocketFactory;
	}

	private SSLSocketFactory createSSLSocketFactory() {
		if(Tor.isAndroidRuntime()) {
			return createAndroidSSLSocketFactory();
		}
		if(sslContext == null) {
			return (SSLSocketFactory) SSLSocketFactory.getDefault();
		} else {
			return sslContext.getSocketFactory();
		}
	}

	private SSLSocketFactory createAndroidSSLSocketFactory() {
		if(sslContext == null) {
			try {
				return new AndroidSSLSocketFactory();
			} catch (NoSuchAlgorithmException e) {
				logger.severe("Failed to create default ssl context");
				System.exit(1);
				return null;
			}
		} else {
			return new AndroidSSLSocketFactory(sslContext);
		}
	}

	protected Socket newSocket(boolean pSSL, String pHostName, int pPort) throws UnknownHostException, IOException {
		final Socket s = socketFactory.createSocket(pHostName, pPort);
		if(pSSL) {
			return getSSLSocketFactory().createSocket(s, pHostName, pPort, true);
		} else {
			return s;
		}
	}
	
	private static final String userAgent = USER_AGENT + " (Lite HTTP Transport)";
	private boolean ssl;
	private String hostname;
	private String host;
	private int port;
	private String uri;
	private Socket socket;
	private OutputStream output;
	private InputStream input;
	private final Map<String, Object> headers = new HashMap<String, Object>();
	private boolean responseGzipCompressed = false;
	private XmlRpcHttpClientConfig config;


	public Object sendRequest(XmlRpcRequest pRequest) throws XmlRpcException {
		config = (XmlRpcHttpClientConfig) pRequest.getConfig();
		URL url = config.getServerURL();
		ssl = "https".equals(url.getProtocol());
		hostname = url.getHost();
        int p = url.getPort();
		port = p < 1 ? 80 : p;
		String u = url.getFile();
		uri = (u == null  ||  "".equals(u)) ? "/" : u;
		host = port == 80 ? hostname : hostname + ":" + port;
		headers.put("Host", host);
		return super.sendRequest(pRequest);
	}

	protected void setRequestHeader(String pHeader, String pValue) {
		Object value = headers.get(pHeader);
		if (value == null) {
			headers.put(pHeader, pValue);
		} else {
			List<Object> list;
			if (value instanceof String) {
				list = new ArrayList<Object>();
				list.add((String)value);
				headers.put(pHeader, list);
			} else {
				list = (List<Object>) value;
			}
			list.add(pValue);
		}
	}

	protected void close() throws XmlRpcClientException {
		IOException e = null;
		if (input != null) {
			try {
				input.close();
			} catch (IOException ex) {
				e = ex;
			}
		}
		if (output != null) {
			try {
				output.close();
			} catch (IOException ex) {
				if (e != null) {
					e = ex;
				}
			}
		}
		if (socket != null) {
			try {
				socket.close();
			} catch (IOException ex) {
				if (e != null) {
					e = ex;
				}
			}
		}
		if (e != null) {
			throw new XmlRpcClientException("Failed to close connection: " + e.getMessage(), e);
		}
	}

	private OutputStream getOutputStream() throws XmlRpcException {
		try {
			final int retries = 3;
	        final int delayMillis = 100;
	
			for (int tries = 0;  ;  tries++) {
				try {
					socket = newSocket(ssl, hostname, port);
					output = new BufferedOutputStream(socket.getOutputStream()){
						/** Closing the output stream would close the whole socket, which we don't want,
						 * because the don't want until the request is processed completely.
						 * A close will later occur within
						 * {@link XmlRpcLiteHttpTransport#close()}.
						 */
						public void close() throws IOException {
							flush();
							if(!(socket instanceof SSLSocket)) {
								socket.shutdownOutput();
							}
						}
					};
					break;
				} catch (ConnectException e) {
					if (tries >= retries) {
						throw new XmlRpcException("Failed to connect to "
								+ hostname + ":" + port + ": " + e.getMessage(), e);
					} else {
	                    try {
	                        Thread.sleep(delayMillis);
	                    } catch (InterruptedException ignore) {
	                    }
					}
				}
			}
			sendRequestHeaders(output);
			return output;
		} catch (IOException e) {
			throw new XmlRpcException("Failed to open connection to "
					+ hostname + ":" + port + ": " + e.getMessage(), e);
		}
	}

   

	private byte[] toHTTPBytes(String pValue) throws UnsupportedEncodingException {
		return pValue.getBytes("US-ASCII");
	}

	private void sendHeader(OutputStream pOut, String pKey, String pValue) throws IOException {
		pOut.write(toHTTPBytes(pKey + ": " + pValue + "\r\n"));
	}

	private void sendRequestHeaders(OutputStream pOut) throws IOException {
		pOut.write(("POST " + uri + " HTTP/1.0\r\n").getBytes("US-ASCII"));
		for (Iterator iter = headers.entrySet().iterator();  iter.hasNext();  ) {
			Map.Entry entry = (Map.Entry) iter.next();
			String key = (String) entry.getKey();
			Object value = entry.getValue();
			if (value instanceof String) {
				sendHeader(pOut, key, (String) value);
			} else {
				List list = (List) value;
				for (int i = 0;  i < list.size();  i++) {
					sendHeader(pOut, key, (String) list.get(i));
				}
			}
		}
		pOut.write(toHTTPBytes("\r\n"));
	}

	protected boolean isResponseGzipCompressed(XmlRpcStreamRequestConfig pConfig) {
		return responseGzipCompressed;
	}

	protected InputStream getInputStream() throws XmlRpcException {
		final byte[] buffer = new byte[2048];
		try {
            // If reply timeout specified, set the socket timeout accordingly
            if (config.getReplyTimeout() != 0)
                socket.setSoTimeout(config.getReplyTimeout());
            input = new BufferedInputStream(socket.getInputStream());
			// start reading  server response headers
			String line = HttpUtil.readLine(input, buffer);
			StringTokenizer tokens = new StringTokenizer(line);
			tokens.nextToken(); // Skip HTTP version
			String statusCode = tokens.nextToken();
			String statusMsg = tokens.nextToken("\n\r");
			final int code;
			try {
			    code = Integer.parseInt(statusCode);
			} catch (NumberFormatException e) {
                throw new XmlRpcClientException("Server returned invalid status code: "
                        + statusCode + " " + statusMsg, null);
			}
			if (code < 200  ||  code > 299) {
		        throw new XmlRpcHttpTransportException(code, statusMsg);
		    }
			int contentLength = -1;
			for (;;) {
				line = HttpUtil.readLine(input, buffer);
				if (line == null  ||  "".equals(line)) {
					break;
				}
				line = line.toLowerCase();
				if (line.startsWith("content-length:")) {
					contentLength = Integer.parseInt(line.substring("content-length:".length()).trim());
				} else if (line.startsWith("content-encoding:")) {
					responseGzipCompressed = HttpUtil.isUsingGzipEncoding(line.substring("content-encoding:".length()));
				}
			}
			InputStream result;
			if (contentLength == -1) {
				result = input;
			} else {
				result = new LimitedInputStream(input, contentLength);
			}
			return result;
		} catch (IOException e) {
			throw new XmlRpcClientException("Failed to read server response: " + e.getMessage(), e);
		}
	}

	protected boolean isUsingByteArrayOutput(XmlRpcHttpClientConfig pConfig) {
	    boolean result = super.isUsingByteArrayOutput(pConfig);
        if (!result) {
            throw new IllegalStateException("The Content-Length header is required with HTTP/1.0, and HTTP/1.1 is unsupported by the Lite HTTP Transport.");
        }
        return result;
    }

    protected void writeRequest(ReqWriter pWriter) throws XmlRpcException, IOException, SAXException {
        pWriter.write(getOutputStream());
	}
}
