package com.subgraph.orchid.directory.downloader;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.DataFormatException;
import java.util.zip.Inflater;

import com.subgraph.orchid.Router;
import com.subgraph.orchid.Stream;

public class HttpConnection {
	private final static Charset CHARSET = Charset.forName("ISO-8859-1");
	
	private final static String HTTP_RESPONSE_REGEX = "HTTP/1\\.(\\d) (\\d+) (.*)";
	private final static String CONTENT_LENGTH_HEADER = "Content-Length";
	private final static String CONTENT_ENCODING_HEADER = "Content-Encoding";
	private final static String COMPRESSION_SUFFIX = ".z";
	private final String hostname;
	private final Stream stream;
	private final InputStream input;
	private final OutputStream output;
	private final Map<String, String> headers;
	private final boolean useCompression;
	private int responseCode;
	private boolean bodyCompressed;
	private String responseMessage;
	private ByteBuffer messageBody;
	
	public HttpConnection(Stream stream) {
		this(stream, true);
	}

	public HttpConnection(Stream stream, boolean useCompression) {
		this.hostname = getHostnameFromStream(stream);
		this.stream = stream;
		this.headers = new HashMap<String, String>();
		this.input = stream.getInputStream();
		this.output = stream.getOutputStream();
		this.useCompression = useCompression;
	}
	
	private static String getHostnameFromStream(Stream stream) {
		final StringBuilder sb = new StringBuilder();
		final Router r = stream.getCircuit().getFinalCircuitNode().getRouter();
		if(r == null) {
			return null;
		}
		sb.append(r.getAddress().toString());
		if(r.getOnionPort() != 80) {
			sb.append(":");
			sb.append(r.getOnionPort());
		}
		return sb.toString();
	}

	public void sendGetRequest(String request) throws IOException {
		final StringBuilder sb = new StringBuilder();
		sb.append("GET ");
		sb.append(request);
		if(useCompression && !request.endsWith(COMPRESSION_SUFFIX)) {
			sb.append(COMPRESSION_SUFFIX);
		}
		sb.append(" HTTP/1.0\r\n");
		if(hostname != null) {
			sb.append("Host: "+ hostname +"\r\n");
		}
		sb.append("\r\n");
		
		final String requestLine = sb.toString();
		output.write(requestLine.getBytes(CHARSET));
		output.flush();
	}
	
	public String getHost() {
		if(hostname == null) {
			return hostname;
		} else {
			return "(none)";
		}
	}

	public void readResponse() throws IOException, DirectoryRequestFailedException {
		readStatusLine();
		readHeaders();
		readBody();
	}
	
	public int getStatusCode() {
		return responseCode;
	}
	
	public String getStatusMessage() {
		return responseMessage;
	}

	public ByteBuffer getMessageBody() {
		return messageBody;
	}
	
	public void close() {
		if(stream == null) {
			return;
		}
		stream.close();
	}
	
	private void readStatusLine() throws IOException, DirectoryRequestFailedException {
		final String line = nextResponseLine();	
		final Pattern p = Pattern.compile(HTTP_RESPONSE_REGEX);
		final Matcher m = p.matcher(line);
		if(!m.find() || m.groupCount() != 3) 
			throw new DirectoryRequestFailedException("Error parsing HTTP response line: "+ line);
		
		try {
			int n1 = Integer.parseInt(m.group(1));
			int n2 = Integer.parseInt(m.group(2));
			if( (n1 != 0 && n1 != 1) ||
					(n2 < 100 || n2 >= 600))
				throw new DirectoryRequestFailedException("Failed to parse header: "+ line);
			responseCode = n2;
			responseMessage = m.group(3);
		} catch(NumberFormatException e) {
			throw new DirectoryRequestFailedException("Failed to parse header: "+ line);
		}
	}
	
	private void readHeaders() throws IOException, DirectoryRequestFailedException {
		headers.clear();
		while(true) {
			final String line = nextResponseLine();
			if(line.length() == 0)
				return;
			final String[] args = line.split(": ", 2);
			if(args.length != 2)
				throw new DirectoryRequestFailedException("Failed to parse HTTP header: "+ line);
			headers.put(args[0], args[1]);
		}
	}
	
	private String nextResponseLine() throws IOException, DirectoryRequestFailedException {
		final String line = readInputLine();
		if(line == null) {
			throw new DirectoryRequestFailedException("Unexpected EOF reading HTTP response");
		}
		return line;
	}
	
	private void readBody() throws IOException, DirectoryRequestFailedException {
		processContentEncodingHeader();
		
		if(headers.containsKey(CONTENT_LENGTH_HEADER)) { 
			readBodyFromContentLength();
		} else { 
			readBodyUntilEOF();
		}
	}
	
	private void processContentEncodingHeader() throws DirectoryRequestFailedException {
		final String encoding = headers.get(CONTENT_ENCODING_HEADER);
		if(encoding == null || encoding.equals("identity")) 
			bodyCompressed = false;
		else if(encoding.equals("deflate") || encoding.equals("x-deflate"))
			bodyCompressed = true;
		else
			throw new DirectoryRequestFailedException("Unrecognized content encoding: "+ encoding);
	}
	
	private void readBodyFromContentLength() throws IOException {
		int bodyLength = Integer.parseInt(headers.get(CONTENT_LENGTH_HEADER));
		byte[] bodyBuffer = new byte[bodyLength];
		readAll(bodyBuffer);
		messageBody = bytesToBody(bodyBuffer);
	}
	
	private void readBodyUntilEOF() throws IOException {
		final byte[] bodyBuffer = readToEOF();
		messageBody = bytesToBody(bodyBuffer);
	}
	
	private ByteBuffer bytesToBody(byte[] bs) throws IOException {
		if(bodyCompressed) {
			return ByteBuffer.wrap(decompressBuffer(bs));
		} else {
			return ByteBuffer.wrap(bs);
		}
	}
	
	private byte[] decompressBuffer(byte[] buffer) throws IOException {
		final ByteArrayOutputStream output = new ByteArrayOutputStream();
		final Inflater decompressor = new Inflater();
		final byte[] decompressBuffer = new byte[4096];
		decompressor.setInput(buffer);
		int n;
		try {
			while((n = decompressor.inflate(decompressBuffer)) != 0) {
				output.write(decompressBuffer, 0, n);
			}
			return output.toByteArray();
		} catch (DataFormatException e) {
			throw new IOException("Error decompressing http body: "+ e);
		}
	}
	
	private byte[] readToEOF() throws IOException {
		final ByteArrayOutputStream output = new ByteArrayOutputStream();
		final byte[] buffer = new byte[2048];
		int n;
		while( (n = input.read(buffer, 0, buffer.length)) != -1) {
			output.write(buffer, 0, n);
		}
		return output.toByteArray();
	}

	private void readAll(byte[] buffer) throws IOException {
		int offset = 0;
		int remaining = buffer.length;
		while(remaining > 0) {
			int n = input.read(buffer, offset, remaining);
			if(n == -1) {
				throw new IOException("Unexpected early EOF reading HTTP body");
			}
			offset += n;
			remaining -= n;
		}
	}
	
	private String readInputLine() throws IOException {
		final StringBuilder sb = new StringBuilder();
		int c;
		while((c = input.read()) != -1) {
			if(c == '\n') {
				return sb.toString();
			} else if(c != '\r') {
				sb.append((char) c);
			}
		}
		return (sb.length() == 0) ? (null) : (sb.toString());
	}
}
