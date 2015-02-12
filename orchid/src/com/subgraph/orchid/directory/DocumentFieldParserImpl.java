package com.subgraph.orchid.directory;

import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.List;
import java.util.TimeZone;
import java.util.logging.Logger;

import com.subgraph.orchid.TorException;
import com.subgraph.orchid.TorParsingException;
import com.subgraph.orchid.crypto.TorMessageDigest;
import com.subgraph.orchid.crypto.TorNTorKeyAgreement;
import com.subgraph.orchid.crypto.TorPublicKey;
import com.subgraph.orchid.crypto.TorSignature;
import com.subgraph.orchid.data.HexDigest;
import com.subgraph.orchid.data.IPv4Address;
import com.subgraph.orchid.data.Timestamp;
import com.subgraph.orchid.directory.parsing.DocumentFieldParser;
import com.subgraph.orchid.directory.parsing.DocumentObject;
import com.subgraph.orchid.directory.parsing.DocumentParsingHandler;
import com.subgraph.orchid.directory.parsing.NameIntegerParameter;
import com.subgraph.orchid.encoders.Base64;

public class DocumentFieldParserImpl implements DocumentFieldParser {
	private final static Logger logger = Logger.getLogger(DocumentFieldParserImpl.class.getName());
	private final static String BEGIN_TAG = "-----BEGIN";
	private final static String END_TAG = "-----END";
	private final static String TAG_DELIMITER = "-----";
	private final static String DEFAULT_DELIMITER = " ";
	private final ByteBuffer inputBuffer;
	private final SimpleDateFormat dateFormat;
	private String delimiter = DEFAULT_DELIMITER;
	private String currentKeyword;
	private List<String> currentItems;
	private int currentItemsPosition;
	private boolean recognizeOpt;
	/* If a line begins with this string do not include it in the current signature. */
 	private String signatureIgnoreToken;
	private boolean isProcessingSignedEntity = false;
	private TorMessageDigest signatureDigest;
	private TorMessageDigest signatureDigest256;
	private StringBuilder rawDocumentBuffer;

	private DocumentParsingHandler callbackHandler;

	public DocumentFieldParserImpl(ByteBuffer buffer) {
		buffer.rewind();
		this.inputBuffer = buffer;
		rawDocumentBuffer = new StringBuilder();
		dateFormat = createDateFormat();
	}

	private static SimpleDateFormat createDateFormat() {
		final SimpleDateFormat format = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
		format.setTimeZone(TimeZone.getTimeZone("GMT"));
		format.setLenient(false);
		return format;
	}

	public String parseNickname() {
		// XXX verify valid nickname
		return getItem();
	}
	public String parseString() {
		return getItem();
	}

	public void setRecognizeOpt() {
		recognizeOpt = true;
	}

	public void setHandler(DocumentParsingHandler handler) {
		callbackHandler = handler;
	}

	public void setDelimiter(String delimiter) {
		this.delimiter = delimiter;
	}

	public int argumentsRemaining() {
		return currentItems.size() - currentItemsPosition;
	}

	private String getItem() {
		if(currentItemsPosition >= currentItems.size()) 
			throw new TorParsingException("Overrun while reading arguments");
		return currentItems.get(currentItemsPosition++);
	}
	/*
	 * Return a string containing all remaining arguments concatenated together
	 */
	public String parseConcatenatedString() {
		StringBuilder result = new StringBuilder();
		while(argumentsRemaining() > 0) {
			if(result.length() > 0)
				result.append(" ");
			result.append(getItem());
		}
		return result.toString();
	}

	public boolean parseBoolean() {
		final int i = parseInteger();
		if(i == 1)
			return true;
		else if(i == 0)
			return false;
		else 
			throw new TorParsingException("Illegal boolean value: "+ i);
	}

	public int parseInteger() {
		return parseInteger(getItem());
	}

	public int parseInteger(String item) {
		try {
			return Integer.parseInt(item);
		} catch(NumberFormatException e) {
			throw new TorParsingException("Failed to parse expected integer value: " + item);
		}
	}

	public int[] parseIntegerList() {
		final String item = getItem();
		final String[] ns = item.split(",");
		final int[] result = new int[ns.length];
		for(int i = 0; i < result.length; i++) {
			result[i] = parseInteger(ns[i]);
		}
		return result;
	}

	public int parsePort() {
		return parsePort(getItem());
	}

	public int parsePort(String item) {
		final int port = parseInteger(item);
		if(port < 0 || port > 65535)
			throw new TorParsingException("Illegal port value: " + port);
		return port;
	}


	public Timestamp parseTimestamp() {
		String timeAndDate = getItem() + " " + getItem();
		try {
			return new Timestamp(dateFormat.parse(timeAndDate));
		} catch (ParseException e) {
			throw new TorParsingException("Could not parse timestamp value: "+ timeAndDate);
		}
	}

	public HexDigest parseHexDigest() {
		return HexDigest.createFromString(parseString());
	}
	
	public HexDigest parseBase32Digest() {
		return HexDigest.createFromBase32String(parseString());
	}

	public HexDigest parseFingerprint() {
		return HexDigest.createFromString(parseConcatenatedString());
	}

	public void verifyExpectedArgumentCount(String keyword, int argumentCount) {
		verifyExpectedArgumentCount(keyword, argumentCount, argumentCount);
	}

	private  void verifyExpectedArgumentCount(String keyword, int expectedMin, int expectedMax) {
		final int argumentCount = argumentsRemaining();
		if(expectedMin != -1 && argumentCount < expectedMin) 
			throw new TorParsingException("Not enough arguments for keyword '"+ keyword +"' expected "+ expectedMin +" and got "+ argumentCount);

		if(expectedMax != -1 && argumentCount > expectedMax)
			// Is this the correct thing to do, or should just be a warning?
			throw new TorParsingException("Too many arguments for keyword '"+ keyword +"' expected "+ expectedMax +" and got "+ argumentCount);
	}

	public byte[] parseBase64Data() {
		final StringBuilder string = new StringBuilder(getItem());
		switch(string.length() % 4) {
		case 2:
			string.append("==");
			break;
		case 3:
			string.append("=");
			break;
		default:
			break;
		}
		try {
			return Base64.decode(string.toString().getBytes("ISO-8859-1"));
		} catch (UnsupportedEncodingException e) {
			throw new TorException(e);
		}

	}

	public IPv4Address parseAddress() {
		return IPv4Address.createFromString(getItem());
	}

	public TorPublicKey parsePublicKey() {
		final DocumentObject documentObject = parseObject();
		return TorPublicKey.createFromPEMBuffer(documentObject.getContent());
	}

	
	public byte[] parseNtorPublicKey() {
		final byte[] key = parseBase64Data();
		if(key.length != TorNTorKeyAgreement.CURVE25519_PUBKEY_LEN) {
			throw new TorParsingException("NTor public key was not expected length after base64 decoding.  Length is "+ key.length);
		}
		return key;
	}

	public TorSignature parseSignature() {
		final DocumentObject documentObject = parseObject();
		TorSignature s = TorSignature.createFromPEMBuffer(documentObject.getContent());
		return s;
	}

	public NameIntegerParameter parseParameter() {
		final String item = getItem();
		final int eq = item.indexOf('=');
		if(eq == -1) {
			throw new TorParsingException("Parameter not in expected form name=value");
		}
		final String name = item.substring(0, eq);
		validateParameterName(name);
		final int value = parseInteger(item.substring(eq + 1));
		return new NameIntegerParameter(name, value);
	}
	
	private void validateParameterName(String name) {
		if(name.isEmpty()) {
			throw new TorParsingException("Parameter name cannot be empty");
		}
		for(char c: name.toCharArray()) {
			if(!(Character.isLetterOrDigit(c) || c == '_')) {
				throw new TorParsingException("Parameter name can only contain letters.  Rejecting: "+ name);
			}
		}
	}

	public DocumentObject parseTypedObject(String type) {
		final DocumentObject object = parseObject();
		if(!type.equals(object.getKeyword()))
			throw new TorParsingException("Unexpected object type.  Expecting: "+ type +", but got: "+ object.getKeyword());
		return object;
	}

	public DocumentObject parseObject() {
		final String line = readLine();
		final String keyword = parseObjectHeader(line);
		final DocumentObject object = new DocumentObject(keyword, line);
		parseObjectBody(object, keyword);
		return object;
	}

	private String parseObjectHeader(String headerLine) {
		if(!(headerLine.startsWith(BEGIN_TAG) && headerLine.endsWith(TAG_DELIMITER)))
			throw new TorParsingException("Did not find expected object start tag.");
		return headerLine.substring(BEGIN_TAG.length() + 1, 
				headerLine.length() - TAG_DELIMITER.length());
	}

	private void parseObjectBody(DocumentObject object, String keyword) {
		final String endTag = END_TAG +" "+ keyword +TAG_DELIMITER;
		while(true) {
			final String line = readLine();
			if(line == null) {
				throw new TorParsingException("EOF reached before end of '"+ keyword +"' object.");
			}
			if(line.equals(endTag)) {
				object.addFooterLine(line);
				return;
			}
			parseObjectContent(object, line);
		}
	}

	private void parseObjectContent(DocumentObject object, String content) {
		// XXX verify legal base64 data
		object.addContent(content);
	}

	public String getCurrentKeyword() {
		return currentKeyword;
	}

	public void processDocument() {
		if(callbackHandler == null) 
			throw new TorException("DocumentFieldParser#processDocument() called with null callbackHandler");

		while(true) {
			final String line = readLine();
			if(line == null) {
				callbackHandler.endOfDocument();
				return;
			}
			if(processLine(line))
				callbackHandler.parseKeywordLine();
		}
	}

	public void startSignedEntity() {
		isProcessingSignedEntity = true;
		signatureDigest = new TorMessageDigest();
		signatureDigest256 = new TorMessageDigest(true);
	}

	public void endSignedEntity() {
		isProcessingSignedEntity = false;
	}

	public void setSignatureIgnoreToken(String token) {
		signatureIgnoreToken = token;
	}

	public TorMessageDigest getSignatureMessageDigest() {
		return signatureDigest;
	}

	public TorMessageDigest getSignatureMessageDigest256() {
		return signatureDigest256;
	}

	private void updateRawDocument(String line) {
		rawDocumentBuffer.append(line);
		rawDocumentBuffer.append('\n');
	}

	public String getRawDocument() {
		return rawDocumentBuffer.toString();
	}

	public void resetRawDocument() {
		rawDocumentBuffer = new StringBuilder();
	}

	public void resetRawDocument(String initialContent) {
		rawDocumentBuffer = new StringBuilder();
		rawDocumentBuffer.append(initialContent);
	}

	public boolean verifySignedEntity(TorPublicKey publicKey, TorSignature signature) {
		isProcessingSignedEntity = false;
		return publicKey.verifySignature(signature, signatureDigest);
	}

	private String readLine() {
		final String line = nextLineFromInputBuffer();
		if(line != null) {
			updateCurrentSignature(line);
			updateRawDocument(line);
		}
		return line;
	}
	
	private String nextLineFromInputBuffer() {
		if(!inputBuffer.hasRemaining()) {
			return null;
		}
		final StringBuilder sb = new StringBuilder();
		while(inputBuffer.hasRemaining()) {
			char c = (char) (inputBuffer.get() & 0xFF);
			if(c == '\n') {
				return sb.toString();
			} else if(c != '\r') {
				sb.append(c);
			}
		}
		return sb.toString();
	}

	private void updateCurrentSignature(String line) {
		if(!isProcessingSignedEntity)
			return;
		if(signatureIgnoreToken != null && line.startsWith(signatureIgnoreToken))
			return;
		signatureDigest.update(line + "\n");
		signatureDigest256.update(line + "\n");
	}

	private boolean processLine(String line) {
		final List<String> lineItems = Arrays.asList(line.split(delimiter));
		if(lineItems.size() == 0 || lineItems.get(0).length() == 0) {
			// XXX warn
			return false;
		}

		currentKeyword = lineItems.get(0);
		currentItems = lineItems;
		currentItemsPosition = 1;

		if(recognizeOpt && currentKeyword.equals("opt") && lineItems.size() > 1) {
			currentKeyword = lineItems.get(1);
			currentItemsPosition = 2;
		}

		return true;
	}

	public void logDebug(String message) {
		logger.fine(message);
	}

	public void logError(String message) {
		logger.warning(message);
	}

	public void logWarn(String message) {
		logger.info(message);
	}

}
