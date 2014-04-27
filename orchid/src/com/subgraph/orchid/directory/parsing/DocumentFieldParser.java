package com.subgraph.orchid.directory.parsing;

import com.subgraph.orchid.TorParsingException;
import com.subgraph.orchid.crypto.TorMessageDigest;
import com.subgraph.orchid.crypto.TorPublicKey;
import com.subgraph.orchid.crypto.TorSignature;
import com.subgraph.orchid.data.HexDigest;
import com.subgraph.orchid.data.IPv4Address;
import com.subgraph.orchid.data.Timestamp;

/**
 * This helper class is used by document parsing classes to extract individual
 * fields from a directory document.  The DocumentFieldParser also manages the
 * InputStream which is the source of the document to parse.  Parsing classes
 * are implemented by creating an instance of the DocumentParsingHandler interface.
 * 
 */
public interface DocumentFieldParser {
	
	/**
	 * Run the document parser.  The {@link #setHandler(DocumentParsingHandler)} method must be
	 * called before calling this method to set a <code>DocumentParsingHandler</code> for processing
	 * this document.
	 * 
	 * @throws TorParsingException If a parsing error occurs while processing the document.
	 */
	void processDocument();
	
	/**
	 * Returns the number of unprocessed argument items on the current keyword line.
	 * 
	 * @return The number of remaining arguments.
	 */
	int argumentsRemaining();
	
	/**
	 * Extract the next argument item and return it as a String
	 * 
	 * @return The next argument as a String
	 * @throws TorParsingException If no arguments are remaining on the current keyword line.
	 */
	String parseString();
	
	/**
	 * Take all remaining arguments on the current keyword line and return them as a single space
	 * delimited String.  If no arguments are remaining, then an empty String is returned.
	 * 
	 * @return The remaining arguments on the current keyword line concatenated together.
	 */
	String parseConcatenatedString();
	
	/**
	 * Extract the next argument and interpret it as an integer boolean value.  The legal values
	 * are '1' for true or '0' for false.
	 * @return Return the next argument interpreted as a boolean value.
	 * @throws TorParsingException If no arguments are remaining or if the current argument cannot be 
	 *         parsed as a boolean integer value.
	 */
	boolean parseBoolean();
	
	/**
	 * Extract the next argument item and return it as a <code>String</code> if it conforms to
	 * a legally formed router nickname (dir-spec.txt section 2.3).
	 * 
	 * A router nickname must be between 1 and 19 alphanumeric characters ([A-Za-z0-9]) to
	 * be considered valid.
	 * 
	 * @return The next argument as a <code>String</code> if it is a validly formatted nickname.
	 * @throws TorParsingException  If no arguments are remaining or if the current argument is not
	 *         a valid router nickname.
	 */
	String parseNickname();
	
	/**
	 * Extract the next argument and interpret it as an integer.
	 * 
	 * @return The next argument interpreted as an integer.
	 * @throws TorParsingException If no arguments are remaining or if the current argument cannot
	 *         be parsed as an integer value.
	 */
	int parseInteger();
	
	/**
	 * Parse the <code>item</code> argument as an integer.
	 * 
	 * @param item A string to parse as an integer.
	 * @return The integer value of the <code>item</code> argument.
	 * @throws TorParsingException If the <code>item</code> argument cannot be parsed as an 
	 *         integer value.
	 */
	int parseInteger(String item);
	
	/**
	 * Extract the next argument and interpret it as a comma separated list of integers.
	 * 
	 * @return An array of integers.
	 * @throws TorParsingException If no arguments are remaining or if the current argument cannot
	 *         be parsed as a list of integers.
	 */
	int[] parseIntegerList();
	
	/**
	 * Extract the next argument and interpret it as a network port value.  A valid port
	 * value is an integer between 0 and 65535 inclusive.
	 * 
	 * @return The next argument interpreted as an integer port value.
	 * @throws TorParsingException If no arguments are remaining or if the current argument cannot
	 *         be parsed as a legal port value.
	 */
	int parsePort();
	
	/**
	 * Parse the <code>item</code> arguement as a network port value.  A valid port value
	 * is an integer between 0 and 65535 inclusive.
	 * 
	 * @param item A string to parse as an integer port value.
	 * @return The port integer value of the <code>item</code> argument
	 * @throws TorParsingException If the <code>item</code> argument cannot be parsed as a 
	 *         legal port value.
	 */
	int parsePort(String item);
	
	/**
	 * Extract the next argument and interpret it as Base64 encoded binary data.  
	 * 
	 * @return The bytes decoded from the Base64 encoded argument.
	 * @throws TorParsingException If no arguments are remaining or if the current argument cannot
	 *         be parsed as Base64 encoded data.
	 */
	byte[] parseBase64Data();
	
	/**
	 * Extract the next two arguments and parse as a timestamp field.
	 * 
	 * The format of a timestamp is: YYYY-MM-DD HH:MM:SS
	 * 
	 * @return The parsed <code>Timestamp</code> value.
	 * @throws TorParsingException If there are not sufficient arguments remaining or if the current
	 *         arguments could not be parsed as a timestamp field.
	 */
	Timestamp parseTimestamp();
	
	/**
	 * Extract the next argument and interpret it as a hex encoded digest string.
	 * 
	 * @return The parsed <code>HexDigest</code> value.
	 * @throws TorParsingException If no arguments are remaining or if the current argument cannot 
	 *         be parsed as a hex encoded digest string.
	 */
	HexDigest parseHexDigest();
	
	
	/**
	 * Extract the next argument and interpret it as a base 32 encoded digest string.
	 * 
	 * @return The parsed <code>HexDigest</code> value.
	 * @throws TorParsingException If no arguments are remaining or if the current argument cannot 
	 *         be parsed as a base 32 encoded digest string.
	 */
	HexDigest parseBase32Digest();

	/**
	 * Extract all remaining arguments and interpret the concatenated string as a
	 * hex encoded fingerprint string.
	 *  
	 * @return The parsed <code>HexDigest</code> value extracted from the concatenated string.
	 * @throws TorParsingException If the concatenation of the remaining arguments could not be parsed
	 *         as a hex encoded fingerprint string.
	 */
	HexDigest parseFingerprint();
	
	/**
	 * Extract the next argument and interpret it as an IPv4 network address in dotted quad notation.
	 * 
	 * @return The parsed <code>IPv4Address</code> value.
	 * @throws TorParsingException If no arguments are remaining or if the current argument cannot
	 *         be parsed as an IPv4 network address.
	 */
	IPv4Address parseAddress();
	
	/**
	 * Extract a document object following the current keyword line and interpret it as a PEM
	 * encoded public key.
	 * 
	 * @return The extracted <code>TorPublicKey</code> value.
	 * @throws TorParsingException If no document object is found following the current keyword line,
	 *         or if the document object cannot be parsed as a PEM encoded public key.
	 */
	TorPublicKey parsePublicKey();
	
	byte[] parseNtorPublicKey();
	/**
	 * Extract a document object following the current keyword line and interpret it as a 
	 * Base64 encoded PKCS1 signature object.
	 * 
	 * @return The extracted <code>TorSignature</code> value.
	 * @throws TorParsingException If no document object is found following the current keyword line,
	 *         or if the document object cannot be parsed as a signature.
	 */
	TorSignature parseSignature();
	
	/**
	 * Extract a document object following the current keyword line and don't attempt to interpret
	 * it further.
	 * 
	 * @return The extracted <code>DocumentObject</code>.
	 * @throws TorParsingException If no document object is found following the current keyword line.
	 */
	DocumentObject parseObject();
	
	/**
	 * 
	 * @return
	 */
	
	NameIntegerParameter parseParameter();
	/**
	 * Return the keyword of the current keyword line.  The keyword is the first token on the line 
	 * unless the first token is 'opt' and 'opt' recognition is enabled.  In this case, the keyword
	 * is the token immediately following the 'opt' token.
	 * 
	 * @return The keyword token of the current keyword line.
	 */
	String getCurrentKeyword();
	
	/**
	 * Return all lines from the current document as a single String.
	 * 
	 * @return The raw data from the current document.
	 */
	String getRawDocument();
	
	/**
	 * Empty the internal buffer which is capturing the raw data from
	 * the document which is being parsed. 
	 */
	void resetRawDocument();
	
	/**
	 * Empty the internal buffer which is capturing raw data from document being parsed and set buffer contents to <tt>initalContent</tt>.
	 * 
	 * @param initialContent Initial raw document content.
	 */
	void resetRawDocument(String initialContent);
	
	/**
	 * Reset the document signing state.  Any lines read after calling this method will be included 
	 * in the current signature hash.
	 */
	void startSignedEntity();
	
	/**
	 * Set the current keyword line as the last line included in the current signature hash.
	 */
	void endSignedEntity();
	
	/**
	 * Tells the parser to not include lines that begin with <code>token</code> in the current
	 * signature calculation.
	 * 
	 * @param token The parser will not include lines that begin with <code>token</code> in the
	 *              current signature.
	 */
	void setSignatureIgnoreToken(String token);
	
	/**
	 * Return the internal message digest which is being used to calculate the
	 * signature over the current document.
	 * 
	 * @return The <code>TorMessageDigest</code> instance or <code>null</code> if 
	 *         a signature is not being actively calculated.
	 */
	TorMessageDigest getSignatureMessageDigest();
	TorMessageDigest getSignatureMessageDigest256();
	
	/**
	 * Verify that current signature hash matches the specified <code>signature</code> signed
	 * with the public key <code>publicKey</code>
	 * 
	 * @param publicKey The public key used to verify the signature.
	 * @param signature The signature to verify against the current signature hash.
	 * @return <code>true</code>If the <code>signature</code> argument matches the hash currently
	 *         calculated document hash.
	 */
	boolean verifySignedEntity(TorPublicKey publicKey, TorSignature signature);
	
	/**
	 * Test that the current keyword line has the correct number of arguments.
	 * 
	 * @param keyword The name of the current keyword. (used for errors)
	 * @param argumentCount The expected number of arguments.
	 * @throws TorParsingException If the number of remaining arguments does not match
	 *         <code>argumentCount</code>.
	 */
	void verifyExpectedArgumentCount(String keyword, int argumentCount);

	/**
	 * Set a flag so that 'opt' tokens will be recognized at the start of keyword lines.  If
	 * this flag is set, a token string 'opt' at the start of a keyword line will be ignored 
	 * and the token following the 'opt' string will be interpreted as the keyword.
	 */
	void setRecognizeOpt();
	
	/**
	 * The default delimiter between keyword line tokens is any whitespace.  This method may
	 * be called to specify a different delimiter policy.
	 * 
	 * @param delimeter A regular expression which matches the desired delimiter.
	 */
	void setDelimiter(String delimeter);
	
	/**
	 * Set the callback handler which is used to process the document.  This method must be called
	 * before calling {@link #processDocument()}.
	 * 
	 * @param handler The callback handler.
	 */
	void setHandler(DocumentParsingHandler handler);

	/**
	 * Log the specified message at the debug logging level.
	 * 
	 * @param message The message to log.
	 */
	void logDebug(String message);
	
	/**
	 * Log the specified message at the warn logging level.
	 * 
	 * @param message The message to log.
	 */
	void logWarn(String message);
	
	/**
	 * Log the specified message at the error logging level.
	 * 
	 * @param message The message to log.
	 */
	void logError(String message);

}
