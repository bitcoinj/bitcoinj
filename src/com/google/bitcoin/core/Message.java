/**
 * Copyright 2011 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.google.bitcoin.core;

import java.io.*;
import java.math.BigInteger;
import java.util.Arrays;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A Message is a data structure that can be serialized/deserialized using both the BitCoin proprietary serialization
 * format and built-in Java object serialization. Specific types of messages that are used both in the block chain,
 * and on the wire, are derived from this class.
 *
 * This class is not useful for library users. If you want to talk to the network see the {@link Peer} class.
 */
public abstract class Message implements Serializable {
	private static final Logger log = LoggerFactory.getLogger(Message.class);
	private static final long serialVersionUID = -3561053461717079135L;

    public static final int MAX_SIZE = 0x02000000;
	
	public static final int UNKNOWN_LENGTH = -1;

    // Useful to ensure serialize/deserialize are consistent with each other.
    private static final boolean SELF_CHECK = false;

    // The offset is how many bytes into the provided byte array this message starts at.
    protected transient int offset;
    // The cursor keeps track of where we are in the byte array as we parse it.
    // Note that it's relative to the start of the array NOT the start of the message.
    protected transient int cursor;
    
    protected transient int length = UNKNOWN_LENGTH;

    // The raw message bytes themselves.
    protected transient byte[] bytes;
    
    protected transient boolean parsed = false;
    protected transient boolean recached = false;
    protected transient final boolean parseLazy;
    protected transient final boolean parseRetain;

    protected transient int protocolVersion;

    // This will be saved by subclasses that implement Serializable.
    protected NetworkParameters params;

    /** This exists for the Java serialization framework to use only. */
    protected Message() {
    	parsed = true;
    	parseLazy = false;
    	parseRetain = false;
    }
    
    Message(NetworkParameters params) {
        this.params = params;
        parsed = true;
        parseLazy = false;
    	parseRetain = false;
    }

    Message(NetworkParameters params, byte[] msg, int offset, int protocolVersion) throws ProtocolException {
    	this(params, msg, offset, protocolVersion, false, false, UNKNOWN_LENGTH);
    }
    
    @SuppressWarnings("unused")
    Message(NetworkParameters params, byte[] msg, int offset, int protocolVersion, final boolean parseLazy, final boolean parseRetain, int length) throws ProtocolException {
        this.parseLazy = parseLazy;
        this.parseRetain = parseRetain;
    	this.protocolVersion = protocolVersion;
        this.params = params;
        this.bytes = msg;
        this.cursor = this.offset = offset;
        this.length = length;
        if (parseLazy) {
        	parseLite();
        } else {
        	parseLite();
        	parse();
        	parsed = true;
        }
        
        assert (parseLazy ? !parsed : parsed && (parseRetain ? bytes != null : bytes == null)) 
        	: "parseLazy : " + parseLazy + " parsed: " + parsed 
        	+ " parseRetain:" + parseRetain 
        	+ " bytes == null" + bytes == null;
        
        if (SELF_CHECK && !this.getClass().getSimpleName().equals("VersionMessage"))  {
            checkParse();
        	byte[] msgbytes = new byte[cursor - offset];
            System.arraycopy(msg, offset, msgbytes, 0, cursor - offset);
            byte[] reserialized = bitcoinSerialize();
            if (!Arrays.equals(reserialized, msgbytes))
                throw new RuntimeException("Serialization is wrong: \n" +
                        Utils.bytesToHexString(reserialized) + " vs \n" +
                        Utils.bytesToHexString(msgbytes));
        }
        if (parseRetain || !parsed)
        	return;
        this.bytes = null;
    }

    Message(NetworkParameters params, byte[] msg, int offset) throws ProtocolException {
        this(params, msg, offset, NetworkParameters.PROTOCOL_VERSION, false, false, UNKNOWN_LENGTH);
    }
    
    Message(NetworkParameters params, byte[] msg, int offset, final boolean parseLazy, final boolean parseRetain, int length) throws ProtocolException {
        this(params, msg, offset, NetworkParameters.PROTOCOL_VERSION, parseLazy, parseRetain, length);
    }
    
    // These methods handle the serialization/deserialization using the custom BitCoin protocol.
    // It's somewhat painful to work with in Java, so some of these objects support a second 
    // serialization mechanism - the standard Java serialization system. This is used when things 
    // are serialized to the wallet.
    abstract void parse() throws ProtocolException;
    
    /**
     * Perform the most minimal parse possible to calculate the length of the message.
     * This is only required for subclasses of ChildClass as root level messages will have their length passed
     * into the constructor.
     * 
     * It is expected that the length field will be set before this method returns.
     * @return 
     * @throws ProtocolException 
     */
    protected abstract void parseLite() throws ProtocolException;
//    {
//    	length = getMessageSize();
//    }
    
    /**
     * Ensure the object is parsed if needed.  This should be called in every getter before returning a value.
     * If the lazy parse flag is not set this is a method returns immediately.  
     */
    protected synchronized void checkParse() {
    	if (parsed || bytes == null)
    		return;
    	try {
			parse();
			parsed = true;
			if (!parseRetain)
				bytes = null;
		} catch (ProtocolException e) {
			 throw new LazyParseException("ProtocolException caught during lazy parse.  For safe access to fields call ensureParsed before attempting read or write access", e);
		}
    }
    
    /**
     * In lazy parsing mode access to getters and setters may throw an unchecked LazyParseException.  If guaranteed safe access is required
     * this method will force parsing to occur immediately thus ensuring LazyParseExeption will never be thrown from this Message.
     * If the Message contains child messages (e.g. a Block containing Transaction messages) this will not force child messages to parse.
     * 
     * This could be overidden for Transaction and it's child classes to ensure the entire tree of Message objects is parsed.
     * 
     * @throws ProtocolException
     */
    public void ensureParsed() throws ProtocolException {
    	try {
    		checkParse();
    	} catch (LazyParseException e) {
    		if (e.getCause() instanceof ProtocolException)
    			throw (ProtocolException) e.getCause();
    		throw new ProtocolException(e);
    	}
    }
    
    /**
     * To be called before any change of internal values including any setters.  This ensures any cached byte array is removed after performing
     * a lazy parse if necessary to ensure the object is fully populated.
     * 
     * Child messages of this object(e.g. Transactions belonging to a Block) will not have their internal byte caches invalidated unless
     * they are also modified internally.
     */
    protected void unCache() {
    	
    	/*
    	 * 	   This is a NOP at the moment.  Will complete lazy parsing as a separate patch first.
    	 *     safe retention of backing byte array is tricky in cases where a parent Message object
    	 *     may have child message objects (e.g. block - tx).  There has to be a way to either
    	 *     mark the cursor at the end of the parent portion of the array or a way the child can
    	 *     invalidate the parent array. This might require a ByteArrayView class which implements List
    	 *     and retains a reference to it's parent ByteArrayView so it can invalidate it.  
    	 *     Alternately the child message can hold a reference to
    	 *     it's parent and propagate a call to unCache up the chain to the parent.  This way only those children on the
    	 *     invalidated branch lose their caching.  On the other hand this might introduce more overhead than it's worth
    	 *     since this call has to made in every setter.
    	 *     Perhaps a simpler approach where in the special cases where a cached array is wanted it is the callers responsibility
    	 *     to keep track of whether the cache is valid or not.
    	 */

    	checkParse();
    	bytes = null;
    	recached = false;
    }
    
    protected void adjustLength(int adjustment) {
    	if (length != UNKNOWN_LENGTH)
    		//our own length is now unknown if we have an unknown length adjustment.
    		length = adjustment == UNKNOWN_LENGTH ? UNKNOWN_LENGTH : length + adjustment;
    }
    
    /**
     * used for unit testing
     */
    public boolean isParsed() {
    	return parsed;
    }
    
    /**
     * used for unit testing
     */
    public boolean isCached() {
    	//return parseLazy ? parsed && bytes != null : bytes != null;
    	return bytes != null;
    }
    
    public boolean isRecached() {
    	return recached;
    }
    
    /**
     * Serialize this message to a byte array that conforms to the bitcoin wire protocol.
     * <br/>
     * This method may return the original byte array used to construct this message if the 
     * following conditions are met:
     * <ol>
     * <li>1) The message was parsed from a byte array with parseRetain = true</li>
     * <li>2) The message has not been modified</li>
     * <li>3) The array had an offset of 0 and no surplus bytes</li>
     * </ol>
     * 
     * If condition 3 is not met then an copy of the relevant portion of the array will be returned.
     * Otherwise a full serialize will occur. 
     * 
     * @return 
     */
    public byte[] bitcoinSerialize() {
    	
    	//1st attempt to use a cached array
    	if (bytes != null) {
    		if (offset == 0 && length == bytes.length) {
    			//cached byte array is the entire message with no extras
    			//so we can return as is and avoid an array copy.
    			return bytes;
    		}
    		
    		//int len = cursor - offset;
    		byte[] buf = new byte[length];
    		System.arraycopy(bytes, offset, buf, 0, length);
    		return buf;
    	}
    	
    	assert bytes == null : "cached bytes present but failed to use them for serialization";
    	
    	//no cached array available so serialize parts by stream.
    	ByteArrayOutputStream stream = new UnsafeByteArrayOutputStream(length < 32 ? 32 : length + 32);
        try {
            bitcoinSerializeToStream(stream);
        } catch (IOException e) {
            // Cannot happen, we are serializing to a memory stream.
        }
        
        if (parseRetain) {
        	//a free set of steak knives!
        	//If there happens to be a call to this method we gain an opportunity to recache
        	//the byte array and in this case it contains no bytes from parent messages.
        	//This give a dual benefit.  Releasing references to the larger byte array so that it
        	//it is more likely to be GC'd.  A preventing double serializations.  E.g. calculating
        	//merkle root calls this method.  It is will frequently happen prior to serializing the block
        	//which means another call to bitcoinSerialize is coming.  If we didn't recache then internal
        	//serialization would occur a 2nd time and every subsequent time the message is serialized.
        	bytes = stream.toByteArray();
        	cursor = cursor - offset;
        	offset = 0;
        	recached = true;
        	length = bytes.length;
        	return bytes;
        }
        //record length.  If this Message wasn't parsed from a but stream it won't have length field
        //set (except for static length message types).  Setting it makes future streaming more efficient
        //because we can preallocate the ByteArrayOutputStream buffer and avoid resizing.
        byte[] buf = stream.toByteArray();
        length = buf.length;
        return buf;
    }
    
    /**
     * Serialize this message to the provided OutputStream using the bitcoin wire format.
     * @param stream
     * @throws IOException
     */
    final public void bitcoinSerialize(OutputStream stream) throws IOException {
    	//1st check for cached bytes
    	if (bytes != null && length != UNKNOWN_LENGTH) {
    		stream.write(bytes, offset, length);
    		return;
    	}
    	
    	bitcoinSerializeToStream(stream);
    }

    /**
     * Serializes this message to the provided stream. If you just want the raw bytes use bitcoinSerialize().
     */
    void bitcoinSerializeToStream(OutputStream stream) throws IOException {
    	log.debug("Warning: {} class has not implemented bitcoinSerializeToStream method.  Generating message with no payload", getClass());
    }
    
    /**
     * This method is a NOP for all classes except Block and Transaction.  It is only declared in Message
     * so BitcoinSerializer can avoid 2 instanceof checks + a casting.
     * @return
     */
    public Sha256Hash getHash() {
    	return null;
    }
    
    /**
     * This should be overridden to extract correct message size in the case of lazy parsing.  Until this method is
     * implemented in a subclass of ChildMessage lazy parsing may have no effect.
     * 
     * This default implementation is a safe fall back that will ensure it returns a correct value by parsing the message.
     * @return
     */
    int getMessageSize() {
        if (length != UNKNOWN_LENGTH)
        	return length;
    	checkParse();
    	if (length != UNKNOWN_LENGTH)
    		length = cursor - offset;
    	return length;
    }
    
    long readUint32() {
        long u = Utils.readUint32(bytes, cursor);
        cursor += 4;
        return u;
    }
    
    Sha256Hash readHash() {
        byte[] hash = new byte[32];
        System.arraycopy(bytes, cursor, hash, 0, 32);
        // We have to flip it around, as it's been read off the wire in little endian.
        // Not the most efficient way to do this but the clearest.
        hash = Utils.reverseBytes(hash);        
        cursor += 32;
        return new Sha256Hash(hash);
    }


    BigInteger readUint64() {
        // Java does not have an unsigned 64 bit type. So scrape it off the wire then flip.
        byte[] valbytes = new byte[8];
        System.arraycopy(bytes, cursor, valbytes, 0, 8);
        valbytes = Utils.reverseBytes(valbytes);
        cursor += valbytes.length;
        return new BigInteger(valbytes);
    }
    
    long readVarInt() {
        VarInt varint = new VarInt(bytes, cursor);
        cursor += varint.getSizeInBytes();
        return varint.value;
    }
    
    long readVarInt(int offset) {
    	VarInt varint = new VarInt(bytes, cursor + offset);
        cursor += offset + varint.getSizeInBytes();
        return varint.value;
    }


    byte[] readBytes(int length) {
        byte[] b = new byte[length];
        System.arraycopy(bytes, cursor, b, 0, length);
        cursor += length;
        return b;
    }

    String readStr() {
        VarInt varInt = new VarInt(bytes, cursor);
        if (varInt.value == 0) {
            cursor += 1;
            return "";
        }
        cursor += varInt.getSizeInBytes();
        byte[] characters = new byte[(int)varInt.value];
        System.arraycopy(bytes, cursor, characters, 0, characters.length);
        cursor += characters.length;
        try {
            return new String(characters, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);  // Cannot happen, UTF-8 is always supported.
        }
    }
    
    public class LazyParseException extends RuntimeException {

		public LazyParseException(String message, Throwable cause) {
			super(message, cause);
		}

		public LazyParseException(String message) {
			super(message);
		}
    	
    }
}
