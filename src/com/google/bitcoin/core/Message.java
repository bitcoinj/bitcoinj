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

    // Useful to ensure serialize/deserialize are consistent with each other.
    private static final boolean SELF_CHECK = false;

    // The offset is how many bytes into the provided byte array this message starts at.
    protected transient int offset;
    // The cursor keeps track of where we are in the byte array as we parse it.
    // Note that it's relative to the start of the array NOT the start of the message.
    protected transient int cursor;

    // The raw message bytes themselves.
    protected transient byte[] bytes;
    
    private transient boolean parsed = false;
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
    	this(params, msg, offset, protocolVersion, false, false);
    }
    
    @SuppressWarnings("unused")
    Message(NetworkParameters params, byte[] msg, int offset, int protocolVersion, final boolean parseLazy, final boolean parseRetain) throws ProtocolException {
        this.parseLazy = parseLazy;
        this.parseRetain = parseRetain;
    	this.protocolVersion = protocolVersion;
        this.params = params;
        this.bytes = msg;
        this.cursor = this.offset = offset;
        if (!parseLazy) {
        	parse();
        	parsed = true;
        }
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
        this(params, msg, offset, NetworkParameters.PROTOCOL_VERSION, false, false);
    }
    
    Message(NetworkParameters params, byte[] msg, int offset, final boolean parseLazy, final boolean parseRetain) throws ProtocolException {
        this(params, msg, offset, NetworkParameters.PROTOCOL_VERSION, parseLazy, parseRetain);
    }
    
    // These methods handle the serialization/deserialization using the custom BitCoin protocol.
    // It's somewhat painful to work with in Java, so some of these objects support a second 
    // serialization mechanism - the standard Java serialization system. This is used when things 
    // are serialized to the wallet.
    abstract void parse() throws ProtocolException;
    
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
			//if (!parseRetain)
				//bytes = null;
		} catch (ProtocolException e) {
			throw new RuntimeException("Lazy parsing of message failed", e);
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

    	
    	//if (!parseRetain)
    	//	return;
    	//checkParse();
    	//bytes = null;
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
    final public byte[] bitcoinSerialize() {
    	
    	//1st attempt to use a cached array
    	if (bytes != null) {
    		if (offset == 0 && cursor == bytes.length) {
    			//cached byte array is the entire message with no extras
    			//so we can return as is and avoid an array copy.
    			return bytes;
    		}
    		int len = cursor - offset;
    		byte[] buf = new byte[len];
    		System.arraycopy(bytes, offset, buf, 0, len);
    		return buf;
    	}
    	
    	//no cached array available so serialize parts by stream.
    	ByteArrayOutputStream stream = new ByteArrayOutputStream();
        try {
            bitcoinSerializeToStream(stream);
        } catch (IOException e) {
            // Cannot happen, we are serializing to a memory stream.
            throw new RuntimeException(e);
        }
        return stream.toByteArray();
    }
    
    /**
     * Serialize this message to the provided OutputStream using the bitcoin wire format.
     * @param stream
     * @throws IOException
     */
    final public void bitcoinSerialize(OutputStream stream) throws IOException {
    	//1st check for cached bytes
    	if (bytes != null) {
    		stream.write(bytes, offset, cursor - offset);
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
    
    int getMessageSize() {
        return cursor - offset;
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
}
