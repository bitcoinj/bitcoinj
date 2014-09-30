/**
 * Copyright 2013 Matt Corallo
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

package org.bitcoinj.core;

import java.io.IOException;
import java.io.OutputStream;

/**
 * A message sent by nodes when a message we sent was rejected (ie a transaction had too little fee/was invalid/etc)
 */
public class RejectMessage extends Message {
    private static final long serialVersionUID = -5246995579800334336L;

    private String message, reason;
    public static enum RejectCode {
        /** The message was not able to be parsed */
        MALFORMED((byte) 0x01),
        /** The message described an invalid object */
        INVALID((byte) 0x10),
        /** The message was obsolete or described an object which is obsolete (eg unsupported, old version, v1 block) */
        OBSOLETE((byte) 0x11),
        /**
         * The message was relayed multiple times or described an object which is in conflict with another.
         * This message can describe errors in protocol implementation or the presence of an attempt to DOUBLE SPEND.
         */
        DUPLICATE((byte) 0x12),
        /**
         * The message described an object was not standard and was thus not accepted.
         * The reference client has a concept of standard transaction forms, which describe scripts and encodings which
         * it is willing to relay further. Other transactions are neither relayed nor mined, though they are considered
         * valid if they appear in a block.
         */
        NONSTANDARD((byte) 0x40),
        /**
         * This refers to a specific form of NONSTANDARD transactions, which have an output smaller than some constant
         * defining them as dust (this is no longer used).
         */
        DUST((byte) 0x41),
        /** The messages described an object which did not have sufficient fee to be relayed further. */
        INSUFFICIENTFEE((byte) 0x42),
        /** The message described a block which was invalid according to hard-coded checkpoint blocks. */
        CHECKPOINT((byte) 0x43),
        OTHER((byte) 0xff);

        byte code;
        RejectCode(byte code) { this.code = code; }
        static RejectCode fromCode(byte code) {
            for (RejectCode rejectCode : RejectCode.values())
                if (rejectCode.code == code)
                    return rejectCode;
            return OTHER;
        }
    }
    private RejectCode code;
    private Sha256Hash messageHash;

    public RejectMessage(NetworkParameters params, byte[] payload) throws ProtocolException {
        super(params, payload, 0);
    }

    public RejectMessage(NetworkParameters params, byte[] payload, boolean parseLazy, boolean parseRetain, int length) throws ProtocolException {
        super(params, payload, 0, parseLazy, parseRetain, length);
    }

    @Override
    protected void parseLite() throws ProtocolException {
        message = readStr();
        code = RejectCode.fromCode(readBytes(1)[0]);
        reason = readStr();
        if (message.equals("block") || message.equals("tx"))
            messageHash = readHash();
        length = cursor - offset;
    }

    @Override
    public void parse() throws ProtocolException {
        if (length == UNKNOWN_LENGTH)
            parseLite();
    }

    @Override
    public void bitcoinSerializeToStream(OutputStream stream) throws IOException {
        byte[] messageBytes = message.getBytes("UTF-8");
        stream.write(new VarInt(messageBytes.length).encode());
        stream.write(messageBytes);
        stream.write(code.code);
        byte[] reasonBytes = reason.getBytes("UTF-8");
        stream.write(new VarInt(reasonBytes.length).encode());
        stream.write(reasonBytes);
        if (message.equals("block") || message.equals("tx"))
            stream.write(messageHash.getBytes());
    }

    /**
     * Provides the type of message which was rejected by the peer.
     * Note that this is ENTIRELY UNTRUSTED and should be sanity-checked before it is printed or processed.
     */
    public String getRejectedMessage() {
        ensureParsed();
        return message;
    }

    /**
     * Provides the hash of the rejected object (if getRejectedMessage() is either "tx" or "block"), otherwise null.
     */
    public Sha256Hash getRejectedObjectHash() {
        ensureParsed();
        return messageHash;
    }

    /**
     * The reason code given for why the peer rejected the message.
     */
    public RejectCode getReasonCode() {
        return code;
    }

    /**
     * The reason message given for rejection.
     * Note that this is ENTIRELY UNTRUSTED and should be sanity-checked before it is printed or processed.
     */
    public String getReasonString() {
        return reason;
    }

    @Override
    public String toString() {
        Sha256Hash hash = getRejectedObjectHash();
        if (hash != null)
            return String.format("Reject: %s %s for reason '%s' (%d)", getRejectedMessage(), getRejectedObjectHash(),
                getReasonString(), getReasonCode().code);
        else
            return String.format("Reject: %s for reason '%s' (%d)", getRejectedMessage(),
                    getReasonString(), getReasonCode().code);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        RejectMessage other = (RejectMessage) o;
        return message.equals(other.message) &&
               code.equals(other.code) &&
               reason.equals(other.reason) &&
               messageHash.equals(other.messageHash);
    }

    @Override
    public int hashCode() {
        int result = message.hashCode();
        result = 31 * result + reason.hashCode();
        result = 31 * result + code.hashCode();
        result = 31 * result + messageHash.hashCode();
        return result;
    }
}
