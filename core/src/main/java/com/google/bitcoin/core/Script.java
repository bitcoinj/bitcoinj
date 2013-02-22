/**
 * Copyright 2011 Google Inc.
 * Copyright 2012 Matt Corallo.
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

import org.spongycastle.crypto.digests.RIPEMD160Digest;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;

import static com.google.bitcoin.core.Utils.bytesToHexString;

/**
 * A chunk in a script
 */
class ScriptChunk {
    public boolean isOpCode;
    public byte[] data;
    public int startLocationInProgram;
    public ScriptChunk(boolean isOpCode, byte[] data, int startLocationInProgram) {
        this.isOpCode = isOpCode;
        this.data = data;
        this.startLocationInProgram = startLocationInProgram;
    }
    public boolean equalsOpCode(int opCode) {
        return isOpCode &&
                data.length == 1 &&
                (0xFF & data[0]) == opCode;
    }
}

/**
 * <p>Programs embedded inside transactions that control redemption of payments.</p>
 *
 * <p>Bitcoin transactions don't specify what they do directly. Instead <a href="https://en.bitcoin.it/wiki/Script">a
 * small binary stack language</a> is used to define programs that when evaluated return whether the transaction
 * "accepts" or rejects the other transactions connected to it.</p>
 *
 * <p>In SPV mode, scripts are not run, because that would require all transactions to be available and lightweight
 * clients don't have that data. In full mode, this class is used to run the interpreted language. It also has
 * static methods for building scripts.</p>
 */
public class Script {
    // Some constants used for decoding the scripts, copied from the reference client
    // push value
    public static final int OP_0 = 0x00;
    public static final int OP_FALSE = OP_0;
    public static final int OP_PUSHDATA1 = 0x4c;
    public static final int OP_PUSHDATA2 = 0x4d;
    public static final int OP_PUSHDATA4 = 0x4e;
    public static final int OP_1NEGATE = 0x4f;
    public static final int OP_RESERVED = 0x50;
    public static final int OP_1 = 0x51;
    public static final int OP_TRUE=OP_1;
    public static final int OP_2 = 0x52;
    public static final int OP_3 = 0x53;
    public static final int OP_4 = 0x54;
    public static final int OP_5 = 0x55;
    public static final int OP_6 = 0x56;
    public static final int OP_7 = 0x57;
    public static final int OP_8 = 0x58;
    public static final int OP_9 = 0x59;
    public static final int OP_10 = 0x5a;
    public static final int OP_11 = 0x5b;
    public static final int OP_12 = 0x5c;
    public static final int OP_13 = 0x5d;
    public static final int OP_14 = 0x5e;
    public static final int OP_15 = 0x5f;
    public static final int OP_16 = 0x60;

    // control
    public static final int OP_NOP = 0x61;
    public static final int OP_VER = 0x62;
    public static final int OP_IF = 0x63;
    public static final int OP_NOTIF = 0x64;
    public static final int OP_VERIF = 0x65;
    public static final int OP_VERNOTIF = 0x66;
    public static final int OP_ELSE = 0x67;
    public static final int OP_ENDIF = 0x68;
    public static final int OP_VERIFY = 0x69;
    public static final int OP_RETURN = 0x6a;

    // stack ops
    public static final int OP_TOALTSTACK = 0x6b;
    public static final int OP_FROMALTSTACK = 0x6c;
    public static final int OP_2DROP = 0x6d;
    public static final int OP_2DUP = 0x6e;
    public static final int OP_3DUP = 0x6f;
    public static final int OP_2OVER = 0x70;
    public static final int OP_2ROT = 0x71;
    public static final int OP_2SWAP = 0x72;
    public static final int OP_IFDUP = 0x73;
    public static final int OP_DEPTH = 0x74;
    public static final int OP_DROP = 0x75;
    public static final int OP_DUP = 0x76;
    public static final int OP_NIP = 0x77;
    public static final int OP_OVER = 0x78;
    public static final int OP_PICK = 0x79;
    public static final int OP_ROLL = 0x7a;
    public static final int OP_ROT = 0x7b;
    public static final int OP_SWAP = 0x7c;
    public static final int OP_TUCK = 0x7d;

    // splice ops
    public static final int OP_CAT = 0x7e;
    public static final int OP_SUBSTR = 0x7f;
    public static final int OP_LEFT = 0x80;
    public static final int OP_RIGHT = 0x81;
    public static final int OP_SIZE = 0x82;

    // bit logic
    public static final int OP_INVERT = 0x83;
    public static final int OP_AND = 0x84;
    public static final int OP_OR = 0x85;
    public static final int OP_XOR = 0x86;
    public static final int OP_EQUAL = 0x87;
    public static final int OP_EQUALVERIFY = 0x88;
    public static final int OP_RESERVED1 = 0x89;
    public static final int OP_RESERVED2 = 0x8a;

    // numeric
    public static final int OP_1ADD = 0x8b;
    public static final int OP_1SUB = 0x8c;
    public static final int OP_2MUL = 0x8d;
    public static final int OP_2DIV = 0x8e;
    public static final int OP_NEGATE = 0x8f;
    public static final int OP_ABS = 0x90;
    public static final int OP_NOT = 0x91;
    public static final int OP_0NOTEQUAL = 0x92;

    public static final int OP_ADD = 0x93;
    public static final int OP_SUB = 0x94;
    public static final int OP_MUL = 0x95;
    public static final int OP_DIV = 0x96;
    public static final int OP_MOD = 0x97;
    public static final int OP_LSHIFT = 0x98;
    public static final int OP_RSHIFT = 0x99;

    public static final int OP_BOOLAND = 0x9a;
    public static final int OP_BOOLOR = 0x9b;
    public static final int OP_NUMEQUAL = 0x9c;
    public static final int OP_NUMEQUALVERIFY = 0x9d;
    public static final int OP_NUMNOTEQUAL = 0x9e;
    public static final int OP_LESSTHAN = 0x9f;
    public static final int OP_GREATERTHAN = 0xa0;
    public static final int OP_LESSTHANOREQUAL = 0xa1;
    public static final int OP_GREATERTHANOREQUAL = 0xa2;
    public static final int OP_MIN = 0xa3;
    public static final int OP_MAX = 0xa4;

    public static final int OP_WITHIN = 0xa5;

    // crypto
    public static final int OP_RIPEMD160 = 0xa6;
    public static final int OP_SHA1 = 0xa7;
    public static final int OP_SHA256 = 0xa8;
    public static final int OP_HASH160 = 0xa9;
    public static final int OP_HASH256 = 0xaa;
    public static final int OP_CODESEPARATOR = 0xab;
    public static final int OP_CHECKSIG = 0xac;
    public static final int OP_CHECKSIGVERIFY = 0xad;
    public static final int OP_CHECKMULTISIG = 0xae;
    public static final int OP_CHECKMULTISIGVERIFY = 0xaf;

    // expansion
    public static final int OP_NOP1 = 0xb0;
    public static final int OP_NOP2 = 0xb1;
    public static final int OP_NOP3 = 0xb2;
    public static final int OP_NOP4 = 0xb3;
    public static final int OP_NOP5 = 0xb4;
    public static final int OP_NOP6 = 0xb5;
    public static final int OP_NOP7 = 0xb6;
    public static final int OP_NOP8 = 0xb7;
    public static final int OP_NOP9 = 0xb8;
    public static final int OP_NOP10 = 0xb9;

    public static final int OP_INVALIDOPCODE = 0xff;

    byte[] program;
    private int cursor;

    // The program is a set of byte[]s where each element is either [opcode] or [data, data, data ...]
    List<ScriptChunk> chunks;
    private final NetworkParameters params;
    
    // Only for internal use
    private Script() {
        params = null;
    }

    /**
     * Construct a Script using the given network parameters and a range of the programBytes array.
     *
     * @param params       Network parameters.
     * @param programBytes Array of program bytes from a transaction.
     * @param offset       How many bytes into programBytes to start reading from.
     * @param length       How many bytes to read.
     * @throws ScriptException
     */
    public Script(NetworkParameters params, byte[] programBytes, int offset, int length) throws ScriptException {
        this.params = params;
        parse(programBytes, offset, length);
    }

    /**
     * Returns the program opcodes as a string, for example "[1234] DUP HAHS160"
     */
    public String toString() {
        StringBuffer buf = new StringBuffer();
        for (ScriptChunk chunk : chunks) {
            if (chunk.isOpCode) {
                buf.append(getOpCodeName(chunk.data[0]));
                buf.append(" ");
            } else {
                // Data chunk
                buf.append("[");
                buf.append(bytesToHexString(chunk.data));
                buf.append("] ");
            }
        }
        return buf.toString();
    }
    
    /**
     * Converts the given OpCode into a string (eg "0", "PUSHDATA", or "NON_OP(10)")
     */
    public static String getOpCodeName(byte opCode) {
        int opcode = opCode & 0xff;
        switch (opcode) {
        case OP_0:
            return "0";
        case OP_PUSHDATA1:
            return "PUSHDATA1";
        case OP_PUSHDATA2:
            return "PUSHDATA1";
        case OP_PUSHDATA4:
            return "PUSHDATA4";
        case OP_1NEGATE:
            return "1NEGATE";
        case OP_RESERVED:
            return "RESERVED";
        case OP_1:
            return "1";
        case OP_2:
            return "2";
        case OP_3:
            return "3";
        case OP_4:
            return "4";
        case OP_5:
            return "5";
        case OP_6:
            return "6";
        case OP_7:
            return "7";
        case OP_8:
            return "8";
        case OP_9:
            return "9";
        case OP_10:
            return "10";
        case OP_11:
            return "11";
        case OP_12:
            return "12";
        case OP_13:
            return "13";
        case OP_14:
            return "14";
        case OP_15:
            return "15";
        case OP_16:
            return "16";
        case OP_NOP:
            return "NOP";
        case OP_VER:
            return "VER";
        case OP_IF:
            return "IF";
        case OP_NOTIF:
            return "NOTIF";
        case OP_VERIF:
            return "VERIF";
        case OP_VERNOTIF:
            return "VERNOTIF";
        case OP_ELSE:
            return "ELSE";
        case OP_ENDIF:
            return "ENDIF";
        case OP_VERIFY:
            return "VERIFY";
        case OP_RETURN:
            return "RETURN";
        case OP_TOALTSTACK:
            return "TOALTSTACK";
        case OP_FROMALTSTACK:
            return "FROMALTSTACK";
        case OP_2DROP:
            return "2DROP";
        case OP_2DUP:
            return "2DUP";
        case OP_3DUP:
            return "3DUP";
        case OP_2OVER:
            return "2OVER";
        case OP_2ROT:
            return "2ROT";
        case OP_2SWAP:
            return "2SWAP";
        case OP_IFDUP:
            return "IFDUP";
        case OP_DEPTH:
            return "DEPTH";
        case OP_DROP:
            return "DROP";
        case OP_DUP:
            return "DUP";
        case OP_NIP:
            return "NIP";
        case OP_OVER:
            return "OVER";
        case OP_PICK:
            return "PICK";
        case OP_ROLL:
            return "ROLL";
        case OP_ROT:
            return "ROT";
        case OP_SWAP:
            return "SWAP";
        case OP_TUCK:
            return "TUCK";
        case OP_CAT:
            return "CAT";
        case OP_SUBSTR:
            return "SUBSTR";
        case OP_LEFT:
            return "LEFT";
        case OP_RIGHT:
            return "RIGHT";
        case OP_SIZE:
            return "SIZE";
        case OP_INVERT:
            return "INVERT";
        case OP_AND:
            return "AND";
        case OP_OR:
            return "OR";
        case OP_XOR:
            return "XOR";
        case OP_EQUAL:
            return "EQUAL";
        case OP_EQUALVERIFY:
            return "EQUALVERIFY";
        case OP_RESERVED1:
            return "RESERVED1";
        case OP_RESERVED2:
            return "RESERVED2";
        case OP_1ADD:
            return "1ADD";
        case OP_1SUB:
            return "1SUB";
        case OP_2MUL:
            return "2MUL";
        case OP_2DIV:
            return "2DIV";
        case OP_NEGATE:
            return "NEGATE";
        case OP_ABS:
            return "ABS";
        case OP_NOT:
            return "NOT";
        case OP_0NOTEQUAL:
            return "0NOTEQUAL";
        case OP_ADD:
            return "ADD";
        case OP_SUB:
            return "SUB";
        case OP_MUL:
            return "MUL";
        case OP_DIV:
            return "DIV";
        case OP_MOD:
            return "MOD";
        case OP_LSHIFT:
            return "LSHIFT";
        case OP_RSHIFT:
            return "RSHIFT";
        case OP_BOOLAND:
            return "BOOLAND";
        case OP_BOOLOR:
            return "BOOLOR";
        case OP_NUMEQUAL:
            return "NUMEQUAL";
        case OP_NUMEQUALVERIFY:
            return "NUMEQUALVERIFY";
        case OP_NUMNOTEQUAL:
            return "NUMNOTEQUAL";
        case OP_LESSTHAN:
            return "LESSTHAN";
        case OP_GREATERTHAN:
            return "GREATERTHAN";
        case OP_LESSTHANOREQUAL:
            return "LESSTHANOREQUAL";
        case OP_GREATERTHANOREQUAL:
            return "GREATERTHANOREQUAL";
        case OP_MIN:
            return "MIN";
        case OP_MAX:
            return "MAX";
        case OP_WITHIN:
            return "WITHIN";
        case OP_RIPEMD160:
            return "RIPEMD160";
        case OP_SHA1:
            return "SHA1";
        case OP_SHA256:
            return "SHA256";
        case OP_HASH160:
            return "HASH160";
        case OP_HASH256:
            return "HASH256";
        case OP_CODESEPARATOR:
            return "CODESEPARATOR";
        case OP_CHECKSIG:
            return "CHECKSIG";
        case OP_CHECKSIGVERIFY:
            return "CHECKSIGVERIFY";
        case OP_CHECKMULTISIG:
            return "CHECKMULTISIG";
        case OP_CHECKMULTISIGVERIFY:
            return "CHECKMULTISIGVERIFY";
        case OP_NOP1:
            return "NOP1";
        case OP_NOP2:
            return "NOP2";
        case OP_NOP3:
            return "NOP3";
        case OP_NOP4:
            return "NOP4";
        case OP_NOP5:
            return "NOP5";
        case OP_NOP6:
            return "NOP6";
        case OP_NOP7:
            return "NOP7";
        case OP_NOP8:
            return "NOP8";
        case OP_NOP9:
            return "NOP9";
        case OP_NOP10:
            return "NOP10";
        default:
            return "NON_OP(" + opcode + ")";
        }
    }


    private byte[] getData(int len) throws ScriptException {
        if (len > program.length - cursor)
            throw new ScriptException("Failed read of " + len + " bytes");
        try {
            byte[] buf = new byte[len];
            System.arraycopy(program, cursor, buf, 0, len);
            cursor += len;
            return buf;
        } catch (ArrayIndexOutOfBoundsException e) {
            // We want running out of data in the array to be treated as a handleable script parsing exception,
            // not something that abnormally terminates the app.
            throw new ScriptException("Failed read of " + len + " bytes", e);
        } catch (NegativeArraySizeException e) {
            // We want running out of data in the array to be treated as a handleable script parsing exception,
            // not something that abnormally terminates the app.
            throw new ScriptException("Failed read of " + len + " bytes", e);
        }
    }

    private int readByte() throws ScriptException {
        try {
            return 0xFF & program[cursor++];
        } catch (ArrayIndexOutOfBoundsException e) {
            throw new ScriptException("Attempted to read outside of script boundaries");
        }
    }

    /**
     * To run a script, first we parse it which breaks it up into chunks representing pushes of
     * data or logical opcodes. Then we can run the parsed chunks.
     * <p/>
     * The reason for this split, instead of just interpreting directly, is to make it easier
     * to reach into a programs structure and pull out bits of data without having to run it.
     * This is necessary to render the to/from addresses of transactions in a user interface.
     * The official client does something similar.
     */
    private void parse(byte[] programBytes, int offset, int length) throws ScriptException {
        // TODO: this is inefficient
        program = new byte[length];
        System.arraycopy(programBytes, offset, program, 0, length);

        offset = 0;
        chunks = new ArrayList<ScriptChunk>(10);  // Arbitrary choice of initial size.
        cursor = offset;
        while (cursor < offset + length) {
            int startLocationInProgram = cursor - offset;
            int opcode = readByte();
            if (opcode >= 0 && opcode < OP_PUSHDATA1) {
                // Read some bytes of data, where how many is the opcode value itself.
                chunks.add(new ScriptChunk(false, getData(opcode), startLocationInProgram));  // opcode == len here.
            } else if (opcode == OP_PUSHDATA1) {
                int len = readByte();
                chunks.add(new ScriptChunk(false, getData(len), startLocationInProgram));
            } else if (opcode == OP_PUSHDATA2) {
                // Read a short, then read that many bytes of data.
                int len = readByte() | (readByte() << 8);
                chunks.add(new ScriptChunk(false, getData(len), startLocationInProgram));
            } else if (opcode == OP_PUSHDATA4) {
                // Read a uint32, then read that many bytes of data.
                // Though this is allowed, because its value cannot be > 520, it should never actually be used
                long len = readByte() | (readByte() << 8) | (readByte() << 16) | (readByte() << 24);
                chunks.add(new ScriptChunk(false, getData((int)len), startLocationInProgram));
            } else {
                chunks.add(new ScriptChunk(true, new byte[]{(byte) opcode}, startLocationInProgram));
            }
        }
    }

    /**
     * Returns true if this script is of the form <sig> OP_CHECKSIG. This form was originally intended for transactions
     * where the peers talked to each other directly via TCP/IP, but has fallen out of favor with time due to that mode
     * of operation being susceptible to man-in-the-middle attacks. It is still used in coinbase outputs and can be
     * useful more exotic types of transaction, but today most payments are to addresses.
     */
    public boolean isSentToRawPubKey() {
        if (chunks.size() != 2)
            return false;
        return chunks.get(1).equalsOpCode(OP_CHECKSIG) &&
                !chunks.get(0).isOpCode && chunks.get(0).data.length > 1;
    }

    /**
     * Returns true if this script is of the form DUP HASH160 <pubkey hash> EQUALVERIFY CHECKSIG, ie, payment to an
     * address like 1VayNert3x1KzbpzMGt2qdqrAThiRovi8. This form was originally intended for the case where you wish
     * to send somebody money with a written code because their node is offline, but over time has become the standard
     * way to make payments due to the short and recognizable base58 form addresses come in.
     */
    public boolean isSentToAddress() {
        if (chunks.size() != 5) return false;
        return chunks.get(0).equalsOpCode(OP_DUP) &&
               chunks.get(1).equalsOpCode(OP_HASH160) &&
               chunks.get(2).data.length == Address.LENGTH &&
               chunks.get(3).equalsOpCode(OP_EQUALVERIFY) &&
               chunks.get(4).equalsOpCode(OP_CHECKSIG);
    }

    /**
     * If a program matches the standard template DUP HASH160 <pubkey hash> EQUALVERIFY CHECKSIG
     * then this function retrieves the third element, otherwise it throws a ScriptException.<p>
     *
     * This is useful for fetching the destination address of a transaction.
     */
    public byte[] getPubKeyHash() throws ScriptException {
        if (!isSentToAddress())
            throw new ScriptException("Script not in the standard scriptPubKey form");
        // Otherwise, the third element is the hash of the public key, ie the bitcoin address.
        return chunks.get(2).data;
    }

    /**
     * Returns the public key in this script. If a script contains two constants and nothing else, it is assumed to
     * be a scriptSig (input) for a pay-to-address output and the second constant is returned (the first is the
     * signature). If a script contains a constant and an OP_CHECKSIG opcode, the constant is returned as it is
     * assumed to be a direct pay-to-key scriptPubKey (output) and the first constant is the public key.
     *
     * @throws ScriptException if the script is none of the named forms.
     */
    public byte[] getPubKey() throws ScriptException {
        if (chunks.size() != 2) {
            throw new ScriptException("Script not of right size, expecting 2 but got " + chunks.size());
        }
        if (chunks.get(0).data.length > 2 && chunks.get(1).data.length > 2) {
            // If we have two large constants assume the input to a pay-to-address output.
            return chunks.get(1).data;
        } else if (chunks.get(1).data.length == 1 && chunks.get(1).equalsOpCode(OP_CHECKSIG) && chunks.get(0).data.length > 2) {
            // A large constant followed by an OP_CHECKSIG is the key.
            return chunks.get(0).data;
        } else {
            throw new ScriptException("Script did not match expected form: " + toString());
        }
    }

    /**
     * Convenience wrapper around getPubKey. Only works for scriptSigs.
     */
    public Address getFromAddress() throws ScriptException {
        return new Address(params, Utils.sha256hash160(getPubKey()));
    }

    /**
     * Gets the destination address from this script, if it's in the required form (see getPubKey).
     *
     * @throws ScriptException
     */
    public Address getToAddress() throws ScriptException {
        return new Address(params, getPubKeyHash());
    }

    ////////////////////// Interface for writing scripts from scratch ////////////////////////////////

    /**
     * Writes out the given byte buffer to the output stream with the correct opcode prefix
     * To write an integer call writeBytes(out, Utils.reverseBytes(Utils.encodeMPI(val, false)));
     */
    static void writeBytes(OutputStream os, byte[] buf) throws IOException {
        if (buf.length < OP_PUSHDATA1) {
            os.write(buf.length);
            os.write(buf);
        } else if (buf.length < 256) {
            os.write(OP_PUSHDATA1);
            os.write(buf.length);
            os.write(buf);
        } else if (buf.length < 65536) {
            os.write(OP_PUSHDATA2);
            os.write(0xFF & (buf.length));
            os.write(0xFF & (buf.length >> 8));
            os.write(buf);
        } else {
            throw new RuntimeException("Unimplemented");
        }
    }

    public static byte[] createOutputScript(Address to) {
        try {
            // TODO: Do this by creating a Script *first* then having the script reassemble itself into bytes.
            ByteArrayOutputStream bits = new UnsafeByteArrayOutputStream(24);
            bits.write(OP_DUP);
            bits.write(OP_HASH160);
            writeBytes(bits, to.getHash160());
            bits.write(OP_EQUALVERIFY);
            bits.write(OP_CHECKSIG);
            return bits.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException(e);  // Cannot happen.
        }
    }

    /**
     * Create a script that sends coins directly to the given public key (eg in a coinbase transaction).
     */
    public static byte[] createOutputScript(byte[] pubkey) {
        try {
            // TODO: Do this by creating a Script *first* then having the script reassemble itself into bytes.
            ByteArrayOutputStream bits = new UnsafeByteArrayOutputStream(pubkey.length + 1);
            writeBytes(bits, pubkey);
            bits.write(OP_CHECKSIG);
            return bits.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException(e);  // Cannot happen.
        }
    }

    /**
     * Creates a script that sends coins directly to the given public key. Same as
     * {@link Script#createOutputScript(byte[])} but more type safe.
     */
    public static byte[] createOutputScript(ECKey pubkey) {
        return createOutputScript(pubkey.getPubKey());
    }

    public static byte[] createInputScript(byte[] signature, byte[] pubkey) {
        try {
            // TODO: Do this by creating a Script *first* then having the script reassemble itself into bytes.
            ByteArrayOutputStream bits = new UnsafeByteArrayOutputStream(signature.length + pubkey.length + 2);
            writeBytes(bits, signature);
            writeBytes(bits, pubkey);
            return bits.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static byte[] createInputScript(byte[] signature) {
        try {
            // TODO: Do this by creating a Script *first* then having the script reassemble itself into bytes.
            ByteArrayOutputStream bits = new UnsafeByteArrayOutputStream(signature.length + 2);
            writeBytes(bits, signature);
            return bits.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
    
    ////////////////////// Interface used during verification of transactions/blocks ////////////////////////////////
    
    private static int getSigOpCount(List<ScriptChunk> chunks, boolean accurate) throws ScriptException {
        int sigOps = 0;
        int lastOpCode = OP_INVALIDOPCODE;
        for (ScriptChunk chunk : chunks) {
            if (chunk.isOpCode) {
                int opcode = 0xFF & chunk.data[0];
                switch (opcode) {
                case OP_CHECKSIG:
                case OP_CHECKSIGVERIFY:
                    sigOps++;
                    break;
                case OP_CHECKMULTISIG:
                case OP_CHECKMULTISIGVERIFY:
                    if (accurate && lastOpCode >= OP_1 && lastOpCode <= OP_16)
                        sigOps += getOpNValue(lastOpCode);
                    else
                        sigOps += 20;
                    break;
                default:
                    break;
                }
                lastOpCode = opcode;
            }
        }
        return sigOps;
    }
    
    /**
     * Convince method to get the int value of OP_N
     */
    private static int getOpNValue(int opcode) throws ScriptException {
        if (opcode == OP_0)
            return 0;
        if (opcode < OP_1 || opcode > OP_16) // This should absolutely never happen
            throw new ScriptException("getOpNValue called on non OP_N opcode");
        return opcode + 1 - OP_1;
    }

    /**
     * Gets the count of regular SigOps in the script program (counting multisig ops as 20)
     */
    public static int getSigOpCount(byte[] program) throws ScriptException {
        Script script = new Script();
        try {
            script.parse(program, 0, program.length);
        } catch (ScriptException e) {
            // Ignore errors and count up to the parse-able length
        }
        return getSigOpCount(script.chunks, false);
    }
    
    /**
     * Gets the count of P2SH Sig Ops in the Script scriptSig
     */
    public static long getP2SHSigOpCount(byte[] scriptSig) throws ScriptException {
        Script script = new Script();
        try {
            script.parse(scriptSig, 0, scriptSig.length);
        } catch (ScriptException e) {
            // Ignore errors and count up to the parse-able length
        }
        for (int i = script.chunks.size() - 1; i >= 0; i--)
            if (!script.chunks.get(i).isOpCode) {
                Script subScript =  new Script();
                subScript.parse(script.chunks.get(i).data, 0, script.chunks.get(i).data.length);
                return getSigOpCount(subScript.chunks, true);
            }
        return 0;
    }

    /**
     * <p>Whether or not this is a scriptPubKey representing a pay-to-script-hash output. In such outputs, the logic that
     * controls reclamation is not actually in the output at all. Instead there's just a hash, and it's up to the
     * spending input to provide a program matching that hash. This rule is "soft enforced" by the network as it does
     * not exist in Satoshis original implementation. It means blocks containing P2SH transactions that don't match
     * correctly are considered valid, but won't be mined upon, so they'll be rapidly re-orgd out of the chain. This
     * logic is defined by <a href="https://en.bitcoin.it/wiki/BIP_0016">BIP 16</a>.</p>
     *
     * <p>bitcoinj does not support creation of P2SH transactions today. The goal of P2SH is to allow short addresses
     * even for complex scripts (eg, multi-sig outputs) so they are convenient to work with in things like QRcodes or
     * with copy/paste, and also to minimize the size of the unspent output set (which improves performance of the
     * Bitcoin system).</p>
     */
    public boolean isPayToScriptHash() {
        return program.length == 23 &&
               (program[0] & 0xff) == OP_HASH160 &&
               (program[1] & 0xff) == 0x14 &&
               (program[22] & 0xff) == OP_EQUAL;
    }
    
    private static boolean equalsRange(byte[] a, int start, byte[] b) {
        if (start + b.length > a.length)
            return false;
        for (int i = 0; i < b.length; i++)
            if (a[i + start] != b[i])
                return false;
        return true;
    }
    
    /**
     * Returns the script bytes of inputScript with all instances of the specified script object removed
     */
    public static byte[] removeAllInstancesOf(byte[] inputScript, byte[] chunkToRemove) {
        // We usually don't end up removing anything
        UnsafeByteArrayOutputStream bos = new UnsafeByteArrayOutputStream(inputScript.length);

        int cursor = 0;
        while (cursor < inputScript.length) {
            boolean skip = equalsRange(inputScript, cursor, chunkToRemove);
            
            int opcode = inputScript[cursor++] & 0xFF;
            int additionalBytes = 0;
            if (opcode >= 0 && opcode < OP_PUSHDATA1) {
                additionalBytes = opcode;
            } else if (opcode == OP_PUSHDATA1) {
                additionalBytes = inputScript[cursor] + 1;
            } else if (opcode == OP_PUSHDATA2) {
                additionalBytes = ((0xFF & inputScript[cursor]) |
                                  ((0xFF & inputScript[cursor+1]) << 8)) + 2;
            } else if (opcode == OP_PUSHDATA4) {
                additionalBytes = ((0xFF & inputScript[cursor]) |
                                  ((0xFF & inputScript[cursor+1]) << 8) |
                                  ((0xFF & inputScript[cursor+1]) << 16) |
                                  ((0xFF & inputScript[cursor+1]) << 24)) + 4;
            }
            if (!skip) {
                try {
                    bos.write(opcode);
                    bos.write(copyOfRange(inputScript, cursor, cursor + additionalBytes));
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            }
            cursor += additionalBytes;
        }
        return bos.toByteArray();
    }

    private static byte[] copyOfRange(byte[] original, int start, int end) {
        if (start > end) {
            throw new IllegalArgumentException();
        }
        int originalLength = original.length;
        if (start < 0 || start > originalLength) {
            throw new ArrayIndexOutOfBoundsException();
        }
        int resultLength = end - start;
        int copyLength = Math.min(resultLength, originalLength - start);
        byte[] result = new byte[resultLength];
        System.arraycopy(original, start, result, 0, copyLength);
        return result;
    }

    /**
     * Returns the script bytes of inputScript with all instances of the given op code removed
     */
    public static byte[] removeAllInstancesOfOp(byte[] inputScript, int opCode) {
        return removeAllInstancesOf(inputScript, new byte[] {(byte)opCode});
    }
    
    ////////////////////// Script verification and helpers ////////////////////////////////
    
    private static boolean castToBool(byte[] data) {
        for (int i = 0; i < data.length; i++)
        {
            if (data[i] != 0)
            {
                // "Can be negative zero" -reference client (see OpenSSL's BN_bn2mpi)
                if (i == data.length - 1 && (data[i] & 0xFF) == 0x80)
                    return false;
                return true;
            }
        }
        return false;
    }
    
    private static BigInteger castToBigInteger(byte[] chunk) throws ScriptException {
        if (chunk.length > 4)
            throw new ScriptException("Script attempted to use an integer larger than 4 bytes");
        return Utils.decodeMPI(Utils.reverseBytes(chunk), false);
    }
    
    private static void executeScript(Transaction txContainingThis, long index,
                                      Script script, LinkedList<byte[]> stack) throws ScriptException {
        int opCount = 0;
        int lastCodeSepLocation = 0;
        
        LinkedList<byte[]> altstack = new LinkedList<byte[]>();
        LinkedList<Boolean> ifStack = new LinkedList<Boolean>();
        
        for (ScriptChunk chunk : script.chunks) {
            boolean shouldExecute = !ifStack.contains(false);
            
            if (!chunk.isOpCode) {
                if (chunk.data.length > 520)
                    throw new ScriptException("Attempted to push a data string larger than 520 bytes");
                
                if (!shouldExecute)
                    continue;
                
                stack.add(chunk.data);
            } else {
                int opcode = 0xFF & chunk.data[0];
                if (opcode > OP_16) {
                    opCount++;
                    if (opCount > 201)
                        throw new ScriptException("More script operations than is allowed");
                }
                
                if (opcode == OP_VERIF || opcode == OP_VERNOTIF)
                    throw new ScriptException("Script included OP_VERIF or OP_VERNOTIF");
                
                if (opcode == OP_CAT || opcode == OP_SUBSTR || opcode == OP_LEFT || opcode == OP_RIGHT ||
                    opcode == OP_INVERT || opcode == OP_AND || opcode == OP_OR || opcode == OP_XOR ||
                    opcode == OP_2MUL || opcode == OP_2DIV || opcode == OP_MUL || opcode == OP_DIV ||
                    opcode == OP_MOD || opcode == OP_LSHIFT || opcode == OP_RSHIFT)
                    throw new ScriptException("Script included a disabled Script Op.");
                
                switch (opcode) {
                case OP_IF:
                    if (!shouldExecute) {
                        ifStack.add(false);
                        continue;
                    }
                    if (stack.size() < 1)
                        throw new ScriptException("Attempted OP_IF on an empty stack");
                    ifStack.add(castToBool(stack.pollLast()));
                    continue;
                case OP_NOTIF:
                    if (!shouldExecute) {
                        ifStack.add(false);
                        continue;
                    }
                    if (stack.size() < 1)
                        throw new ScriptException("Attempted OP_NOTIF on an empty stack");
                    ifStack.add(!castToBool(stack.pollLast()));
                    continue;
                case OP_ELSE:
                    if (ifStack.isEmpty())
                        throw new ScriptException("Attempted OP_ELSE without OP_IF/NOTIF");
                    ifStack.add(!ifStack.pollLast());
                    continue;
                case OP_ENDIF:
                    if (ifStack.isEmpty())
                        throw new ScriptException("Attempted OP_ENDIF without OP_IF/NOTIF");
                    ifStack.pollLast();
                    continue;
                }
                
                if (!shouldExecute)
                    continue;
                
                switch(opcode) {
                //case OP_0: dont know why this isnt also here in the reference client
                case OP_1NEGATE:
                    stack.add(Utils.reverseBytes(Utils.encodeMPI(BigInteger.ONE.negate(), false)));
                    break;
                case OP_1:
                case OP_2:
                case OP_3:
                case OP_4:
                case OP_5:
                case OP_6:
                case OP_7:
                case OP_8:
                case OP_9:
                case OP_10:
                case OP_11:
                case OP_12:
                case OP_13:
                case OP_14:
                case OP_15:
                case OP_16:
                    stack.add(Utils.reverseBytes(Utils.encodeMPI(BigInteger.valueOf(getOpNValue(opcode)), false)));
                    break;
                case OP_NOP:
                    break;
                case OP_VERIFY:
                    if (stack.size() < 1)
                        throw new ScriptException("Attempted OP_VERIFY on an empty stack");
                    if (!castToBool(stack.pollLast()))
                        throw new ScriptException("OP_VERIFY failed");
                    break;
                case OP_RETURN:
                    throw new ScriptException("Script called OP_RETURN");
                case OP_TOALTSTACK:
                    if (stack.size() < 1)
                        throw new ScriptException("Attempted OP_TOALTSTACK on an empty stack");
                    altstack.add(stack.pollLast());
                    break;
                case OP_FROMALTSTACK:
                    if (altstack.size() < 1)
                        throw new ScriptException("Attempted OP_TOALTSTACK on an empty altstack");
                    stack.add(altstack.pollLast());
                    break;
                case OP_2DROP:
                    if (stack.size() < 2)
                        throw new ScriptException("Attempted OP_2DROP on a stack with size < 2");
                    stack.pollLast();
                    stack.pollLast();
                    break;
                case OP_2DUP:
                    if (stack.size() < 2)
                        throw new ScriptException("Attempted OP_2DUP on a stack with size < 2");
                    Iterator<byte[]> it2DUP = stack.descendingIterator();
                    byte[] OP2DUPtmpChunk2 = it2DUP.next();
                    stack.add(it2DUP.next());
                    stack.add(OP2DUPtmpChunk2);
                    break;
                case OP_3DUP:
                    if (stack.size() < 3)
                        throw new ScriptException("Attempted OP_3DUP on a stack with size < 3");
                    Iterator<byte[]> it3DUP = stack.descendingIterator();
                    byte[] OP3DUPtmpChunk3 = it3DUP.next();
                    byte[] OP3DUPtmpChunk2 = it3DUP.next();
                    stack.add(it3DUP.next());
                    stack.add(OP3DUPtmpChunk2);
                    stack.add(OP3DUPtmpChunk3);
                    break;
                case OP_2OVER:
                    if (stack.size() < 4)
                        throw new ScriptException("Attempted OP_2OVER on a stack with size < 4");
                    Iterator<byte[]> it2OVER = stack.descendingIterator();
                    it2OVER.next();
                    it2OVER.next();
                    byte[] OP2OVERtmpChunk2 = it2OVER.next();
                    stack.add(it2OVER.next());
                    stack.add(OP2OVERtmpChunk2);
                    break;
                case OP_2ROT:
                    if (stack.size() < 6)
                        throw new ScriptException("Attempted OP_2ROT on a stack with size < 6");
                    byte[] OP2ROTtmpChunk6 = stack.pollLast();
                    byte[] OP2ROTtmpChunk5 = stack.pollLast();
                    byte[] OP2ROTtmpChunk4 = stack.pollLast();
                    byte[] OP2ROTtmpChunk3 = stack.pollLast();
                    byte[] OP2ROTtmpChunk2 = stack.pollLast();
                    byte[] OP2ROTtmpChunk1 = stack.pollLast();
                    stack.add(OP2ROTtmpChunk3);
                    stack.add(OP2ROTtmpChunk4);
                    stack.add(OP2ROTtmpChunk5);
                    stack.add(OP2ROTtmpChunk6);
                    stack.add(OP2ROTtmpChunk1);
                    stack.add(OP2ROTtmpChunk2);
                    break;
                case OP_2SWAP:
                    if (stack.size() < 4)
                        throw new ScriptException("Attempted OP_2SWAP on a stack with size < 4");
                    byte[] OP2SWAPtmpChunk4 = stack.pollLast();
                    byte[] OP2SWAPtmpChunk3 = stack.pollLast();
                    byte[] OP2SWAPtmpChunk2 = stack.pollLast();
                    byte[] OP2SWAPtmpChunk1 = stack.pollLast();
                    stack.add(OP2SWAPtmpChunk3);
                    stack.add(OP2SWAPtmpChunk4);
                    stack.add(OP2SWAPtmpChunk1);
                    stack.add(OP2SWAPtmpChunk2);
                    break;
                case OP_IFDUP:
                    if (stack.size() < 1)
                        throw new ScriptException("Attempted OP_IFDUP on an empty stack");
                    if (castToBool(stack.getLast()))
                        stack.add(stack.getLast());
                    break;
                case OP_DEPTH:
                    stack.add(Utils.reverseBytes(Utils.encodeMPI(BigInteger.valueOf(stack.size()), false)));
                    break;
                case OP_DROP:
                    if (stack.size() < 1)
                        throw new ScriptException("Attempted OP_DROP on an empty stack");
                    stack.pollLast();
                    break;
                case OP_DUP:
                    if (stack.size() < 1)
                        throw new ScriptException("Attempted OP_DUP on an empty stack");
                    stack.add(stack.getLast());
                    break;
                case OP_NIP:
                    if (stack.size() < 2)
                        throw new ScriptException("Attempted OP_NIP on a stack with size < 2");
                    byte[] OPNIPtmpChunk = stack.pollLast();
                    stack.pollLast();
                    stack.add(OPNIPtmpChunk);
                    break;
                case OP_OVER:
                    if (stack.size() < 2)
                        throw new ScriptException("Attempted OP_OVER on a stack with size < 2");
                    Iterator<byte[]> itOVER = stack.descendingIterator();
                    itOVER.next();
                    stack.add(itOVER.next());
                    break;
                case OP_PICK:
                case OP_ROLL:
                    if (stack.size() < 1)
                        throw new ScriptException("Attempted OP_PICK/OP_ROLL on an empty stack");
                    long val = castToBigInteger(stack.pollLast()).longValue();
                    if (val < 0 || val >= stack.size())
                        throw new ScriptException("OP_PICK/OP_ROLL attempted to get data deeper than stack size");
                    Iterator<byte[]> itPICK = stack.descendingIterator();
                    for (long i = 0; i < val; i++)
                        itPICK.next();
                    byte[] OPROLLtmpChunk = itPICK.next();
                    if (opcode == OP_ROLL)
                        itPICK.remove();
                    stack.add(OPROLLtmpChunk);
                    break;
                case OP_ROT:
                    if (stack.size() < 3)
                        throw new ScriptException("Attempted OP_ROT on a stack with size < 3");
                    byte[] OPROTtmpChunk3 = stack.pollLast();
                    byte[] OPROTtmpChunk2 = stack.pollLast();
                    byte[] OPROTtmpChunk1 = stack.pollLast();
                    stack.add(OPROTtmpChunk2);
                    stack.add(OPROTtmpChunk3);
                    stack.add(OPROTtmpChunk1);
                    break;
                case OP_SWAP:
                case OP_TUCK:
                    if (stack.size() < 2)
                        throw new ScriptException("Attempted OP_SWAP on a stack with size < 2");
                    byte[] OPSWAPtmpChunk2 = stack.pollLast();
                    byte[] OPSWAPtmpChunk1 = stack.pollLast();
                    stack.add(OPSWAPtmpChunk2);
                    stack.add(OPSWAPtmpChunk1);
                    if (opcode == OP_TUCK)
                        stack.add(OPSWAPtmpChunk2);
                    break;
                case OP_CAT:
                case OP_SUBSTR:
                case OP_LEFT:
                case OP_RIGHT:
                    throw new ScriptException("Attempted to use disabled Script Op.");
                case OP_SIZE:
                    if (stack.size() < 1)
                        throw new ScriptException("Attempted OP_SIZE on an empty stack");
                    stack.add(Utils.reverseBytes(Utils.encodeMPI(BigInteger.valueOf(stack.getLast().length), false)));
                    break;
                case OP_INVERT:
                case OP_AND:
                case OP_OR:
                case OP_XOR:
                    throw new ScriptException("Attempted to use disabled Script Op.");
                case OP_EQUAL:
                    if (stack.size() < 2)
                        throw new ScriptException("Attempted OP_EQUALVERIFY on a stack with size < 2");
                    stack.add(Arrays.equals(stack.pollLast(), stack.pollLast()) ? new byte[] {1} : new byte[] {0});
                    break;
                case OP_EQUALVERIFY:
                    if (stack.size() < 2)
                        throw new ScriptException("Attempted OP_EQUALVERIFY on a stack with size < 2");
                    if (!Arrays.equals(stack.pollLast(), stack.pollLast()))
                        throw new ScriptException("OP_EQUALVERIFY: non-equal data");
                    break;
                case OP_1ADD:
                case OP_1SUB:
                case OP_NEGATE:
                case OP_ABS:
                case OP_NOT:
                case OP_0NOTEQUAL:
                    if (stack.size() < 1)
                        throw new ScriptException("Attempted a numeric op on an empty stack");
                    BigInteger numericOPnum = castToBigInteger(stack.pollLast());
                                        
                    switch (opcode) {
                    case OP_1ADD:
                        numericOPnum = numericOPnum.add(BigInteger.ONE);
                        break;
                    case OP_1SUB:
                        numericOPnum = numericOPnum.subtract(BigInteger.ONE);
                        break;
                    case OP_NEGATE:
                        numericOPnum = numericOPnum.negate();
                        break;
                    case OP_ABS:
                        if (numericOPnum.compareTo(BigInteger.ZERO) < 0)
                            numericOPnum = numericOPnum.negate();
                        break;
                    case OP_NOT:
                        if (numericOPnum.equals(BigInteger.ZERO))
                            numericOPnum = BigInteger.ONE;
                        else
                            numericOPnum = BigInteger.ZERO;
                        break;
                    case OP_0NOTEQUAL:
                        if (numericOPnum.equals(BigInteger.ZERO))
                            numericOPnum = BigInteger.ZERO;
                        else
                            numericOPnum = BigInteger.ONE;
                        break;
                    default:
                        throw new AssertionError("Unreachable");
                    }
                    
                    stack.add(Utils.reverseBytes(Utils.encodeMPI(numericOPnum, false)));
                    break;
                case OP_2MUL:
                case OP_2DIV:
                    throw new ScriptException("Attempted to use disabled Script Op.");
                case OP_ADD:
                case OP_SUB:
                case OP_BOOLAND:
                case OP_BOOLOR:
                case OP_NUMEQUAL:
                case OP_NUMNOTEQUAL:
                case OP_LESSTHAN:
                case OP_GREATERTHAN:
                case OP_LESSTHANOREQUAL:
                case OP_GREATERTHANOREQUAL:
                case OP_MIN:
                case OP_MAX:
                    if (stack.size() < 2)
                        throw new ScriptException("Attempted a numeric op on a stack with size < 2");
                    BigInteger numericOPnum2 = castToBigInteger(stack.pollLast());
                    BigInteger numericOPnum1 = castToBigInteger(stack.pollLast());

                    BigInteger numericOPresult;
                    switch (opcode) {
                    case OP_ADD:
                        numericOPresult = numericOPnum1.add(numericOPnum2);
                        break;
                    case OP_SUB:
                        numericOPresult = numericOPnum1.subtract(numericOPnum2);
                        break;
                    case OP_BOOLAND:
                        if (!numericOPnum1.equals(BigInteger.ZERO) && !numericOPnum2.equals(BigInteger.ZERO))
                            numericOPresult = BigInteger.ONE;
                        else
                            numericOPresult = BigInteger.ZERO;
                        break;
                    case OP_BOOLOR:
                        if (!numericOPnum1.equals(BigInteger.ZERO) || !numericOPnum2.equals(BigInteger.ZERO))
                            numericOPresult = BigInteger.ONE;
                        else
                            numericOPresult = BigInteger.ZERO;
                        break;
                    case OP_NUMEQUAL:
                        if (numericOPnum1.equals(numericOPnum2))
                            numericOPresult = BigInteger.ONE;
                        else
                            numericOPresult = BigInteger.ZERO;
                        break;
                    case OP_NUMNOTEQUAL:
                        if (!numericOPnum1.equals(numericOPnum2))
                            numericOPresult = BigInteger.ONE;
                        else
                            numericOPresult = BigInteger.ZERO;
                        break;
                    case OP_LESSTHAN:
                        if (numericOPnum1.compareTo(numericOPnum2) < 0)
                            numericOPresult = BigInteger.ONE;
                        else
                            numericOPresult = BigInteger.ZERO;
                        break;
                    case OP_GREATERTHAN:
                        if (numericOPnum1.compareTo(numericOPnum2) > 0)
                            numericOPresult = BigInteger.ONE;
                        else
                            numericOPresult = BigInteger.ZERO;
                        break;
                    case OP_LESSTHANOREQUAL:
                        if (numericOPnum1.compareTo(numericOPnum2) <= 0)
                            numericOPresult = BigInteger.ONE;
                        else
                            numericOPresult = BigInteger.ZERO;
                        break;
                    case OP_GREATERTHANOREQUAL:
                        if (numericOPnum1.compareTo(numericOPnum2) >= 0)
                            numericOPresult = BigInteger.ONE;
                        else
                            numericOPresult = BigInteger.ZERO;
                        break;
                    case OP_MIN:
                        if (numericOPnum1.compareTo(numericOPnum2) < 0)
                            numericOPresult = numericOPnum1;
                        else
                            numericOPresult = numericOPnum2;
                        break;
                    case OP_MAX:
                        if (numericOPnum1.compareTo(numericOPnum2) > 0)
                            numericOPresult = numericOPnum1;
                        else
                            numericOPresult = numericOPnum2;
                        break;
                    default:
                        throw new RuntimeException("Opcode switched at runtime?");
                    }
                    
                    stack.add(Utils.reverseBytes(Utils.encodeMPI(numericOPresult, false)));
                    break;
                case OP_MUL:
                case OP_DIV:
                case OP_MOD:
                case OP_LSHIFT:
                case OP_RSHIFT:
                    throw new ScriptException("Attempted to use disabled Script Op.");
                case OP_NUMEQUALVERIFY:
                    if (stack.size() < 2)
                        throw new ScriptException("Attempted OP_NUMEQUALVERIFY on a stack with size < 2");
                    BigInteger OPNUMEQUALVERIFYnum2 = castToBigInteger(stack.pollLast());
                    BigInteger OPNUMEQUALVERIFYnum1 = castToBigInteger(stack.pollLast());
                    
                    if (!OPNUMEQUALVERIFYnum1.equals(OPNUMEQUALVERIFYnum2))
                        throw new ScriptException("OP_NUMEQUALVERIFY failed");
                    break;
                case OP_WITHIN:
                    if (stack.size() < 3)
                        throw new ScriptException("Attempted OP_WITHIN on a stack with size < 3");
                    BigInteger OPWITHINnum3 = castToBigInteger(stack.pollLast());
                    BigInteger OPWITHINnum2 = castToBigInteger(stack.pollLast());
                    BigInteger OPWITHINnum1 = castToBigInteger(stack.pollLast());
                    if (OPWITHINnum2.compareTo(OPWITHINnum1) <= 0 && OPWITHINnum1.compareTo(OPWITHINnum3) < 0)
                        stack.add(Utils.reverseBytes(Utils.encodeMPI(BigInteger.ONE, false)));
                    else
                        stack.add(Utils.reverseBytes(Utils.encodeMPI(BigInteger.ZERO, false)));
                    break;
                case OP_RIPEMD160:
                    if (stack.size() < 1)
                        throw new ScriptException("Attempted OP_RIPEMD160 on an empty stack");
                    RIPEMD160Digest digest = new RIPEMD160Digest();
                    byte[] dataToHash = stack.pollLast();
                    digest.update(dataToHash, 0, dataToHash.length);
                    byte[] ripmemdHash = new byte[20];
                    digest.doFinal(ripmemdHash, 0);
                    stack.add(ripmemdHash);
                    break;
                case OP_SHA1:
                    if (stack.size() < 1)
                        throw new ScriptException("Attempted OP_SHA1 on an empty stack");
                    try {
                        stack.add(MessageDigest.getInstance("SHA-1").digest(stack.pollLast()));
                    } catch (NoSuchAlgorithmException e) {
                        throw new RuntimeException(e);  // Cannot happen.
                    }
                    break;
                case OP_SHA256:
                    if (stack.size() < 1)
                        throw new ScriptException("Attempted OP_SHA256 on an empty stack");
                    try {
                        stack.add(MessageDigest.getInstance("SHA-256").digest(stack.pollLast()));
                    } catch (NoSuchAlgorithmException e) {
                        throw new RuntimeException(e);  // Cannot happen.
                    }
                    break;
                case OP_HASH160:
                    if (stack.size() < 1)
                        throw new ScriptException("Attempted OP_HASH160 on an empty stack");
                    stack.add(Utils.sha256hash160(stack.pollLast()));
                    break;
                case OP_HASH256:
                    if (stack.size() < 1)
                        throw new ScriptException("Attempted OP_SHA256 on an empty stack");
                    stack.add(Utils.doubleDigest(stack.pollLast()));
                    break;
                case OP_CODESEPARATOR:
                    lastCodeSepLocation = chunk.startLocationInProgram + 1;
                    break;
                case OP_CHECKSIG:
                case OP_CHECKSIGVERIFY:
                    if (stack.size() < 2)
                        throw new ScriptException("Attempted OP_CHECKSIG(VERIFY) on a stack with size < 2");
                    byte[] CHECKSIGpubKey = stack.pollLast();
                    byte[] CHECKSIGsig = stack.pollLast();
                    
                    byte[] CHECKSIGconnectedScript = Arrays.copyOfRange(script.program, lastCodeSepLocation, script.program.length);
                    
                    UnsafeByteArrayOutputStream OPCHECKSIGOutStream = new UnsafeByteArrayOutputStream(CHECKSIGsig.length + 1);
                    try {
                        writeBytes(OPCHECKSIGOutStream, CHECKSIGsig);
                    } catch (IOException e) {
                        throw new RuntimeException(e); // Cannot happen
                    }
                    CHECKSIGconnectedScript = removeAllInstancesOf(CHECKSIGconnectedScript, OPCHECKSIGOutStream.toByteArray());
                    
                    // TODO: Use int for indexes everywhere, we can't have that many inputs/outputs
                    Sha256Hash CHECKSIGhash = txContainingThis.hashTransactionForSignature((int)index, CHECKSIGconnectedScript,
                            CHECKSIGsig[CHECKSIGsig.length - 1]);
                                        
                    boolean CHECKSIGsigValid;
                    try {
                        CHECKSIGsigValid = ECKey.verify(CHECKSIGhash.getBytes(), Arrays.copyOf(CHECKSIGsig, CHECKSIGsig.length - 1), CHECKSIGpubKey);
                    } catch (Exception e1) {
                        // There is (at least) one exception that could be hit here (EOFException, if the sig is too short)
                        // Because I can't verify there aren't more, we use a very generic Exception catch
                        CHECKSIGsigValid = false;
                    }
                    
                    if (opcode == OP_CHECKSIG)
                        stack.add(CHECKSIGsigValid ? new byte[] {1} : new byte[] {0});
                    else if (opcode == OP_CHECKSIGVERIFY)
                        if (!CHECKSIGsigValid)
                            throw new ScriptException("Script failed OP_CHECKSIGVERIFY");
                    break;
                case OP_CHECKMULTISIG:
                case OP_CHECKMULTISIGVERIFY:
                    if (stack.size() < 2)
                        throw new ScriptException("Attempted OP_CHECKMULTISIG(VERIFY) on a stack with size < 2");
                    int CHECKMULTISIGpubKeyCount = castToBigInteger(stack.pollLast()).intValue();
                    if (CHECKMULTISIGpubKeyCount < 0 || CHECKMULTISIGpubKeyCount > 20)
                        throw new ScriptException("OP_CHECKMULTISIG(VERIFY) with pubkey count out of range");
                    opCount += CHECKMULTISIGpubKeyCount;
                    if (opCount > 201)
                        throw new ScriptException("Total op count > 201 during OP_CHECKMULTISIG(VERIFY)");
                    if (stack.size() < CHECKMULTISIGpubKeyCount + 1)
                        throw new ScriptException("Attempted OP_CHECKMULTISIG(VERIFY) on a stack with size < num_of_pubkeys + 2");
                    
                    LinkedList<byte[]> CHECKMULTISIGpubkeys = new LinkedList<byte[]>();
                    for (int i = 0; i < CHECKMULTISIGpubKeyCount; i++)
                        CHECKMULTISIGpubkeys.add(stack.pollLast());
                    
                    int CHECKMULTISIGsigCount = castToBigInteger(stack.pollLast()).intValue();
                    if (CHECKMULTISIGsigCount < 0 || CHECKMULTISIGsigCount > CHECKMULTISIGpubKeyCount)
                        throw new ScriptException("OP_CHECKMULTISIG(VERIFY) with sig count out of range");
                    if (stack.size() < CHECKMULTISIGsigCount + 1)
                        throw new ScriptException("Attempted OP_CHECKMULTISIG(VERIFY) on a stack with size < num_of_pubkeys + num_of_signatures + 3");
                    
                    LinkedList<byte[]> CHECKMULTISIGsigs = new LinkedList<byte[]>();
                    for (int i = 0; i < CHECKMULTISIGsigCount; i++)
                        CHECKMULTISIGsigs.add(stack.pollLast());
                    
                    byte[] CHECKMULTISIGconnectedScript = Arrays.copyOfRange(script.program, lastCodeSepLocation, script.program.length);
                    
                    for (byte[] CHECKMULTISIGsig : CHECKMULTISIGsigs) {
                        UnsafeByteArrayOutputStream OPCHECKMULTISIGOutStream = new UnsafeByteArrayOutputStream(CHECKMULTISIGsig.length + 1);
                        try {
                            writeBytes(OPCHECKMULTISIGOutStream, CHECKMULTISIGsig);
                        } catch (IOException e) {
                            throw new RuntimeException(e); // Cannot happen
                        }
                        CHECKMULTISIGconnectedScript = removeAllInstancesOf(CHECKMULTISIGconnectedScript, OPCHECKMULTISIGOutStream.toByteArray());
                    }
                    
                    boolean CHECKMULTISIGValid = true;
                    while (CHECKMULTISIGsigs.size() > 0) {
                        byte[] CHECKMULTISIGsig = CHECKMULTISIGsigs.getFirst();
                        byte[] CHECKMULTISIGpubKey = CHECKMULTISIGpubkeys.pollFirst();
                        
                        // We could reasonably move this out of the loop,
                        // but because signature verification is significantly more expensive than hashing, its not a big deal
                        Sha256Hash CHECKMULTISIGhash = txContainingThis.hashTransactionForSignature((int)index, CHECKMULTISIGconnectedScript,
                                CHECKMULTISIGsig[CHECKMULTISIGsig.length - 1]);
                        try {
                            if (ECKey.verify(CHECKMULTISIGhash.getBytes(), Arrays.copyOf(CHECKMULTISIGsig, CHECKMULTISIGsig.length - 1), CHECKMULTISIGpubKey))
                                CHECKMULTISIGsigs.pollFirst();
                        } catch (Exception e) {
                            // There is (at least) one exception that could be hit here (EOFException, if the sig is too short)
                            // Because I can't verify there aren't more, we use a very generic Exception catch
                        }
                        
                        if (CHECKMULTISIGsigs.size() > CHECKMULTISIGpubkeys.size()) {
                            CHECKMULTISIGValid = false;
                            break;
                        }
                    }
                    
                    // We uselessly remove a stack object to emulate a reference client bug
                    stack.pollLast();
                    
                    if (opcode == OP_CHECKMULTISIG)
                        stack.add(CHECKMULTISIGValid ? new byte[] {1} : new byte[] {0});
                    else if (opcode == OP_CHECKMULTISIGVERIFY)
                        if (!CHECKMULTISIGValid)
                            throw new ScriptException("Script failed OP_CHECKMULTISIGVERIFY");
                    break;
                case OP_NOP1:
                case OP_NOP2:
                case OP_NOP3:
                case OP_NOP4:
                case OP_NOP5:
                case OP_NOP6:
                case OP_NOP7:
                case OP_NOP8:
                case OP_NOP9:
                case OP_NOP10:
                    break;
                    
                default:
                    throw new ScriptException("Script used a reserved Op Code");
                }
            }
            
            if (stack.size() + altstack.size() > 1000 || stack.size() + altstack.size() < 0)
                throw new ScriptException("Stack size exceeded range");
        }
        
        if (!ifStack.isEmpty())
            throw new ScriptException("OP_IF/OP_NOTIF without OP_ENDIF");
    }

    /**
     * Verifies that this script (interpreted as a scriptSig) correctly spends the given scriptPubKey.
     * @param txContainingThis The transaction in which this input scriptSig resides.
     * @param scriptSigIndex The index in txContainingThis of the scriptSig (note: NOT the index of the scriptPubKey).
     * @param scriptPubKey The connected scriptPubKey containing the conditions needed to claim the value.
     * @param enforceP2SH Whether "pay to script hash" rules should be enforced. If in doubt, set to true.
     * @throws VerificationException if this script does not correctly spend the scriptPubKey
     */
    public void correctlySpends(Transaction txContainingThis, long scriptSigIndex, Script scriptPubKey,
                                boolean enforceP2SH) throws ScriptException {
        if (program.length > 10000 || scriptPubKey.program.length > 10000)
            throw new ScriptException("Script larger than 10,000 bytes");
        
        LinkedList<byte[]> stack = new LinkedList<byte[]>();
        LinkedList<byte[]> p2shStack = null;
        
        executeScript(txContainingThis, scriptSigIndex, this, stack);
        if (enforceP2SH)
            p2shStack = new LinkedList<byte[]>(stack);
        executeScript(txContainingThis, scriptSigIndex, scriptPubKey, stack);
        
        if (stack.size() == 0)
            throw new ScriptException("Stack empty at end of script execution.");
        
        if (!castToBool(stack.pollLast()))
            throw new ScriptException("Script resulted in a non-true stack");

        // P2SH is pay to script hash. It means that the scriptPubKey has a special form which is a valid
        // program but it has "useless" form that if evaluated as a normal program always returns true.
        // Instead, miners recognize it as special based on its template - it provides a hash of the real scriptPubKey
        // and that must be provided by the input. The goal of this bizarre arrangement is twofold:
        //
        // (1) You can sum up a large, complex script (like a CHECKMULTISIG script) with an address that's the same
        //     size as a regular address. This means it doesn't overload scannable QR codes/NFC tags or become
        //     un-wieldy to copy/paste.
        // (2) It allows the working set to be smaller: nodes perform best when they can store as many unspent outputs
        //     in RAM as possible, so if the outputs are made smaller and the inputs get bigger, then it's better for
        //     overall scalability and performance.

        // TODO: Check if we can take out enforceP2SH if there's a checkpoint at the enforcement block.
        if (enforceP2SH && scriptPubKey.isPayToScriptHash()) {
            for (ScriptChunk chunk : chunks)
                if (chunk.isOpCode && (chunk.data[0] & 0xff) > OP_16)
                    throw new ScriptException("Attempted to spend a P2SH scriptPubKey with a script that contained script ops");
            
            byte[] scriptPubKeyBytes = p2shStack.pollLast();
            Script scriptPubKeyP2SH = new Script(params, scriptPubKeyBytes, 0, scriptPubKeyBytes.length);
            
            executeScript(txContainingThis, scriptSigIndex, scriptPubKeyP2SH, p2shStack);
            
            if (p2shStack.size() == 0)
                throw new ScriptException("P2SH stack empty at end of script execution.");
            
            if (!castToBool(p2shStack.pollLast()))
                throw new ScriptException("P2SH script execution resulted in a non-true stack");
        }
    }
}
