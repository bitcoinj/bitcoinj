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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.List;

import static com.google.bitcoin.core.Utils.bytesToHexString;

/**
 * A chunk in a script
 */
class ScriptChunk {
    public boolean isOpCode;
    public byte[] data;
    public ScriptChunk(boolean isOpCode, byte[] data) {
        this.isOpCode = isOpCode;
        this.data = data;
    }
    public boolean equalsOpCode(int opCode) {
        return isOpCode &&
                data.length == 1 &&
                (0xFF & data[0]) == opCode;
    }
}

/**
 * Instructions for redeeming a payment.
 *
 * <p>Bitcoin transactions don't specify what they do directly. Instead <a href="https://en.bitcoin.it/wiki/Script">a
 * small binary stack language</a> is used to define programs that when evaluated return whether the transaction
 * "accepts" or rejects the other transactions connected to it.</p>
 *
 * <p>bitcoinj does not evaluate/run scripts. The reason is that doing so requires the connected transactions, ie, all
 * transactions, and as a lightweight/SPV client we don't store them all. Instead tx validity is decided by miners
 * and we rely purely on the majority consensus to determine if the scripts are valid. This class therefore just lets
 * you manipulate and parse them.</p>
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
            int opcode = readByte();
            if (opcode >= 0 && opcode < OP_PUSHDATA1) {
                // Read some bytes of data, where how many is the opcode value itself.
                chunks.add(new ScriptChunk(false, getData(opcode)));  // opcode == len here.
            } else if (opcode == OP_PUSHDATA1) {
                int len = readByte();
                chunks.add(new ScriptChunk(false, getData(len)));
            } else if (opcode == OP_PUSHDATA2) {
                // Read a short, then read that many bytes of data.
                int len = readByte() | (readByte() << 8);
                chunks.add(new ScriptChunk(false, getData(len)));
            } else if (opcode == OP_PUSHDATA4) {
                // Read a uint32, then read that many bytes of data.
                // Though this is allowed, because its value cannot be > 520, it should never actually be used
                long len = readByte() | (readByte() << 8) | (readByte() << 16) | (readByte() << 24);
                chunks.add(new ScriptChunk(false, getData((int)len)));
            } else {
                chunks.add(new ScriptChunk(true, new byte[]{(byte) opcode}));
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
}
