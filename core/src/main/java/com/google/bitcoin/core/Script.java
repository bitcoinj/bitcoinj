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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.List;

import static com.google.bitcoin.core.Utils.bytesToHexString;

/**
 * Bitcoin transactions don't specify what they do directly. Instead <a href="https://en.bitcoin.it/wiki/Script">a
 * small binary stack language</a> is used to define programs that when evaluated return whether the transaction
 * "accepts" or rejects the other transactions connected to it.<p>
 *
 * BitcoinJ does not evaluate/run scripts. The reason is that doing so requires the connected transactions, ie, all
 * transactions, and as a lightweight/SPV client we don't store them all. Instead tx validity is decided by miners
 * and we rely purely on the majority consensus to determine if the scripts are valid. This class therefore just lets
 * you manipulate and parse them.
 */
public class Script {
    private static Logger log = LoggerFactory.getLogger(Script.class);

    // Some constants used for decoding the scripts.
    public static final int OP_PUSHDATA1 = 76;
    public static final int OP_PUSHDATA2 = 77;
    public static final int OP_PUSHDATA4 = 78;
    public static final int OP_DUP = 118;
    public static final int OP_HASH160 = 169;
    public static final int OP_EQUALVERIFY = 136;
    public static final int OP_CHECKSIG = 172;

    byte[] program;
    private int cursor;

    // The program is a set of byte[]s where each element is either [opcode] or [data, data, data ...]
    // TODO: Differentiate between 1 byte data chunks and opcodes here.
    List<byte[]> chunks;
    byte[] programCopy;      // TODO: remove this
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
        for (byte[] chunk : chunks) {
            if (chunk.length == 1) {
                String opName;
                int opcode = 0xFF & chunk[0];
                switch (opcode) {
                    case OP_DUP:
                        opName = "DUP";
                        break;
                    case OP_HASH160:
                        opName = "HASH160";
                        break;
                    case OP_CHECKSIG:
                        opName = "CHECKSIG";
                        break;
                    case OP_EQUALVERIFY:
                        opName = "EQUALVERIFY";
                        break;
                    default:
                        opName = "?(" + opcode + ")";
                        break;
                }
                buf.append(opName);
                buf.append(" ");
            } else {
                // Data chunk
                buf.append("[");
                buf.append(chunk.length);
                buf.append("]");
                buf.append(bytesToHexString(chunk));
                buf.append(" ");
            }
        }
        return buf.toString();
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
        programCopy = new byte[length];
        System.arraycopy(programBytes, offset, programCopy, 0, length);

        program = programCopy;
        offset = 0;
        chunks = new ArrayList<byte[]>(10);  // Arbitrary choice of initial size.
        cursor = offset;
        while (cursor < offset + length) {
            int opcode = readByte();
            if (opcode >= 0xF0) {
                // Not a single byte opcode.
                opcode = (opcode << 8) | readByte();
            }

            if (opcode > 0 && opcode < OP_PUSHDATA1) {
                // Read some bytes of data, where how many is the opcode value itself.
                chunks.add(getData(opcode));  // opcode == len here.
            } else if (opcode == OP_PUSHDATA1) {
                int len = readByte();
                chunks.add(getData(len));
            } else if (opcode == OP_PUSHDATA2) {
                // Read a short, then read that many bytes of data.
                int len = readByte() | (readByte() << 8);
                chunks.add(getData(len));
            } else if (opcode == OP_PUSHDATA4) {
                // Read a uint32, then read that many bytes of data.
                log.error("PUSHDATA4: Unimplemented");
            } else {
                chunks.add(new byte[]{(byte) opcode});
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
        return (0xFF & chunks.get(1)[0]) == OP_CHECKSIG && chunks.get(0).length > 1;
    }

    /**
     * Returns true if this script is of the form DUP HASH160 <pubkey hash> EQUALVERIFY CHECKSIG, ie, payment to an
     * address like 1VayNert3x1KzbpzMGt2qdqrAThiRovi8. This form was originally intended for the case where you wish
     * to send somebody money with a written code because their node is offline, but over time has become the standard
     * way to make payments due to the short and recognizable base58 form addresses come in.
     */
    public boolean isSentToAddress() {
        if (chunks.size() != 5) return false;
        return (0xFF & chunks.get(0)[0]) == OP_DUP &&
               (0xFF & chunks.get(1)[0]) == OP_HASH160 &&
               chunks.get(2).length == Address.LENGTH &&
               (0xFF & chunks.get(3)[0]) == OP_EQUALVERIFY &&
               (0xFF & chunks.get(4)[0]) == OP_CHECKSIG;
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
        return chunks.get(2);
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
        if (chunks.get(0).length > 2 && chunks.get(1).length > 2) {
            // If we have two large constants assume the input to a pay-to-address output.
            return chunks.get(1);
        } else if (chunks.get(1).length == 1 && (0xFF & chunks.get(1)[0]) == OP_CHECKSIG && chunks.get(0).length > 2) {
            // A large constant followed by an OP_CHECKSIG is the key.
            return chunks.get(0);
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
