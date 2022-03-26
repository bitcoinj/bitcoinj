/*
 * Copyright 2013 Google Inc.
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

package org.bitcoinj.script;

import com.google.common.collect.BiMap;
import com.google.common.collect.ImmutableBiMap;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * Various constants that define the assembly-like scripting language that forms part of the Bitcoin protocol.
 * See {@link Script} for details. Also provides a method to convert them to a string.
 */
public class ScriptOpCodes {
    // push value
    public static final int OP_0 = 0x00; // push empty vector
    public static final int OP_FALSE = OP_0;
    public static final int OP_PUSHDATA1 = 0x4c;
    public static final int OP_PUSHDATA2 = 0x4d;
    public static final int OP_PUSHDATA4 = 0x4e;
    public static final int OP_1NEGATE = 0x4f;
    public static final int OP_RESERVED = 0x50;
    public static final int OP_1 = 0x51;
    public static final int OP_TRUE = OP_1;
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

    // block state
    /** Check lock time of the block. Introduced in BIP 65, replacing OP_NOP2 */
    public static final int OP_CHECKLOCKTIMEVERIFY = 0xb1;
    public static final int OP_CHECKSEQUENCEVERIFY = 0xb2;

    // expansion
    public static final int OP_NOP1 = 0xb0;
    /** Deprecated by BIP 65 */
    @Deprecated
    public static final int OP_NOP2 = OP_CHECKLOCKTIMEVERIFY;
    /** Deprecated by BIP 112 */
    @Deprecated
    public static final int OP_NOP3 = OP_CHECKSEQUENCEVERIFY;
    public static final int OP_NOP4 = 0xb3;
    public static final int OP_NOP5 = 0xb4;
    public static final int OP_NOP6 = 0xb5;
    public static final int OP_NOP7 = 0xb6;
    public static final int OP_NOP8 = 0xb7;
    public static final int OP_NOP9 = 0xb8;
    public static final int OP_NOP10 = 0xb9;
    public static final int OP_INVALIDOPCODE = 0xff;

    private static final BiMap<Integer, String> opCodeMap = ImmutableBiMap.<Integer, String>builder()
        .put(OP_0, "0")
        .put(OP_PUSHDATA1, "PUSHDATA1")
        .put(OP_PUSHDATA2, "PUSHDATA2")
        .put(OP_PUSHDATA4, "PUSHDATA4")
        .put(OP_1NEGATE, "1NEGATE")
        .put(OP_RESERVED, "RESERVED")
        .put(OP_1, "1")
        .put(OP_2, "2")
        .put(OP_3, "3")
        .put(OP_4, "4")
        .put(OP_5, "5")
        .put(OP_6, "6")
        .put(OP_7, "7")
        .put(OP_8, "8")
        .put(OP_9, "9")
        .put(OP_10, "10")
        .put(OP_11, "11")
        .put(OP_12, "12")
        .put(OP_13, "13")
        .put(OP_14, "14")
        .put(OP_15, "15")
        .put(OP_16, "16")
        .put(OP_NOP, "NOP")
        .put(OP_VER, "VER")
        .put(OP_IF, "IF")
        .put(OP_NOTIF, "NOTIF")
        .put(OP_VERIF, "VERIF")
        .put(OP_VERNOTIF, "VERNOTIF")
        .put(OP_ELSE, "ELSE")
        .put(OP_ENDIF, "ENDIF")
        .put(OP_VERIFY, "VERIFY")
        .put(OP_RETURN, "RETURN")
        .put(OP_TOALTSTACK, "TOALTSTACK")
        .put(OP_FROMALTSTACK, "FROMALTSTACK")
        .put(OP_2DROP, "2DROP")
        .put(OP_2DUP, "2DUP")
        .put(OP_3DUP, "3DUP")
        .put(OP_2OVER, "2OVER")
        .put(OP_2ROT, "2ROT")
        .put(OP_2SWAP, "2SWAP")
        .put(OP_IFDUP, "IFDUP")
        .put(OP_DEPTH, "DEPTH")
        .put(OP_DROP, "DROP")
        .put(OP_DUP, "DUP")
        .put(OP_NIP, "NIP")
        .put(OP_OVER, "OVER")
        .put(OP_PICK, "PICK")
        .put(OP_ROLL, "ROLL")
        .put(OP_ROT, "ROT")
        .put(OP_SWAP, "SWAP")
        .put(OP_TUCK, "TUCK")
        .put(OP_CAT, "CAT")
        .put(OP_SUBSTR, "SUBSTR")
        .put(OP_LEFT, "LEFT")
        .put(OP_RIGHT, "RIGHT")
        .put(OP_SIZE, "SIZE")
        .put(OP_INVERT, "INVERT")
        .put(OP_AND, "AND")
        .put(OP_OR, "OR")
        .put(OP_XOR, "XOR")
        .put(OP_EQUAL, "EQUAL")
        .put(OP_EQUALVERIFY, "EQUALVERIFY")
        .put(OP_RESERVED1, "RESERVED1")
        .put(OP_RESERVED2, "RESERVED2")
        .put(OP_1ADD, "1ADD")
        .put(OP_1SUB, "1SUB")
        .put(OP_2MUL, "2MUL")
        .put(OP_2DIV, "2DIV")
        .put(OP_NEGATE, "NEGATE")
        .put(OP_ABS, "ABS")
        .put(OP_NOT, "NOT")
        .put(OP_0NOTEQUAL, "0NOTEQUAL")
        .put(OP_ADD, "ADD")
        .put(OP_SUB, "SUB")
        .put(OP_MUL, "MUL")
        .put(OP_DIV, "DIV")
        .put(OP_MOD, "MOD")
        .put(OP_LSHIFT, "LSHIFT")
        .put(OP_RSHIFT, "RSHIFT")
        .put(OP_BOOLAND, "BOOLAND")
        .put(OP_BOOLOR, "BOOLOR")
        .put(OP_NUMEQUAL, "NUMEQUAL")
        .put(OP_NUMEQUALVERIFY, "NUMEQUALVERIFY")
        .put(OP_NUMNOTEQUAL, "NUMNOTEQUAL")
        .put(OP_LESSTHAN, "LESSTHAN")
        .put(OP_GREATERTHAN, "GREATERTHAN")
        .put(OP_LESSTHANOREQUAL, "LESSTHANOREQUAL")
        .put(OP_GREATERTHANOREQUAL, "GREATERTHANOREQUAL")
        .put(OP_MIN, "MIN")
        .put(OP_MAX, "MAX")
        .put(OP_WITHIN, "WITHIN")
        .put(OP_RIPEMD160, "RIPEMD160")
        .put(OP_SHA1, "SHA1")
        .put(OP_SHA256, "SHA256")
        .put(OP_HASH160, "HASH160")
        .put(OP_HASH256, "HASH256")
        .put(OP_CODESEPARATOR, "CODESEPARATOR")
        .put(OP_CHECKSIG, "CHECKSIG")
        .put(OP_CHECKSIGVERIFY, "CHECKSIGVERIFY")
        .put(OP_CHECKMULTISIG, "CHECKMULTISIG")
        .put(OP_CHECKMULTISIGVERIFY, "CHECKMULTISIGVERIFY")
        .put(OP_NOP1, "NOP1")
        .put(OP_CHECKLOCKTIMEVERIFY, "CHECKLOCKTIMEVERIFY")
        .put(OP_CHECKSEQUENCEVERIFY, "CHECKSEQUENCEVERIFY")
        .put(OP_NOP4, "NOP4")
        .put(OP_NOP5, "NOP5")
        .put(OP_NOP6, "NOP6")
        .put(OP_NOP7, "NOP7")
        .put(OP_NOP8, "NOP8")
        .put(OP_NOP9, "NOP9")
        .put(OP_NOP10, "NOP10").build();

    private static final Map<String, Integer> opCodeNameMap = createOpCodeNameMap();

    private static Map<String, Integer> createOpCodeNameMap() {
        Map<String, Integer> map = new HashMap<>(opCodeMap.inverse());
        map.put("OP_FALSE", OP_FALSE);
        map.put("OP_TRUE", OP_TRUE);
        map.put("NOP2", OP_NOP2);
        map.put("NOP3", OP_NOP3);
        return Collections.unmodifiableMap(map);
    }

    /**
     * Converts the given OpCode into a string (eg "0", "PUSHDATA", or "NON_OP(10)")
     */
    public static String getOpCodeName(int opcode) {
        if (opCodeMap.containsKey(opcode))
            return opCodeMap.get(opcode);

        return "NON_OP(" + opcode + ")";
    }

    /**
     * Converts the given pushdata OpCode into a string (eg "PUSHDATA2", or "PUSHDATA(23)")
     */
    public static String getPushDataName(int opcode) {
        if (opCodeMap.containsKey(opcode))
            return opCodeMap.get(opcode);

        return "PUSHDATA(" + opcode + ")";
    }

    /**
     * Converts the given OpCodeName into an int
     */
    public static int getOpCode(String opCodeName) {
        if (opCodeNameMap.containsKey(opCodeName))
            return opCodeNameMap.get(opCodeName);

        return OP_INVALIDOPCODE;
    }
}
