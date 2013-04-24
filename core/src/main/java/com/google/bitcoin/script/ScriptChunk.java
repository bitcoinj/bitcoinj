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

package com.google.bitcoin.script;

import com.google.bitcoin.core.Utils;

import java.io.IOException;
import java.io.OutputStream;

import static com.google.bitcoin.script.ScriptOpCodes.OP_PUSHDATA1;
import static com.google.bitcoin.script.ScriptOpCodes.OP_PUSHDATA2;
import static com.google.bitcoin.script.ScriptOpCodes.OP_PUSHDATA4;
import static com.google.common.base.Preconditions.checkState;

/**
 * An element that is either an opcode or a raw byte array (signature, pubkey, etc).
 */
public class ScriptChunk {
    private boolean isOpCode;
    public byte[] data;
    private int startLocationInProgram;

    public ScriptChunk(boolean isOpCode, byte[] data) {
        this(isOpCode, data, -1);
    }

    public ScriptChunk(boolean isOpCode, byte[] data, int startLocationInProgram) {
        this.isOpCode = isOpCode;
        this.data = data;
        this.startLocationInProgram = startLocationInProgram;
    }

    public boolean equalsOpCode(int opCode) {
        return isOpCode && data.length == 1 && (0xFF & data[0]) == opCode;
    }

    public boolean isOpCode() {
        return isOpCode;
    }

    public int getStartLocationInProgram() {
        checkState(startLocationInProgram >= 0);
        return startLocationInProgram;
    }

    public void write(OutputStream stream) throws IOException {
        if (isOpCode) {
            checkState(data.length == 1);
            stream.write(data);
        } else {
            checkState(data.length <= Script.MAX_SCRIPT_ELEMENT_SIZE);
            if (data.length < OP_PUSHDATA1) {
                stream.write(data.length);
            } else if (data.length <= 0xFF) {
                stream.write(OP_PUSHDATA1);
                stream.write(data.length);
            } else if (data.length <= 0xFFFF) {
                stream.write(OP_PUSHDATA2);
                stream.write(0xFF & data.length);
                stream.write(0xFF & (data.length >> 8));
            } else {
                stream.write(OP_PUSHDATA4);
                Utils.uint32ToByteStreamLE(data.length, stream);
            }
            stream.write(data);
        }
    }
}
