/**
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

package com.google.bitcoin.jni;

import com.google.bitcoin.core.*;

import java.util.List;

/**
 * An event listener that relays events to a native C++ object. A pointer to that object is stored in
 * this class using JNI on the native side, thus several instances of this can point to different actual
 * native implementations.
 */
public class NativeBlockChainListener implements BlockChainListener {
    public long ptr;

    @Override
    public native void notifyNewBestBlock(StoredBlock block) throws VerificationException;

    @Override
    public native void reorganize(StoredBlock splitPoint, List<StoredBlock> oldBlocks, List<StoredBlock> newBlocks) throws VerificationException;

    @Override
    public native boolean isTransactionRelevant(Transaction tx) throws ScriptException;

    @Override
    public native void receiveFromBlock(Transaction tx, StoredBlock block, BlockChain.NewBlockType blockType,
                                        int relativityOffset) throws VerificationException;

    @Override
    public native boolean notifyTransactionIsInBlock(Sha256Hash txHash, StoredBlock block, BlockChain.NewBlockType blockType,
                                                     int relativityOffset) throws VerificationException;
}
