/*
 * Copyright 2012 Google Inc.
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

// TODO: Rename PrunedException to something like RequiredDataWasPrunedException

/**
 * PrunedException is thrown in cases where a fully verifying node has deleted (pruned) old block data that turned
 * out to be necessary for handling a re-org. Normally this should never happen unless you're playing with the testnet
 * as the pruning parameters should be set very conservatively, such that an absolutely enormous re-org would be
 * required to trigger it.
 */
@SuppressWarnings("serial")
public class PrunedException extends Exception {
    private Sha256Hash hash;
    public PrunedException(Sha256Hash hash) {
        super(hash.toString());
        this.hash = hash;
    }
    public Sha256Hash getHash() {
        return hash;
    }
}
