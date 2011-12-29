/*
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

import java.util.List;

/**
 * The "getheaders" command is structurally identical to "getblocks", but has different meaning. On receiving this
 * message a Bitcoin node returns matching blocks up to the limit, but without the bodies. It is useful as an
 * optimization: when your wallet does not contain any keys created before a particular time, you don't have to download
 * the bodies for those blocks because you know there are no relevant transactions.
 */
public class GetHeadersMessage extends GetBlocksMessage {
    public GetHeadersMessage(NetworkParameters params, List<Sha256Hash> locator, Sha256Hash stopHash) {
        super(params, locator, stopHash);
    }
}
