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

package org.bitcoinj.core;

import java.util.ArrayList;
import java.util.List;

/**
 * <p>Sent by a peer when a getdata request doesn't find the requested data in the mempool. It has the same format
 * as an inventory message and lists the hashes of the missing items.</p>
 * 
 * <p>Instances of this class are not safe for use by multiple threads.</p>
 */
public class NotFoundMessage extends InventoryMessage {
    public static int MIN_PROTOCOL_VERSION = 70001;

    public NotFoundMessage(NetworkParameters params) {
        super(params);
    }

    public NotFoundMessage(NetworkParameters params, byte[] payloadBytes) throws ProtocolException {
        super(params, payloadBytes);
    }

    public NotFoundMessage(NetworkParameters params, List<InventoryItem> items) {
        super(params);
        this.items = new ArrayList<InventoryItem>(items);
    }
}
