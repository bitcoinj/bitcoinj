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

public class InventoryMessage extends ListMessage {
    private static final long serialVersionUID = -7050246551646107066L;

    public InventoryMessage(NetworkParameters params, byte[] bytes) throws ProtocolException {
        super(params, bytes);
    }

    public InventoryMessage(NetworkParameters params, byte[] msg, boolean parseLazy, boolean parseRetain, int length)
            throws ProtocolException {
        super(params, msg, parseLazy, parseRetain, length);
    }

    public InventoryMessage(NetworkParameters params) {
        super(params);
    }

}
