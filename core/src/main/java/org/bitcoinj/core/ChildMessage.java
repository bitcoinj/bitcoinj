/*
 * Copyright 2011 Steve Coughlan.
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

import javax.annotation.Nullable;
import java.nio.ByteBuffer;

/**
 * <p>Represents a Message type that can be contained within another Message.  ChildMessages that have a cached
 * backing byte array need to invalidate their parent's caches as well as their own if they are modified.</p>
 * 
 * <p>Instances of this class are not safe for use by multiple threads.</p>
 */
public abstract class ChildMessage extends Message {

    @Nullable protected Message parent;

    public ChildMessage(NetworkParameters params) {
        super(params);
    }

    public ChildMessage(NetworkParameters params, MessageSerializer serializer) {
        super(params, serializer);
    }

    public ChildMessage(NetworkParameters params, ByteBuffer payload) throws ProtocolException {
        super(params, payload);
    }

    public ChildMessage(NetworkParameters params, ByteBuffer payload, @Nullable Message parent,
                        MessageSerializer serializer) throws ProtocolException {
        super(params, payload, serializer);
        this.parent = parent;
    }

    public final void setParent(@Nullable Message parent) {
        if (this.parent != null && this.parent != parent && parent != null) {
            // After old parent is unlinked it won't be able to receive notice if this ChildMessage
            // changes internally.  To be safe we invalidate the parent cache to ensure it rebuilds
            // manually on serialization.
            this.parent.unCache();
        }
        this.parent = parent;
    }

    /* (non-Javadoc)
      * @see Message#unCache()
      */
    @Override
    protected void unCache() {
        super.unCache();
        if (parent != null)
            parent.unCache();
    }
}
