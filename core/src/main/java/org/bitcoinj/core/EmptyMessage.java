/*
 * Copyright 2011 Steve Coughlan.
 * Copyright 2015 Andreas Schildbach
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

import java.io.IOException;
import java.io.OutputStream;

/**
 * <p>Parent class for header only messages that don't have a payload.
 * Currently this includes getaddr, verack and special bitcoinj class UnknownMessage.</p>
 * 
 * <p>Instances of this class are not safe for use by multiple threads.</p>
 */
public abstract class EmptyMessage extends BaseMessage {

    public EmptyMessage() {
        super();
    }

    @Override
    public final int getMessageSize() {
        return 0;
    }

    @Override
    protected final void bitcoinSerializeToStream(OutputStream stream) throws IOException {
    }
}
