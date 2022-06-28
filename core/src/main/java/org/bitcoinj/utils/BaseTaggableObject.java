/*
 * Copyright by the original author or authors.
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

package org.bitcoinj.utils;

import com.google.protobuf.ByteString;

import javax.annotation.Nullable;
import java.util.HashMap;
import java.util.Map;

import static com.google.common.base.Preconditions.checkNotNull;

/**
 * A simple implementation of {@link TaggableObject} that uses a hashmap that is
 * synchronized on this object's Java monitor.
 * @deprecated Applications should use another mechanism to persist application state data
 */
@Deprecated
public class BaseTaggableObject implements TaggableObject {
    protected final Map<String, ByteString> tags = new HashMap<>();

    @Override
    @Nullable
    @Deprecated
    public synchronized ByteString maybeGetTag(String tag) {
        return tags.get(tag);
    }

    @Override
    @Deprecated
    public ByteString getTag(String tag) {
        ByteString b = maybeGetTag(tag);
        if (b == null)
            throw new IllegalArgumentException("Unknown tag " + tag);
        return b;
    }

    @Override
    @Deprecated
    public synchronized void setTag(String tag, ByteString value) {
        // HashMap allows null keys and values, but we don't
        checkNotNull(tag);
        checkNotNull(value);
        tags.put(tag, value);
    }

    @Override
    @Deprecated
    public synchronized Map<String, ByteString> getTags() {
        return new HashMap<>(tags);
    }
}
