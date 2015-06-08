package org.bitcoinj.utils;

import com.google.common.collect.Maps;
import com.google.protobuf.ByteString;

import javax.annotation.Nullable;
import java.util.HashMap;
import java.util.Map;

import static com.google.common.base.Preconditions.checkNotNull;

/**
 * A simple implementation of {@link TaggableObject} that just uses a lazily created hashmap that is
 * synchronized on this objects Java monitor.
 */
public class BaseTaggableObject implements TaggableObject {
    @Nullable protected Map<String, ByteString> tags;

    /** {@inheritDoc} */
    @Override
    @Nullable
    public synchronized ByteString maybeGetTag(String tag) {
        if (tags == null)
            return null;
        else
            return tags.get(tag);
    }

    /** {@inheritDoc} */
    @Override
    public ByteString getTag(String tag) {
        ByteString b = maybeGetTag(tag);
        if (b == null)
            throw new IllegalArgumentException("Unknown tag " + tag);
        return b;
    }

    /** {@inheritDoc} */
    @Override
    public synchronized void setTag(String tag, ByteString value) {
        checkNotNull(tag);
        checkNotNull(value);
        if (tags == null)
            tags = new HashMap<String, ByteString>();
        tags.put(tag, value);
    }

    /** {@inheritDoc} */
    @Override
    public synchronized Map<String, ByteString> getTags() {
        if (tags != null)
            return Maps.newHashMap(tags);
        else
            return Maps.newHashMap();
    }
}
