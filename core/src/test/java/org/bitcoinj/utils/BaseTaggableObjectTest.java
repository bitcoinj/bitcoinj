package org.bitcoinj.utils;

import com.google.protobuf.ByteString;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

public class BaseTaggableObjectTest {
    private BaseTaggableObject obj;

    @Before
    public void setUp() throws Exception {
        obj = new BaseTaggableObject();
    }

    @Test
    public void tags() throws Exception {
        assertNull(obj.maybeGetTag("foo"));
        obj.setTag("foo", ByteString.copyFromUtf8("bar"));
        assertEquals("bar", obj.getTag("foo").toStringUtf8());
    }

    @Test(expected = IllegalArgumentException.class)
    public void exception() throws Exception {
        obj.getTag("non existent");
    }
}