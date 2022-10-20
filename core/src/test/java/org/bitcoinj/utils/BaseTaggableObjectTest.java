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
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

public class BaseTaggableObjectTest {
    private BaseTaggableObject obj;

    @Before
    public void setUp() {
        obj = new BaseTaggableObject();
    }

    @Test
    public void tags() {
        assertNull(obj.maybeGetTag("foo"));
        obj.setTag("foo", ByteString.copyFromUtf8("bar"));
        assertEquals("bar", obj.getTag("foo").toStringUtf8());
    }

    @Test(expected = IllegalArgumentException.class)
    public void exception() {
        obj.getTag("non existent");
    }
}