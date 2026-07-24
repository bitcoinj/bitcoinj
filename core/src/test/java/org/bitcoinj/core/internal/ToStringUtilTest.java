/*
 * Copyright by the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.bitcoinj.core.internal;

import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class ToStringUtilTest {

    static class TestObject {}

    @Test
    public void testBasic() {
        ToStringUtil util = new ToStringUtil(new TestObject());
        util.add("key", "value");
        util.add("number", 123);
        assertEquals("TestObject{key=value, number=123}", util.toString());
    }

    @Test
    public void testOmitNullValues() {
        ToStringUtil util = new ToStringUtil(new TestObject());
        util.add("present", "here");
        util.add("absent", null); // Should be ignored
        assertEquals("TestObject{present=here}", util.toString());
    }

    @Test
    public void testAddIf() {
        ToStringUtil util = new ToStringUtil(new TestObject());
        util.addIf(true, "included", "yes");
        util.addIf(false, "excluded", "no");
        assertEquals("TestObject{included=yes}", util.toString());
    }

    @Test
    public void testAddValue() {
        ToStringUtil util = new ToStringUtil(new TestObject());
        util.addValue("plainValue");
        assertEquals("TestObject{plainValue}", util.toString());
    }
}